// Package imds implements the IMDS credential delegate for EKS Pod Identity.
//
// Pod credentials are delivered to EC2 IMDS under numbered namespaces at
// /latest/meta-data/. Each namespace holds up to 200 pods, spread across
// iam-eks-1 .. iam-eks-N:
//
//	/latest/meta-data/
//	├── iam-eks-1/
//	│   ├── info                          # JSON with PodCredentials map (podUID → role/status)
//	│   └── security-credentials/
//	│       ├── <POD-UID-1>               # JSON credential file (AccessKeyId, SecretAccessKey, Token, Expiration)
//	│       └── <POD-UID-2>
//	├── iam-eks-2/
//	│   ├── info
//	│   └── security-credentials/
//	│       └── ...
//	├── iam                               # EC2 instance role (not EKS)
//	├── placement
//	└── ...
//
// The number of namespaces is dynamic and pods may be reshuffled across namespaces on each renewal. Namespaces are
// discovered by listing the metadata root and filtering for the iam-eks-* prefix.
package imds

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/feature/ec2/imds"
	"github.com/sirupsen/logrus"
	"go.amzn.com/eks/eks-pod-identity-agent/internal/middleware/logger"
	"go.amzn.com/eks/eks-pod-identity-agent/pkg/credentials"
	"golang.org/x/time/rate"
)

// rateLimitedHTTPClient wraps an http.Client with a rate limiter so that all
// IMDS requests are throttled transparently.
type rateLimitedHTTPClient struct {
	client  *http.Client
	limiter *rate.Limiter
}

func (r *rateLimitedHTTPClient) Do(req *http.Request) (*http.Response, error) {
	if err := r.limiter.Wait(req.Context()); err != nil {
		return nil, fmt.Errorf("IMDS rate limiter: %w", err)
	}
	return r.client.Do(req)
}

//go:generate mockgen.sh imds $GOFILE

type Iface interface {
	GetIamCredentials(ctx context.Context,
		request *credentials.EksCredentialsRequest) (*credentials.EksCredentialsResponse, credentials.ResponseMetadata, error)
	String() string
	IsIrrecoverable(err error) (string, bool)
}

const (
	imdsRateLimit          = 20
	defaultRefreshInterval = 60 * time.Second
	// iamEKSPrefix is the IMDS namespace prefix for EKS pod credentials.
	iamEKSPrefix = "iam-eks-"
)

type service struct {
	imdsClient *imds.Client
	// nsMapping stores map[string]string (podUID → namespace).
	nsMapping atomic.Value
}

func NewService(ctx context.Context, cfg aws.Config, optFns ...func(*imds.Options)) Iface {
	// The IMDS SDK enforces a default 5-second timeout per operation. We tighten
	// this to 1s total / 500ms socket connect to match eksauth's config. The client
	// is rate-limited to 20 TPS to protect other critical processes on the instance
	// that call IMDS.
	// https://pkg.go.dev/github.com/aws/aws-sdk-go-v2/feature/ec2/imds#Options
	httpClient := &rateLimitedHTTPClient{
		client: &http.Client{
			Transport: &http.Transport{
				DialContext: (&net.Dialer{
					Timeout: 500 * time.Millisecond,
				}).DialContext,
			},
			Timeout: 1000 * time.Millisecond,
		},
		limiter: rate.NewLimiter(imdsRateLimit, imdsRateLimit),
	}
	opts := append([]func(*imds.Options){func(o *imds.Options) {
		o.HTTPClient = httpClient
	}}, optFns...)
	s := &service{
		imdsClient: imds.NewFromConfig(cfg, opts...),
	}
	s.nsMapping.Store(map[string]string{})

	log := logger.FromContext(ctx)
	if err := s.buildNamespaceMapping(ctx); err != nil {
		log.Warnf("Initial IMDS namespace mapping build failed: %v", err)
	}
	s.startBackgroundRefresh(ctx, defaultRefreshInterval)

	return s
}

func (s *service) String() string { return "imds" }

func (s *service) IsIrrecoverable(err error) (string, bool) {
	// IsIrrecoverable is called by the cache to decide whether to evict a
	// credential entry after a failed refresh.
	//
	// ErrPodNotInMapping (irrecoverable): the pod was not found in the
	// agent's namespaceMapping. The mapping is refreshed every 60s in the
	// background, and credentials are delivered to IMDS within ~15 minutes
	// of pod creation. By the time a cache entry is eligible for refresh
	// (hours), the mapping has long since converged. If the pod is absent
	// at refresh time, it has genuinely been deleted or its association
	// removed — eviction is correct.
	//
	// ErrCredentialNotFound (recoverable): the pod IS in the mapping but
	// IMDS returned 404 for the credential itself. This can happen
	// transiently when credentials are reshuffled across IMDS namespaces.
	// The mapping still knows about the pod, so a subsequent refresh after
	// the reshuffle completes will succeed — eviction would be premature.
	//
	// All other errors (network timeouts, rate limits, etc.) are transient
	// and recoverable by definition.
	if errors.Is(err, ErrPodNotInMapping) {
		return "PodNotInMapping", true
	}
	return "Unknown", false
}

func (s *service) GetIamCredentials(ctx context.Context, request *credentials.EksCredentialsRequest) (*credentials.EksCredentialsResponse, credentials.ResponseMetadata, error) {
	log := logger.FromContext(ctx)

	podUID, err := credentials.GetPodUIDFromToken(request.ServiceAccountToken)
	if err != nil {
		return nil, nil, fmt.Errorf("IMDS delegate: %w", err)
	}

	ns, found := s.lookupNamespace(podUID)
	if !found {
		// The namespace mapping is refreshed in the background every 60s and
		// is not refreshed on demand here. A miss means the pod's credentials
		// were delivered to IMDS between background refresh cycles. On-demand
		// refresh could close this race, but would need a cooldown to prevent
		// bursty workloads from hitting the IMDS rate limit — and delivery
		// during that cooldown recreates the same gap. Background-only refresh
		// is simpler and bounds IMDS call volume predictably.
		//
		// This scenario is unlikely: it requires the agent to restart in the
		// narrow window between a pod first receiving credentials via the sync
		// path and those credentials being placed into IMDS. When wired behind
		// a chained retriever, the retriever will fallback to eksauth.
		return nil, nil, ErrPodNotInMapping
	}

	cred, err := s.readCredential(ctx, ns, podUID)
	if err != nil {
		return nil, nil, fmt.Errorf("IMDS delegate: %w", err)
	}

	log.WithFields(logrus.Fields{
		"source":    credentials.SourceIMDS,
		"namespace": ns,
	}).Info("Fetched credentials from IMDS")

	return cred, credentials.CredentialMetadata{CredSource: credentials.SourceIMDS}, nil
}

// startBackgroundRefresh starts a goroutine that refreshes the namespace
// mapping at the given interval. Failures log a warning but keep the old map.
func (s *service) startBackgroundRefresh(ctx context.Context, interval time.Duration) {
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				if err := s.buildNamespaceMapping(ctx); err != nil {
					log := logger.FromContext(ctx)
					log.Warnf("IMDS namespace mapping refresh failed, keeping old map: %v", err)
				}
			case <-ctx.Done():
				return
			}
		}
	}()
}

// buildNamespaceMapping reads all IMDS namespace info files and builds the
// podUID → namespace mapping.
func (s *service) buildNamespaceMapping(ctx context.Context) error {
	log := logger.FromContext(ctx)

	namespaces, err := s.discoverNamespaces(ctx)
	if err != nil {
		return fmt.Errorf("building namespace mapping: %w", err)
	}

	newMap := make(map[string]string)
	for _, ns := range namespaces {
		info, err := s.readNamespaceInfo(ctx, ns)
		if err != nil {
			log.WithField("namespace", ns).Warnf("Failed to read namespace info, skipping: %v", err)
			continue
		}
		for podUID, entry := range info.PodCredentials {
			if !strings.EqualFold(entry.Code, "Success") {
				log.WithFields(logrus.Fields{"namespace": ns, "podUID": podUID, "code": entry.Code}).
					Debug("Skipping pod with non-success code")
				continue
			}
			newMap[podUID] = ns
		}
	}

	s.nsMapping.Store(newMap)
	log.Infof("IMDS namespace mapping refreshed: %d pods across %d namespaces", len(newMap), len(namespaces))
	return nil
}

// lookupNamespace returns the IMDS namespace for a pod UID, or false if not mapped.
func (s *service) lookupNamespace(podUID string) (string, bool) {
	m := s.nsMapping.Load().(map[string]string)
	ns, ok := m[podUID]
	return ns, ok
}

// getMetadata fetches a metadata path from IMDS.
func (s *service) getMetadata(ctx context.Context, path string) ([]byte, error) {
	out, err := s.imdsClient.GetMetadata(ctx, &imds.GetMetadataInput{Path: path})
	if err != nil {
		return nil, err
	}
	defer out.Content.Close()
	return io.ReadAll(out.Content)
}

// readNamespaceInfo reads and parses the JSON info file for a given namespace.
func (s *service) readNamespaceInfo(ctx context.Context, namespace string) (*credentials.NamespaceInfo, error) {
	path := iamEKSPrefix + namespace + "/info"
	data, err := s.getMetadata(ctx, path)
	if err != nil {
		return nil, fmt.Errorf("reading namespace info %s: %w", namespace, err)
	}
	var info credentials.NamespaceInfo
	if err := json.Unmarshal(data, &info); err != nil {
		return nil, fmt.Errorf("parsing namespace info %s: %w", namespace, err)
	}
	return &info, nil
}

// readCredential reads and parses a pod's credential file from IMDS.
func (s *service) readCredential(ctx context.Context, namespace, podUID string) (*credentials.EksCredentialsResponse, error) {
	path := iamEKSPrefix + namespace + "/security-credentials/" + podUID
	data, err := s.getMetadata(ctx, path)
	if err != nil {
		if isNotFound(err) {
			return nil, ErrCredentialNotFound
		}
		return nil, fmt.Errorf("reading credential %s/%s: %w", namespace, podUID, err)
	}
	var cred credentials.EksCredentialsResponse
	if err := json.Unmarshal(data, &cred); err != nil {
		return nil, fmt.Errorf("parsing credential %s/%s: %w", namespace, podUID, err)
	}
	return &cred, nil
}

// discoverNamespaces lists the IMDS metadata root and returns the suffix of
// each iam-eks-* namespace (e.g. ["1", "2", "10"]). A single IMDS call
// replaces sequential probing, correctly handling non-sequential namespaces
// and dynamic namespace counts.
func (s *service) discoverNamespaces(ctx context.Context) ([]string, error) {
	data, err := s.getMetadata(ctx, "")
	if err != nil {
		return nil, fmt.Errorf("listing IMDS metadata root: %w", err)
	}
	var namespaces []string
	for _, entry := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		entry = strings.TrimRight(entry, "/")
		if strings.HasPrefix(entry, iamEKSPrefix) {
			namespaces = append(namespaces, strings.TrimPrefix(entry, iamEKSPrefix))
		}
	}
	return namespaces, nil
}
