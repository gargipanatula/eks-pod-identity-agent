package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"go.amzn.com/eks/eks-pod-identity-agent/internal/cloud/eksauth"
	imdscloud "go.amzn.com/eks/eks-pod-identity-agent/internal/cloud/imds"
	"go.amzn.com/eks/eks-pod-identity-agent/internal/credsretriever"
	"go.amzn.com/eks/eks-pod-identity-agent/internal/middleware/logger"
	"go.amzn.com/eks/eks-pod-identity-agent/internal/validation"
	"go.amzn.com/eks/eks-pod-identity-agent/pkg/credentials"

	"go.amzn.com/eks/eks-pod-identity-agent/pkg/errors"
)

type EksCredentialHandler struct {
	// ClusterName is the EKS cluster name where the agent runs
	ClusterName string
	// RequestValidator does basic validations for parameters that we are
	// going to send to EKS Auth. Note that these validations are very
	// rough and will never be as thorough as the ones done in the server
	RequestValidator validation.RequestValidator
	// CredentialRetriever will call EksAuthService to retrieve credentials
	CredentialRetriever credentials.CredentialRetriever
}

type EksCredentialHandlerOpts struct {
	Cfg                aws.Config
	ClusterName        string
	CredentialRenewal  time.Duration
	MaxCacheSize       int
	RefreshQPS         int
	EndpointOverridden bool
	EnableIMDS         bool
}

var (
	promHttpStatus = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "pod_identity_http_response",
		Help: "Pod Identity http response code",
	}, []string{"code"})
)

func NewEksCredentialHandler(opts EksCredentialHandlerOpts) *EksCredentialHandler {
	ctx := context.Background()
	ctx = logger.ContextWithField(ctx, "cluster-name", opts.ClusterName)
	log := logger.FromContext(ctx)

	authService := eksauth.NewService(opts.Cfg)

	var imdsSvc credentials.CredentialRetriever
	if opts.EnableIMDS && imdscloud.ProbeIMDS(ctx, opts.Cfg) {
		imdsSvc = imdscloud.NewService(ctx, opts.Cfg)
	}

	delegate := buildCredentialChain(imdsSvc, authService)

	tv, err := validation.NewTokenValidator(ctx)
	if err != nil {
		log.Infof("failed to initialize token validator: %v", err)
	}
	if tv != nil {
		tv.EndpointOverridden = opts.EndpointOverridden
	}

	if opts.CredentialRenewal != 0 && opts.MaxCacheSize != 0 {
		retrieverOpts := credsretriever.CachedCredentialRetrieverOpts{
			Delegate:              delegate,
			CredentialsRenewalTtl: opts.CredentialRenewal,
			MaxCacheSize:          opts.MaxCacheSize,
			RefreshQPS:            opts.RefreshQPS,
		}
		if tv != nil {
			retrieverOpts.TokenValidator = tv
		}
		delegate = credsretriever.NewCachedCredentialRetriever(retrieverOpts)
	}

	return &EksCredentialHandler{
		RequestValidator:    validation.DefaultCredentialValidator{},
		ClusterName:         opts.ClusterName,
		CredentialRetriever: delegate,
	}
}

// buildCredentialChain constructs a delegate chain in order from the provided retrievers,
// filtering out any nils. If only one retriever remains, it is returned directly.
func buildCredentialChain(retrievers ...credentials.CredentialRetriever) credentials.CredentialRetriever {
	var chain []credentials.CredentialRetriever
	for _, r := range retrievers {
		if r != nil {
			chain = append(chain, r)
		}
	}
	if len(chain) == 1 {
		return chain[0]
	}
	return credsretriever.NewChainedRetriever(chain...)
}

func (h *EksCredentialHandler) ConfigureHandler(register func(pattern string, handlerFunc http.HandlerFunc)) {
	register("/v1/credentials", h.HandleRequest)
}

func (h *EksCredentialHandler) HandleRequest(resp http.ResponseWriter, req *http.Request) {
	ctx := logger.ContextWithField(req.Context(), "cluster-name", h.ClusterName)
	log := logger.FromContext(ctx)

	log.Infof("handling new request request from %s", req.RemoteAddr)

	eksCredentialsRequest := &credentials.EksCredentialsRequest{
		ClusterName:         h.ClusterName,
		ServiceAccountToken: req.Header.Get("Authorization"),
		RequestTargetHost:   req.Host,
	}

	// Bind podUID into the logger context
	if podUID, uidErr := credentials.GetPodUIDFromToken(eksCredentialsRequest.ServiceAccountToken); uidErr != nil {
		log.Infof("could not extract podUID from token for log context: %v", uidErr)
	} else {
		ctx = logger.ContextWithField(ctx, "podUID", podUID)
		log = logger.FromContext(ctx)
	}

	creds, err := h.GetEksCredentials(ctx, eksCredentialsRequest)
	if err != nil {
		msg, code := errors.HandleCredentialFetchingError(ctx, err)
		promHttpStatus.WithLabelValues(strconv.Itoa(code)).Inc()
		http.Error(resp, msg, code)
		return
	}

	jsonOutput, err := json.Marshal(creds)
	if err != nil {
		promHttpStatus.WithLabelValues(strconv.Itoa(http.StatusInternalServerError)).Inc()
		http.Error(resp, "Unable to serialize credentials", http.StatusInternalServerError)
		return
	}

	// send the response
	resp.Header().Add("Content-Type", "application/json")
	promHttpStatus.WithLabelValues("200").Inc()
	_, err = resp.Write(jsonOutput)
	if err != nil {
		log.Errorf("failed to write response: %v", err)
	}
}

func (h *EksCredentialHandler) GetEksCredentials(ctx context.Context, request *credentials.EksCredentialsRequest) (*credentials.EksCredentialsResponse, error) {
	// validate request
	err := h.RequestValidator.ValidateEksCredentialRequest(ctx, request)
	if err != nil {
		return nil, err
	}
	// call EKS Auth
	iamCredentials, _, err := h.CredentialRetriever.GetIamCredentials(ctx, request)
	return iamCredentials, err
}
