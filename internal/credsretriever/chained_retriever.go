package credsretriever

import (
	"context"
	"fmt"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/sirupsen/logrus"
	"go.amzn.com/eks/eks-pod-identity-agent/internal/middleware/logger"
	"go.amzn.com/eks/eks-pod-identity-agent/pkg/credentials"
)

var promChainedResult = promauto.NewCounterVec(prometheus.CounterOpts{
	Name: "pod_identity_chained_retriever_result",
	Help: "Credential returned by chained retriever",
}, []string{"source", "state"})

// expirationSkew is the buffer subtracted from credential expiration to account for clock skew.
const expirationSkew = 5 * time.Minute

// chainedRetriever tries delegates in order and returns the first unexpired credential.
// If only expired credentials are available, the topmost (first) is returned.
// If no delegate returns a credential, the last error is returned.
type chainedRetriever struct {
	delegates []credentials.CredentialRetriever
}

var _ credentials.CredentialRetriever = &chainedRetriever{}

// NewChainedRetriever creates a retriever that tries delegates in order.
func NewChainedRetriever(delegates ...credentials.CredentialRetriever) credentials.CredentialRetriever {
	return &chainedRetriever{delegates: delegates}
}

func (c *chainedRetriever) String() string { return "chained-retriever" }

func (c *chainedRetriever) GetIamCredentials(ctx context.Context,
	request *credentials.EksCredentialsRequest) (*credentials.EksCredentialsResponse, credentials.ResponseMetadata, error) {
	log := logger.FromContext(ctx)

	var bestCred *credentials.EksCredentialsResponse
	var bestMeta credentials.ResponseMetadata
	var bestDelegate string
	var lastErr error

	for _, d := range c.delegates {
		if d == nil {
			continue
		}
		cred, meta, err := d.GetIamCredentials(ctx, request)

		// Delegate failed — log and try the next one.
		if err != nil {
			log.WithFields(logrus.Fields{"delegate": d.String(), "error": err}).Warn("Delegate error, trying next")
			lastErr = err
			continue
		}

		// Got an unexpired credential — return immediately.
		if cred.Expiration.Time.After(time.Now().Add(expirationSkew)) {
			log.WithFields(logrus.Fields{"delegate": d.String(), "expiry": cred.Expiration.Time.Format(time.RFC3339)}).Info("Returning credential")
			promChainedResult.WithLabelValues(d.String(), "unexpired").Inc()
			return cred, meta, nil
		}

		// Expired credential — hold onto the topmost one as fallback.
		if bestCred == nil {
			bestCred = cred
			bestMeta = meta
			bestDelegate = d.String()
		}
		lastErr = nil
	}

	if bestCred != nil {
		log.WithFields(logrus.Fields{"delegate": bestDelegate, "expiry": bestCred.Expiration.Time.Format(time.RFC3339), "expired": true}).Info("Returning fallback credential")
		promChainedResult.WithLabelValues(bestDelegate, "expired").Inc()
		return bestCred, bestMeta, nil
	}

	return nil, credentials.CredentialMetadata{}, fmt.Errorf("chained retriever: all delegates failed: %w", lastErr)
}
