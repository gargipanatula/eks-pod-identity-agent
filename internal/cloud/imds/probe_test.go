package imds

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/feature/ec2/imds"
	"github.com/stretchr/testify/assert"
	_ "go.amzn.com/eks/eks-pod-identity-agent/internal/test"
)

// --- ProbeIMDS tests ---

func TestProbeIMDS_HTTPStatus_ReturnsExpectedAvailability(t *testing.T) {
	tests := []struct {
		name       string
		status     int
		body       string
		wantResult bool
	}{
		{"returns true on 200", http.StatusOK, "i-1234567890abcdef0", true},
		{"returns true on 429", http.StatusTooManyRequests, "", true},
		{"returns false on 404", http.StatusNotFound, "", false},
		{"returns false on 403", http.StatusForbidden, "", false},
		{"returns false on 500", http.StatusInternalServerError, "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := probeIMDS(context.Background(), aws.Config{}, func(o *imds.Options) {
				o.HTTPClient = &mockHTTPClient{handler: func(req *http.Request) (*http.Response, error) {
					return httpResponse(tt.status, tt.body), nil
				}}
				o.ClientEnableState = imds.ClientEnabled
			})
			assert.Equal(t, tt.wantResult, result)
		})
	}
}

func TestProbeIMDS_TransportError_ReturnsFalse(t *testing.T) {
	result := probeIMDS(context.Background(), aws.Config{}, func(o *imds.Options) {
		o.HTTPClient = &mockHTTPClient{handler: func(req *http.Request) (*http.Response, error) {
			return nil, &net.OpError{Op: "dial", Err: fmt.Errorf("connection refused")}
		}}
		o.ClientEnableState = imds.ClientEnabled
	})
	assert.False(t, result)
}
