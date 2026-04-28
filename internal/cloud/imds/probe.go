package imds

import (
	"context"
	"errors"
	"net/http"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/feature/ec2/imds"
	smithyhttp "github.com/aws/smithy-go/transport/http"
	"go.amzn.com/eks/eks-pod-identity-agent/internal/middleware/logger"
)

// ProbeIMDS checks whether IMDS is available on this node using Option C
// (accept 200 or 429). A 200 means IMDS is healthy; a 429 means IMDS is
// present but throttling. Any other result (transport error, 404 from a
// metadata proxy, etc.) is treated as "IMDS not available."
func ProbeIMDS(ctx context.Context, cfg aws.Config) bool {
	available := probeIMDS(ctx, cfg)
	log := logger.FromContext(ctx)
	if available {
		log.Info("IMDS probe succeeded, IMDS is available on this node")
	} else {
		log.Info("IMDS probe failed, IMDS is not available on this node")
	}
	return available
}

func probeIMDS(ctx context.Context, cfg aws.Config, optFns ...func(*imds.Options)) bool {
	client := imds.NewFromConfig(cfg, optFns...)
	_, err := client.GetMetadata(ctx, &imds.GetMetadataInput{Path: "instance-id"})
	if err == nil {
		return true
	}
	var respErr *smithyhttp.ResponseError
	if errors.As(err, &respErr) && respErr.HTTPStatusCode() == http.StatusTooManyRequests {
		return true
	}
	return false
}
