package eksauth

import (
	"testing"

	. "github.com/onsi/gomega"
	"go.amzn.com/eks/eks-pod-identity-agent/pkg/credentials"
)

func TestResponseMetadata_AuthService_ReturnsCorrectSource(t *testing.T) {
	g := NewWithT(t)
	meta := responseMetadata("assoc-123")
	g.Expect(meta.Source()).To(Equal(credentials.SourceAuthService))
}

func TestResponseMetadata_AssociationId_Preserved(t *testing.T) {
	g := NewWithT(t)
	meta := responseMetadata("assoc-456")
	g.Expect(meta.AssociationId()).To(Equal("assoc-456"))
}
