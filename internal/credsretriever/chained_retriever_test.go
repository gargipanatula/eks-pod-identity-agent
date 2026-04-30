package credsretriever

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/eksauth/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.amzn.com/eks/eks-pod-identity-agent/internal/cloud/imds"
	"go.amzn.com/eks/eks-pod-identity-agent/internal/middleware/logger"
	"go.amzn.com/eks/eks-pod-identity-agent/pkg/credentials"
)

var (
	fixedNow    = time.Now()
	futureTime  = fixedNow.Add(6 * time.Hour)
	pastTime    = fixedNow.Add(-1 * time.Hour)
	testRequest = &credentials.EksCredentialsRequest{ServiceAccountToken: "tok", ClusterName: "cluster"}
)

func testContext() context.Context {
	return logger.ContextWithField(context.Background(), "test", "true")
}

func unexpiredCred(source credentials.CredentialSource) (*credentials.EksCredentialsResponse, credentials.ResponseMetadata) {
	return &credentials.EksCredentialsResponse{
		AccessKeyId:    "AKIA-" + string(source),
		SecretAccessKey: "secret",
		Token:          "token",
		AccountId:      "123456789012",
		Expiration:     credentials.SdkCompliantExpirationTime{Time: futureTime},
	}, credentials.CredentialMetadata{CredSource: source}
}

func expiredCred(source credentials.CredentialSource) (*credentials.EksCredentialsResponse, credentials.ResponseMetadata) {
	return &credentials.EksCredentialsResponse{
		AccessKeyId:    "AKIA-expired-" + string(source),
		SecretAccessKey: "secret",
		Token:          "token",
		AccountId:      "123456789012",
		Expiration:     credentials.SdkCompliantExpirationTime{Time: pastTime},
	}, credentials.CredentialMetadata{CredSource: source}
}

// stubRetriever is a simple test double for CredentialRetriever.
type stubRetriever struct {
	cred          *credentials.EksCredentialsResponse
	meta          credentials.ResponseMetadata
	err           error
	called        bool
	name          string
	irrecoverable bool
}

func (s *stubRetriever) String() string { return s.name }

func (s *stubRetriever) GetIamCredentials(_ context.Context, _ *credentials.EksCredentialsRequest) (*credentials.EksCredentialsResponse, credentials.ResponseMetadata, error) {
	s.called = true
	return s.cred, s.meta, s.err
}

func (s *stubRetriever) IsIrrecoverable(_ error) (string, bool) { return "", s.irrecoverable }

func TestChained_SelectionMatrix(t *testing.T) {
	imdsCred, imdsMeta := unexpiredCred(credentials.SourceIMDS)
	imdsExpCred, imdsExpMeta := expiredCred(credentials.SourceIMDS)
	authCred, authMeta := unexpiredCred(credentials.SourceAuthService)
	irrecoverableErr := fmt.Errorf("wrapped: %w", &types.ResourceNotFoundException{})
	recoverableErr := fmt.Errorf("wrapped: %w", &types.InternalServerException{})

	tests := []struct {
		name       string
		imds       credentials.CredentialRetriever
		auth       credentials.CredentialRetriever
		wantKey    string // AccessKeyId of expected credential
		wantSource credentials.CredentialSource
		wantErr    bool
		authCalled bool
	}{
		{
			name:       "IMDS unexpired → return IMDS, Auth Service not called",
			imds:       &stubRetriever{name: "imds", cred: imdsCred, meta: imdsMeta},
			auth:       &stubRetriever{name: "auth", cred: authCred, meta: authMeta},
			wantKey:    imdsCred.AccessKeyId,
			wantSource: credentials.SourceIMDS,
			authCalled: false,
		},
		{
			name:       "IMDS expired + Auth Service unexpired → return Auth Service",
			imds:       &stubRetriever{name: "imds", cred: imdsExpCred, meta: imdsExpMeta},
			auth:       &stubRetriever{name: "auth", cred: authCred, meta: authMeta},
			wantKey:    authCred.AccessKeyId,
			wantSource: credentials.SourceAuthService,
			authCalled: true,
		},
		{
			name:       "IMDS expired + Auth Service irrecoverable error → return IMDS",
			imds:       &stubRetriever{name: "imds", cred: imdsExpCred, meta: imdsExpMeta},
			auth:       &stubRetriever{name: "auth", err: irrecoverableErr},
			wantKey:    imdsExpCred.AccessKeyId,
			wantSource: credentials.SourceIMDS,
			authCalled: true,
		},
		{
			name:       "IMDS expired + Auth Service recoverable error → return IMDS",
			imds:       &stubRetriever{name: "imds", cred: imdsExpCred, meta: imdsExpMeta},
			auth:       &stubRetriever{name: "auth", err: recoverableErr},
			wantKey:    imdsExpCred.AccessKeyId,
			wantSource: credentials.SourceIMDS,
			authCalled: true,
		},
		{
			name:       "IMDS missing + Auth Service unexpired → return Auth Service",
			imds:       &stubRetriever{name: "imds", err: imds.ErrPodNotInMapping},
			auth:       &stubRetriever{name: "auth", cred: authCred, meta: authMeta},
			wantKey:    authCred.AccessKeyId,
			wantSource: credentials.SourceAuthService,
			authCalled: true,
		},
		{
			name:       "IMDS missing + Auth Service irrecoverable error → return error",
			imds:       &stubRetriever{name: "imds", err: imds.ErrPodNotInMapping},
			auth:       &stubRetriever{name: "auth", err: irrecoverableErr},
			wantErr:    true,
			authCalled: true,
		},
		{
			name:       "IMDS missing + Auth Service recoverable error → return error",
			imds:       &stubRetriever{name: "imds", err: imds.ErrCredentialNotFound},
			auth:       &stubRetriever{name: "auth", err: recoverableErr},
			wantErr:    true,
			authCalled: true,
		},
		{
			name:       "IMDS network error → falls through to Auth Service",
			imds:       &stubRetriever{name: "imds", err: errors.New("IMDS rate limiter: context deadline exceeded")},
			auth:       &stubRetriever{name: "auth", cred: authCred, meta: authMeta},
			wantKey:    authCred.AccessKeyId,
			wantSource: credentials.SourceAuthService,
			authCalled: true,
		},
		{
			name:       "nil IMDS delegate → skipped, Auth Service returns credential",
			imds:       nil,
			auth:       &stubRetriever{name: "auth", cred: authCred, meta: authMeta},
			wantKey:    authCred.AccessKeyId,
			wantSource: credentials.SourceAuthService,
			authCalled: true,
		},
		{
			name:    "both delegates nil → return error",
			imds:    nil,
			auth:    nil,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			chain := NewChainedRetriever(tt.imds, tt.auth)
			cred, meta, err := chain.GetIamCredentials(testContext(), testRequest)

			// Check if auth delegate was invoked
			authCalled := false
			if s, ok := tt.auth.(*stubRetriever); ok && s != nil {
				authCalled = s.called
			}
			assert.Equal(t, tt.authCalled, authCalled, "Auth Service called mismatch")

			if tt.wantErr {
				require.Error(t, err)
				assert.Nil(t, cred)
				assert.Equal(t, credentials.CredentialMetadata{}, meta)
				return
			}

			require.NoError(t, err)
			require.NotNil(t, cred)
			assert.Equal(t, tt.wantKey, cred.AccessKeyId)
			assert.Equal(t, tt.wantSource, meta.Source())
		})
	}
}

func TestChained_ErrorPropagation(t *testing.T) {
	tests := []struct {
		name                 string
		imds                 *stubRetriever
		auth                 *stubRetriever
		wantAllIrrecoverable bool
		wantUnwrapIMDSErr    error // if non-nil, errors.Is(err, this) must be true
	}{
		{
			name:                 "both irrecoverable → wraps ErrAllDelegatesIrrecoverable + both delegate errors",
			imds:                 &stubRetriever{name: "imds", err: imds.ErrPodNotInMapping, irrecoverable: true},
			auth:                 &stubRetriever{name: "auth", err: fmt.Errorf("wrapped: %w", &types.AccessDeniedException{}), irrecoverable: true},
			wantAllIrrecoverable: true,
			wantUnwrapIMDSErr:    imds.ErrPodNotInMapping,
		},
		{
			name:                 "IMDS irrecoverable + Auth recoverable → NOT ErrAllDelegatesIrrecoverable",
			imds:                 &stubRetriever{name: "imds", err: imds.ErrPodNotInMapping, irrecoverable: true},
			auth:                 &stubRetriever{name: "auth", err: fmt.Errorf("wrapped: %w", &types.InternalServerException{}), irrecoverable: false},
			wantAllIrrecoverable: false,
			wantUnwrapIMDSErr:    imds.ErrPodNotInMapping,
		},
		{
			name:                 "both recoverable → NOT ErrAllDelegatesIrrecoverable",
			imds:                 &stubRetriever{name: "imds", err: imds.ErrCredentialNotFound, irrecoverable: false},
			auth:                 &stubRetriever{name: "auth", err: fmt.Errorf("wrapped: %w", &types.InternalServerException{}), irrecoverable: false},
			wantAllIrrecoverable: false,
			wantUnwrapIMDSErr:    imds.ErrCredentialNotFound,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			chain := NewChainedRetriever(tt.imds, tt.auth)
			_, _, err := chain.GetIamCredentials(testContext(), testRequest)
			require.Error(t, err)

			assert.Equal(t, tt.wantAllIrrecoverable, errors.Is(err, ErrAllDelegatesIrrecoverable),
				"ErrAllDelegatesIrrecoverable mismatch")

			// Verify chain's own IsIrrecoverable agrees with the sentinel
			_, irrecoverable := chain.IsIrrecoverable(err)
			assert.Equal(t, tt.wantAllIrrecoverable, irrecoverable,
				"chain.IsIrrecoverable mismatch")

			// Verify per-delegate errors are unwrappable via errors.Is
			if tt.wantUnwrapIMDSErr != nil {
				assert.True(t, errors.Is(err, tt.wantUnwrapIMDSErr), "should unwrap IMDS error")
			}
		})
	}
}

func TestChained_SingleDelegate_Passthrough(t *testing.T) {
	cred, meta := unexpiredCred(credentials.SourceAuthService)
	auth := &stubRetriever{name: "auth", cred: cred, meta: meta}
	chain := NewChainedRetriever(auth)

	got, gotMeta, err := chain.GetIamCredentials(testContext(), testRequest)
	require.NoError(t, err)
	assert.Equal(t, cred.AccessKeyId, got.AccessKeyId)
	assert.Equal(t, credentials.SourceAuthService, gotMeta.Source())
}

