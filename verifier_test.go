package oidc

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// -----------------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------------

func generateRSAKey(t *testing.T) *rsa.PrivateKey {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	return key
}

func signToken(t *testing.T, claims jwt.Claims, key *rsa.PrivateKey, kid string) string {
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = kid
	signed, err := token.SignedString(key)
	require.NoError(t, err)
	return signed
}

// -----------------------------------------------------------------------------
// ClientVerifier Tests (ID Token Validation)
// -----------------------------------------------------------------------------

func TestClientVerifier_Verify_Success(t *testing.T) {
	ctx := context.Background()
	privKey := generateRSAKey(t)
	kid := "test-key-1"

	// Setup StaticKeySet
	keySet := NewStaticKeySet()
	keySet.Add(kid, privKey.Public())

	issuer := "https://auth.example.com"
	clientID := "my-client-id"

	verifier := NewClientVerifier(issuer, clientID, keySet)

	// Construct Valid Claims
	now := time.Now()
	claims := &IDTokenClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    issuer,
			Subject:   "user-123",
			Audience:  jwt.ClaimStrings{clientID},
			ExpiresAt: jwt.NewNumericDate(now.Add(1 * time.Hour)),
			IssuedAt:  jwt.NewNumericDate(now),
		},
		AuthorizedParty: clientID,
	}

	tokenStr := signToken(t, claims, privKey, kid)

	// Verify
	gotClaims, err := verifier.Verify(ctx, tokenStr)
	require.NoError(t, err)
	assert.Equal(t, "user-123", gotClaims.Subject)
	assert.Equal(t, clientID, gotClaims.AuthorizedParty)
}

func TestClientVerifier_Verify_Failures(t *testing.T) {
	ctx := context.Background()
	privKey := generateRSAKey(t)
	kid := "test-key-1"
	keySet := NewStaticKeySet()
	keySet.Add(kid, privKey.Public())

	issuer := "https://auth.example.com"
	clientID := "my-client-id"
	verifier := NewClientVerifier(issuer, clientID, keySet)

	tests := []struct {
		name      string
		claims    *IDTokenClaims
		wantError error
		errorMsg  string
	}{
		{
			name: "Expired Token",
			claims: &IDTokenClaims{
				RegisteredClaims: jwt.RegisteredClaims{
					Issuer:    issuer,
					Audience:  jwt.ClaimStrings{clientID},
					ExpiresAt: jwt.NewNumericDate(time.Now().Add(-1 * time.Hour)), // Expired
				},
			},
			wantError: ErrTokenExpired,
		},
		{
			name: "Wrong Issuer",
			claims: &IDTokenClaims{
				RegisteredClaims: jwt.RegisteredClaims{
					Issuer:    "https://evil.com", // Wrong
					Audience:  jwt.ClaimStrings{clientID},
					ExpiresAt: jwt.NewNumericDate(time.Now().Add(1 * time.Hour)),
				},
			},
			wantError: ErrInvalidIssuer,
		},
		{
			name: "Wrong Audience",
			claims: &IDTokenClaims{
				RegisteredClaims: jwt.RegisteredClaims{
					Issuer:    issuer,
					Audience:  jwt.ClaimStrings{"other-client"}, // Wrong
					ExpiresAt: jwt.NewNumericDate(time.Now().Add(1 * time.Hour)),
				},
			},
			wantError: ErrInvalidAudience,
		},
		{
			name: "Multiple Aud without Azp",
			claims: &IDTokenClaims{
				RegisteredClaims: jwt.RegisteredClaims{
					Issuer:    issuer,
					Audience:  jwt.ClaimStrings{clientID, "other-client"}, // Multi
					ExpiresAt: jwt.NewNumericDate(time.Now().Add(1 * time.Hour)),
				},
				AuthorizedParty: "", // Missing
			},
			wantError: ErrAZPRequired,
		},
		{
			name: "Azp Mismatch",
			claims: &IDTokenClaims{
				RegisteredClaims: jwt.RegisteredClaims{
					Issuer:    issuer,
					Audience:  jwt.ClaimStrings{clientID},
					ExpiresAt: jwt.NewNumericDate(time.Now().Add(1 * time.Hour)),
				},
				AuthorizedParty: "other-client", // Mismatch with verifier's clientID
			},
			wantError: ErrAZPMismatch,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tokenStr := signToken(t, tt.claims, privKey, kid)
			_, err := verifier.Verify(ctx, tokenStr)
			if tt.wantError != nil {
				assert.ErrorIs(t, err, tt.wantError)
			} else if tt.errorMsg != "" {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.errorMsg)
			}
		})
	}
}

func TestClientVerifier_SignatureInvalid(t *testing.T) {
	ctx := context.Background()
	privKey := generateRSAKey(t)
	otherKey := generateRSAKey(t) // 用于签名的不同密钥
	kid := "test-key-1"
	keySet := NewStaticKeySet()
	keySet.Add(kid, privKey.Public()) // 验证器只知道 privKey 的公钥

	issuer := "https://auth.example.com"
	clientID := "my-client-id"
	verifier := NewClientVerifier(issuer, clientID, keySet)

	claims := &IDTokenClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    issuer,
			Audience:  jwt.ClaimStrings{clientID},
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(1 * time.Hour)),
		},
	}

	// 用错误的私钥签名
	tokenStr := signToken(t, claims, otherKey, kid)

	_, err := verifier.Verify(ctx, tokenStr)
	assert.ErrorIs(t, err, ErrTokenSignatureInvalid)
}

// -----------------------------------------------------------------------------
// ResourceVerifier Tests (Access Token Validation)
// -----------------------------------------------------------------------------

func TestResourceVerifier_Verify_Success(t *testing.T) {
	ctx := context.Background()
	privKey := generateRSAKey(t)
	kid := "test-key-1"
	keySet := NewStaticKeySet()
	keySet.Add(kid, privKey.Public())

	issuer := "https://auth.example.com"
	resourceURI := "https://api.example.com"

	// Case 1: Standard Verification
	verifier := NewResourceVerifier(issuer, resourceURI, keySet, nil)
	claims := &AccessTokenClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    issuer,
			Audience:  jwt.ClaimStrings{resourceURI},
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(1 * time.Hour)),
		},
		Scope: "read:data",
	}
	tokenStr := signToken(t, claims, privKey, kid)
	got, err := verifier.Verify(ctx, tokenStr)
	require.NoError(t, err)
	assert.Equal(t, "read:data", got.Scope)

	// Case 2: Verification with Trusted Clients
	trustedVerifier := NewResourceVerifier(issuer, resourceURI, keySet, []string{"trusted-client"})
	claims.AuthorizedParty = "trusted-client"
	tokenStr2 := signToken(t, claims, privKey, kid)
	got2, err := trustedVerifier.Verify(ctx, tokenStr2)
	require.NoError(t, err)
	assert.Equal(t, "trusted-client", got2.AuthorizedParty)
}

func TestResourceVerifier_TrustedClients(t *testing.T) {
	ctx := context.Background()
	privKey := generateRSAKey(t)
	kid := "test-key-1"
	keySet := NewStaticKeySet()
	keySet.Add(kid, privKey.Public())

	issuer := "https://auth.example.com"
	resourceURI := "https://api.example.com"
	trustedClients := []string{"client-a", "client-b"}

	verifier := NewResourceVerifier(issuer, resourceURI, keySet, trustedClients)

	tests := []struct {
		name      string
		azp       string
		wantError error
	}{
		{
			name:      "Authorized Client A",
			azp:       "client-a",
			wantError: nil,
		},
		{
			name:      "Authorized Client B",
			azp:       "client-b",
			wantError: nil,
		},
		{
			name:      "Unauthorized Client",
			azp:       "client-c",
			wantError: ErrAZPNotAuthorized,
		},
		{
			name:      "Missing AZP",
			azp:       "",
			wantError: ErrAZPRequiredForTrust,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			claims := &AccessTokenClaims{
				RegisteredClaims: jwt.RegisteredClaims{
					Issuer:    issuer,
					Audience:  jwt.ClaimStrings{resourceURI},
					ExpiresAt: jwt.NewNumericDate(time.Now().Add(1 * time.Hour)),
				},
				AuthorizedParty: tt.azp,
			}
			tokenStr := signToken(t, claims, privKey, kid)
			_, err := verifier.Verify(ctx, tokenStr)
			if tt.wantError != nil {
				assert.ErrorIs(t, err, tt.wantError)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// -----------------------------------------------------------------------------
// KeySource Fallback Test
// -----------------------------------------------------------------------------

func TestStaticKeySet_DefaultKey(t *testing.T) {
	ctx := context.Background()
	privKey := generateRSAKey(t)
	kid := "only-key"
	keySet := NewStaticKeySet()
	keySet.Add(kid, privKey.Public())

	// 测试：当只提供一个 Key 且请求 kid 为空时，应返回该 Key
	key, err := keySet.GetKey(ctx, "")
	require.NoError(t, err)
	assert.NotNil(t, key)

	// 测试：当有多个 Key 且请求 kid 为空时，应返回 Error
	otherKey := generateRSAKey(t)
	keySet.Add("other-key", otherKey.Public())
	_, err = keySet.GetKey(ctx, "")
	assert.ErrorIs(t, err, ErrKeyNotFound)
}
