package oidc_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/oy3o/oidc"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// -----------------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------------

func generateECKey(t *testing.T) *ecdsa.PrivateKey {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	return key
}

// makeDPoPProof 辅助生成 DPoP Proof JWT
func makeDPoPProof(
	t *testing.T,
	key *ecdsa.PrivateKey,
	htm, htu string,
	iat time.Time,
	jti string,
	modifyHeaders func(h map[string]interface{}),
) string {
	// 构造 JWK Map (用于 Header)
	jwkMap := map[string]interface{}{
		"kty": "EC",
		"crv": "P-256",
		"x":   base64.RawURLEncoding.EncodeToString(key.X.Bytes()),
		"y":   base64.RawURLEncoding.EncodeToString(key.Y.Bytes()),
	}

	claims := jwt.MapClaims{
		"htm": htm,
		"htu": htu,
		"iat": iat.Unix(),
		"jti": jti,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	token.Header["typ"] = "dpop+jwt"
	token.Header["jwk"] = jwkMap

	if modifyHeaders != nil {
		modifyHeaders(token.Header)
	}

	str, err := token.SignedString(key)
	require.NoError(t, err)
	return str
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

func TestVerifyDPoPProof_Valid(t *testing.T) {
	ctx := context.Background()
	storage := NewTestStorage(t)
	key := generateECKey(t)

	htm := "POST"
	htu := "https://server.example.com/token"
	jti := uuid.New().String()

	proof := makeDPoPProof(t, key, htm, htu, time.Now(), jti, nil)

	req := httptest.NewRequest(htm, htu, nil)
	req.Header.Set("DPoP", proof)
	w := httptest.NewRecorder()

	jkt, err := oidc.VerifyDPoPProof(ctx, req, w, storage, htm, htu)
	require.NoError(t, err)
	assert.NotEmpty(t, jkt)

	// 验证计算出的 JKT 是否正确 (再次手动计算比对)
	jwkMap := map[string]interface{}{
		"kty": "EC", "crv": "P-256",
		"x": base64.RawURLEncoding.EncodeToString(key.X.Bytes()),
		"y": base64.RawURLEncoding.EncodeToString(key.Y.Bytes()),
	}
	expectedJKT, _ := oidc.ComputeJKT(jwkMap)
	assert.Equal(t, expectedJKT, jkt)
}

func TestVerifyDPoPProof_Replay(t *testing.T) {
	ctx := context.Background()
	storage := NewTestStorage(t)
	key := generateECKey(t)
	htm, htu := "POST", "https://server.example.com/token"
	jti := "replay-jti"

	proof := makeDPoPProof(t, key, htm, htu, time.Now(), jti, nil)
	req := httptest.NewRequest(htm, htu, nil)
	req.Header.Set("DPoP", proof)

	// 第一次：成功
	_, err := oidc.VerifyDPoPProof(ctx, req, nil, storage, htm, htu)
	require.NoError(t, err)

	// 第二次：失败 (Replay)
	_, err = oidc.VerifyDPoPProof(ctx, req, nil, storage, htm, htu)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "jti has been used")
}

func TestVerifyDPoPProof_TimeSkew(t *testing.T) {
	ctx := context.Background()
	storage := NewTestStorage(t)
	key := generateECKey(t)
	htm, htu := "POST", "https://server.example.com/token"

	tests := []struct {
		name      string
		iat       time.Time
		wantError string
	}{
		{
			name:      "Too Old",
			iat:       time.Now().Add(-2 * time.Minute),
			wantError: "iat too far",
		},
		{
			name:      "Too Future",
			iat:       time.Now().Add(2 * time.Minute),
			wantError: "iat too far",
		},
		{
			name:      "Acceptable Past",
			iat:       time.Now().Add(-30 * time.Second),
			wantError: "",
		},
		{
			name:      "Acceptable Future",
			iat:       time.Now().Add(30 * time.Second),
			wantError: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			proof := makeDPoPProof(t, key, htm, htu, tt.iat, uuid.NewString(), nil)
			req := httptest.NewRequest(htm, htu, nil)
			req.Header.Set("DPoP", proof)

			_, err := oidc.VerifyDPoPProof(ctx, req, nil, storage, htm, htu)
			if tt.wantError != "" {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantError)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestVerifyDPoPProof_MethodMismatch(t *testing.T) {
	ctx := context.Background()
	storage := NewTestStorage(t)
	key := generateECKey(t)
	htu := "https://server.example.com/token"

	// Proof claims "GET", but request is "POST"
	proof := makeDPoPProof(t, key, "GET", htu, time.Now(), uuid.NewString(), nil)
	req := httptest.NewRequest("POST", htu, nil)
	req.Header.Set("DPoP", proof)

	_, err := oidc.VerifyDPoPProof(ctx, req, nil, storage, "POST", htu)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "htm mismatch")
}

func TestVerifyDPoPProof_URIMismatch(t *testing.T) {
	ctx := context.Background()
	storage := NewTestStorage(t)
	key := generateECKey(t)
	htm := "POST"

	// Proof claims "/token", but request is "/other"
	proof := makeDPoPProof(t, key, htm, "https://example.com/token", time.Now(), uuid.NewString(), nil)
	req := httptest.NewRequest(htm, "https://example.com/other", nil)
	req.Header.Set("DPoP", proof)

	_, err := oidc.VerifyDPoPProof(ctx, req, nil, storage, htm, "https://example.com/other")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "htu mismatch")
}

func TestVerifyDPoPProof_InvalidHeader(t *testing.T) {
	ctx := context.Background()
	storage := NewTestStorage(t)
	key := generateECKey(t)
	htm, htu := "POST", "https://example.com/token"

	tests := []struct {
		name      string
		modifier  func(h map[string]interface{})
		wantError string
	}{
		{
			name: "Wrong Type",
			modifier: func(h map[string]interface{}) {
				h["typ"] = "JWT"
			},
			wantError: "typ must be 'dpop+jwt'",
		},
		{
			name: "None Alg",
			modifier: func(h map[string]interface{}) {
				h["alg"] = "none"
			},
			wantError: "token signature is invalid",
		},
		{
			name: "Missing JWK",
			modifier: func(h map[string]interface{}) {
				delete(h, "jwk")
			},
			wantError: "missing jwk",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			proof := makeDPoPProof(t, key, htm, htu, time.Now(), uuid.NewString(), tt.modifier)
			req := httptest.NewRequest(htm, htu, nil)
			req.Header.Set("DPoP", proof)

			_, err := oidc.VerifyDPoPProof(ctx, req, nil, storage, htm, htu)
			assert.Error(t, err)
			assert.Contains(t, err.Error(), tt.wantError)
		})
	}
}

func TestComputeJKT(t *testing.T) {
	// RFC 7638 Example for RSA Key
	// N, E taken from RFC example
	jwkRSA := map[string]interface{}{
		"kty": "RSA",
		"n":   "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
		"e":   "AQAB",
	}

	// Expected thumbprint from RFC 7638 Section 3.1
	// SHA-256 hash of canonical JSON:
	// {"e":"AQAB","kty":"RSA","n":"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw"}
	// Value: NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs
	expected := "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"

	jkt, err := oidc.ComputeJKT(jwkRSA)
	require.NoError(t, err)
	assert.Equal(t, expected, jkt)
}

func TestBuildDPoPBoundAccessTokenURI(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"https://example.com/resource", "https://example.com/resource"},
		{"https://example.com/resource?query=123", "https://example.com/resource"},
		{"https://example.com/resource#fragment", "https://example.com/resource"},
		{"https://example.com/resource?query=1#frag", "https://example.com/resource"},
	}

	for _, tt := range tests {
		got, err := oidc.BuildDPoPBoundAccessTokenURI(tt.input)
		require.NoError(t, err)
		assert.Equal(t, tt.expected, got)
	}
}

// -----------------------------------------------------------------------------
// Security Tests
// -----------------------------------------------------------------------------

type mockReplayCache struct{}

func (m *mockReplayCache) CheckAndStore(ctx context.Context, jti string, ttl time.Duration) (bool, error) {
	return false, nil
}

func TestVerifyDPoPProof_RejectsSymmetricKeys(t *testing.T) {
	ctx := context.Background()
	// Use a mock cache to avoid DB dependency for this unit test
	mockCache := &mockReplayCache{}

	htm := "POST"
	htu := "https://server.example.com/token"
	jti := uuid.New().String()

	// Symmetric Key (HMAC)
	secret := []byte("secret-key-must-be-long-enough-for-hs256")

	// Construct JWK for the symmetric key
	jwkMap := map[string]interface{}{
		"kty": "oct",
		"k":   "c2VjcmV0LWtleS1tdXN0LWJlLWxvbmctZW5vdWdoLWZvci1oczI1Ng", // Base64URL encoded secret
	}

	claims := jwt.MapClaims{
		"htm": htm,
		"htu": htu,
		"iat": time.Now().Unix(),
		"jti": jti,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	token.Header["typ"] = "dpop+jwt"
	token.Header["jwk"] = jwkMap

	// Sign using the secret
	proof, err := token.SignedString(secret)
	require.NoError(t, err)

	req := httptest.NewRequest(htm, htu, nil)
	req.Header.Set("DPoP", proof)

	_, err = oidc.VerifyDPoPProof(ctx, req, nil, mockCache, htm, htu)

	assert.Error(t, err)
	if err != nil {
		assert.Contains(t, err.Error(), "symmetric keys (oct) are not allowed")
	}
}
