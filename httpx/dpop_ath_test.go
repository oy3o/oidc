package httpx_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/oy3o/oidc"
	oidchttpx "github.com/oy3o/oidc/httpx"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDPoP_ATH_Enforcement(t *testing.T) {
	server, storage, client := setupServer(t)
	ctx := context.Background()

	// 1. Setup User and DPoP Key
	userID := oidc.BinaryUUID(uuid.New())
	dpopKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	jwkMap := map[string]interface{}{
		"kty": "EC", "crv": "P-256",
		"x": base64.RawURLEncoding.EncodeToString(dpopKey.X.Bytes()),
		"y": base64.RawURLEncoding.EncodeToString(dpopKey.Y.Bytes()),
	}
	dpopJKT, _ := oidc.ComputeJKT(jwkMap)

	// 2. Issue DPoP Token
	issueToken := func() string {
		req := &oidc.IssuerRequest{
			ClientID: client.GetID(),
			UserID:   userID,
			Scopes:   "openid profile",
			Audience: []string{client.GetID().String()},
			DPoPJKT:  dpopJKT,
		}
		resp, err := server.Issuer().IssueOAuthTokens(ctx, req)
		require.NoError(t, err)
		return resp.AccessToken
	}
	token := issueToken()

	// 3. Helper to generate proof with specific ath
	generateProof := func(ath string) string {
		claims := jwt.MapClaims{
			"htm": "GET",
			"htu": "http://example.com/protected",
			"iat": time.Now().Unix(),
			"jti": uuid.New().String(),
		}
		if ath != "" {
			claims["ath"] = ath
		}
		twn := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
		twn.Header["typ"] = "dpop+jwt"
		twn.Header["jwk"] = jwkMap
		str, _ := twn.SignedString(dpopKey)
		return str
	}

	// 4. Setup Middleware Chain
	targetHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	authMiddleware := oidchttpx.AuthenticationMiddleware(server)
	dpopMiddleware := oidc.DPoPOptionalMiddleware(storage)
	handler := dpopMiddleware(authMiddleware(targetHandler))

	// 5. Test Cases
	correctSum := sha256.Sum256([]byte(token))
	correctATH := base64.RawURLEncoding.EncodeToString(correctSum[:])

	tests := []struct {
		name       string
		token      string
		proofATH   string
		wantStatus int
	}{
		{
			name:       "Success: Matching ATH",
			token:      token,
			proofATH:   correctATH,
			wantStatus: http.StatusOK,
		},
		{
			name:       "Failure: Missing ATH",
			token:      token,
			proofATH:   "",
			wantStatus: http.StatusUnauthorized,
		},
		{
			name:       "Failure: Mismatched ATH",
			token:      token,
			proofATH:   "invalid-ath",
			wantStatus: http.StatusUnauthorized,
		},
		{
			name:       "Failure: ATH from different token",
			token:      token,
			proofATH:   base64.RawURLEncoding.EncodeToString([]byte("wrong-token-hash")),
			wantStatus: http.StatusUnauthorized,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			uri := "http://example.com/protected"
			req := httptest.NewRequest("GET", uri, nil)
			req.Header.Set("Authorization", "DPoP "+tt.token)
			req.Header.Set("DPoP", generateProof(tt.proofATH))
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, req)
			assert.Equal(t, tt.wantStatus, w.Code, "Expected status %d for %s, got %d. Body: %s", tt.wantStatus, tt.name, w.Code, w.Body.String())
		})
	}
}
