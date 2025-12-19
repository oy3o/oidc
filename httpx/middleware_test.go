package httpx_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/oy3o/httpx"
	"github.com/oy3o/oidc"
	oidchttpx "github.com/oy3o/oidc/httpx"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// generateDPoPHeader 辅助函数：生成 DPoP Proof Header
func generateDPoPHeader(t *testing.T, key *ecdsa.PrivateKey, method, uri string) string {
	jwkMap := map[string]interface{}{
		"kty": "EC",
		"crv": "P-256",
		"x":   base64.RawURLEncoding.EncodeToString(key.X.Bytes()),
		"y":   base64.RawURLEncoding.EncodeToString(key.Y.Bytes()),
	}

	claims := jwt.MapClaims{
		"htm": method,
		"htu": uri,
		"iat": time.Now().Unix(),
		"jti": uuid.New().String(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	token.Header["typ"] = "dpop+jwt"
	token.Header["jwk"] = jwkMap

	str, err := token.SignedString(key)
	require.NoError(t, err)
	return str
}

func TestAuthenticationMiddleware_Integration(t *testing.T) {
	// 1. 启动环境
	server, storage, client := setupServer(t)
	ctx := context.Background()

	// 2. 准备数据
	userID := oidc.BinaryUUID(uuid.New())
	userScope := "openid profile"

	// 准备 DPoP 密钥
	dpopKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	// 计算 DPoP JKT
	jwkObj, _ := oidc.PublicKeyToJWK(dpopKey.Public(), "", "")
	// 转换为 map 以计算 JKT (复用 dpop_test.go 中的逻辑或简化)
	jwkMap := map[string]interface{}{
		"kty": "EC", "crv": "P-256",
		"x": jwkObj.X, "y": jwkObj.Y,
	}
	dpopJKT, err := oidc.ComputeJKT(jwkMap)
	require.NoError(t, err)

	// 辅助函数：直接使用 Issuer 生成 Token
	issueToken := func(reqDPoPJKT string) string {
		req := &oidc.IssuerRequest{
			ClientID: client.GetID(),
			UserID:   userID,
			Scopes:   userScope,
			Audience: []string{client.GetID().String()},
			DPoPJKT:  reqDPoPJKT,
		}
		resp, err := server.Issuer().IssueOAuthTokens(ctx, req)
		require.NoError(t, err)
		return resp.AccessToken
	}

	// 3. 生成不同类型的 Token
	bearerToken := issueToken("")    // 普通 Token
	dpopToken := issueToken(dpopJKT) // DPoP 绑定 Token

	// 4. 定义自定义策略 (测试 Chain)
	customHeaderKey := "X-API-Key"
	verifyCustom := func(ctx context.Context, token string) (any, error) {
		if token == "valid-api-key" {
			// 返回特定 Claims 以示区别
			return &oidc.AccessTokenClaims{
				RegisteredClaims: jwt.RegisteredClaims{Subject: "system-admin"},
			}, nil
		}
		return nil, errors.New("invalid api key")
	}

	// 5. 组装中间件
	// 注意：DPoP 验证依赖于前置的 DPoPMiddleware 提取 Proof 到 Context
	// 这里我们需要模拟完整的链：DPoPMiddleware -> AuthMiddleware
	customStrategy := func(w http.ResponseWriter, r *http.Request) (any, error) {
		val := r.Header.Get(customHeaderKey)
		if val == "" {
			return nil, httpx.ErrNoCredentials
		}
		return verifyCustom(r.Context(), val)
	}
	authMiddleware := oidchttpx.AuthenticationMiddleware(server, customStrategy)
	dpopMiddleware := oidc.DPoPOptionalMiddleware(storage) // storage 实现了 ReplayCache

	// 6. 目标 Handler
	targetHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		claims, err := oidchttpx.GetClaims(r.Context())
		if err != nil {
			// 可能是 HTTPX Identity
			id := httpx.GetIdentity(r.Context())
			if c, ok := id.(*oidc.AccessTokenClaims); ok {
				w.Write([]byte("sub:" + c.Subject))
				return
			}
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Write([]byte("sub:" + claims.Subject))
	})

	// 组合最终 Handler
	handler := dpopMiddleware(authMiddleware(targetHandler))

	// 7. 测试用例
	tests := []struct {
		name       string
		setupReq   func() *http.Request
		wantStatus int
		wantBody   string
		checkAuth  bool // 检查 WWW-Authenticate 头
	}{
		{
			name: "Success: Bearer Token",
			setupReq: func() *http.Request {
				req := httptest.NewRequest("GET", "http://example.com/resource", nil)
				req.Header.Set("Authorization", "Bearer "+bearerToken)
				return req
			},
			wantStatus: http.StatusOK,
			wantBody:   "sub:" + userID.String(),
		},
		{
			name: "Success: DPoP Token",
			setupReq: func() *http.Request {
				uri := "http://example.com/resource"
				req := httptest.NewRequest("GET", uri, nil)
				req.Header.Set("Authorization", "DPoP "+dpopToken)
				// 添加 DPoP Proof
				proof := generateDPoPHeader(t, dpopKey, "GET", uri)
				req.Header.Set("DPoP", proof)
				return req
			},
			wantStatus: http.StatusOK,
			wantBody:   "sub:" + userID.String(),
		},
		{
			name: "Success: Custom Strategy",
			setupReq: func() *http.Request {
				req := httptest.NewRequest("GET", "http://example.com/resource", nil)
				req.Header.Set(customHeaderKey, "valid-api-key")
				return req
			},
			wantStatus: http.StatusOK,
			wantBody:   "sub:system-admin",
		},
		{
			name: "Success: Query Param Fallback",
			setupReq: func() *http.Request {
				req := httptest.NewRequest("GET", "http://example.com/resource?access_token="+bearerToken, nil)
				return req
			},
			wantStatus: http.StatusOK,
			wantBody:   "sub:" + userID.String(),
		},
		{
			name: "Security: Bearer Downgrade Attack (Use DPoP token as Bearer)",
			setupReq: func() *http.Request {
				req := httptest.NewRequest("GET", "http://example.com/resource", nil)
				// 攻击者截获了 DPoP Token，试图用 Bearer 方式绕过签名验证
				req.Header.Set("Authorization", "Bearer "+dpopToken)
				return req
			},
			wantStatus: http.StatusUnauthorized,
			checkAuth:  true,
		},
		{
			name: "Security: DPoP Missing Proof",
			setupReq: func() *http.Request {
				req := httptest.NewRequest("GET", "http://example.com/resource", nil)
				req.Header.Set("Authorization", "DPoP "+dpopToken)
				// 不发 DPoP Header
				return req
			},
			wantStatus: http.StatusUnauthorized,
			checkAuth:  true,
		},
		{
			name: "Security: DPoP Proof Mismatch (Wrong Key)",
			setupReq: func() *http.Request {
				uri := "http://example.com/resource"
				req := httptest.NewRequest("GET", uri, nil)
				req.Header.Set("Authorization", "DPoP "+dpopToken)

				// 使用另一个 Key 签名 Proof
				otherKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
				proof := generateDPoPHeader(t, otherKey, "GET", uri)
				req.Header.Set("DPoP", proof)
				return req
			},
			wantStatus: http.StatusUnauthorized,
			checkAuth:  true,
		},
		{
			name: "Failure: Invalid Token",
			setupReq: func() *http.Request {
				req := httptest.NewRequest("GET", "http://example.com/resource", nil)
				req.Header.Set("Authorization", "Bearer invalid.token.struct")
				return req
			},
			wantStatus: http.StatusUnauthorized,
			checkAuth:  true,
		},
		{
			name: "Failure: No Credentials",
			setupReq: func() *http.Request {
				return httptest.NewRequest("GET", "http://example.com/resource", nil)
			},
			wantStatus: http.StatusUnauthorized,
			checkAuth:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := tt.setupReq()
			w := httptest.NewRecorder()

			handler.ServeHTTP(w, req)

			assert.Equal(t, tt.wantStatus, w.Code)
			if tt.wantStatus == http.StatusOK {
				assert.Equal(t, tt.wantBody, w.Body.String())
			}

			if tt.checkAuth {
				authHeader := w.Header().Get("WWW-Authenticate")
				assert.NotEmpty(t, authHeader)
				assert.Contains(t, authHeader, "Bearer")
				assert.Contains(t, authHeader, "error=")
			}
		})
	}
}
