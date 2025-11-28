package httpx_test

import (
	"context"
	"github.com/bytedance/sonic"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/oy3o/o11y"
	"github.com/oy3o/oidc"
	oidchttpx "github.com/oy3o/oidc/httpx"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestMain 初始化测试环境
func TestMain(m *testing.M) {
	cfg := o11y.Config{
		Enabled:     true,
		Service:     "oidc-httpx-test",
		Environment: "test",
		Log: o11y.LogConfig{
			Level:         "fatal", // 减少噪音
			EnableConsole: false,
		},
		Trace:  o11y.TraceConfig{Enabled: false, Exporter: "none"},
		Metric: o11y.MetricConfig{Enabled: false},
	}
	shutdown, _ := o11y.Init(cfg)
	code := m.Run()
	shutdown(context.Background())
	os.Exit(code)
}

// setupServer 创建一个完全配置的 OIDC Server 用于测试
func setupServer(t *testing.T) (*oidc.Server, *mockStorage, oidc.RegisteredClient) {
	storage := newMockStorage() // 使用本地定义的 mockStorage
	hasher := &mockHasher{}

	// 1. 初始化 Secret Manager
	sm := oidc.NewSecretManager()
	err := sm.AddKey("hmac-key-1", "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff")
	require.NoError(t, err)

	// 2. 创建 Server
	cfg := oidc.ServerConfig{
		Issuer:         "https://auth.example.com",
		Storage:        storage,
		Hasher:         hasher,
		SecretManager:  sm,
		AccessTokenTTL: 1 * time.Hour,
	}
	server, err := oidc.NewServer(cfg)
	require.NoError(t, err)

	// 3. 生成签名密钥 (必须步骤)
	_, err = server.KeyManager().Generate(context.Background(), oidc.KEY_RSA, true)
	require.NoError(t, err)

	// 4. 创建一个测试客户端
	clientID := oidc.BinaryUUID(uuid.New())
	clientMeta := oidc.ClientMetadata{
		ID:                      clientID,
		RedirectURIs:            []string{"https://client.com/cb"},
		GrantTypes:              []string{"authorization_code", "client_credentials"},
		Scope:                   "openid profile",
		Name:                    "HTTPX Test Client",
		IsConfidential:          true,
		Secret:                  "hashed_test_secret",
		TokenEndpointAuthMethod: "client_secret_basic",
	}
	client, err := storage.CreateClient(context.Background(), clientMeta)
	require.NoError(t, err)

	return server, storage, client
}

// mockHasher 简单哈希实现
type mockHasher struct{}

func (m *mockHasher) Hash(ctx context.Context, password []byte) ([]byte, error) {
	return []byte("hashed_" + string(password)), nil
}

func (m *mockHasher) Compare(ctx context.Context, hashedPassword []byte, password []byte) error {
	if string(hashedPassword) == "hashed_"+string(password) {
		return nil
	}
	return oidc.ErrInvalidGrant
}

// -----------------------------------------------------------------------------
// Discovery & JWKS Tests (CORS Check)
// -----------------------------------------------------------------------------

func TestDiscoveryHandler(t *testing.T) {
	server, _, _ := setupServer(t)
	handler := oidchttpx.DiscoveryHandler(server)

	req := httptest.NewRequest("GET", "/.well-known/openid-configuration", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "*", w.Header().Get("Access-Control-Allow-Origin"))

	var disco oidc.Discovery
	err := sonic.Unmarshal(w.Body.Bytes(), &disco)
	require.NoError(t, err)
	assert.Equal(t, "https://auth.example.com", disco.Issuer)
	assert.Equal(t, "https://auth.example.com/token", disco.TokenEndpoint)
}

func TestJWKSHandler(t *testing.T) {
	server, _, _ := setupServer(t)
	handler := oidchttpx.JWKSHandler(server)

	req := httptest.NewRequest("GET", "/jwks.json", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	// 1. 验证状态码
	assert.Equal(t, http.StatusOK, w.Code)

	// 2. [关键] 验证 CORS 头
	assert.Equal(t, "*", w.Header().Get("Access-Control-Allow-Origin"))
	assert.Contains(t, w.Header().Get("Cache-Control"), "max-age")

	// 3. 验证 JWKS 结构
	var jwks oidc.JSONWebKeySet
	err := sonic.Unmarshal(w.Body.Bytes(), &jwks)
	require.NoError(t, err)
	assert.NotEmpty(t, jwks.Keys)
	assert.Equal(t, "RSA", jwks.Keys[0].Kty)
}

// -----------------------------------------------------------------------------
// Token Handler Tests (Error Unwrapping Check)
// -----------------------------------------------------------------------------

func TestTokenHandler_ErrorHandling(t *testing.T) {
	server, _, _ := setupServer(t)
	handler := oidchttpx.TokenHandler(server)

	v := url.Values{}
	v.Set("grant_type", "unknown_grant")
	v.Set("client_id", "test-client") // 确保通过 Bind 校验，进入 Exchange 逻辑

	req := httptest.NewRequest("POST", "/token", strings.NewReader(v.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	var errResp oidc.Error
	sonic.Unmarshal(w.Body.Bytes(), &errResp)
	assert.Equal(t, "unsupported_grant_type", errResp.Code)
}

func TestTokenHandler_ClientCredentials(t *testing.T) {
	server, _, client := setupServer(t)
	handler := oidchttpx.TokenHandler(server)

	v := url.Values{}
	v.Set("grant_type", "client_credentials")
	v.Set("client_id", client.GetID().String())
	v.Set("client_secret", "test_secret")
	v.Set("scope", "openid")

	req := httptest.NewRequest("POST", "/token", strings.NewReader(v.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	var tokenResp oidc.IssuerResponse
	sonic.Unmarshal(w.Body.Bytes(), &tokenResp)
	assert.NotEmpty(t, tokenResp.AccessToken)
	assert.Equal(t, "Bearer", tokenResp.TokenType)
}

// -----------------------------------------------------------------------------
// Middleware Tests (RFC 6750 Compliance Check)
// -----------------------------------------------------------------------------

func TestAuthenticationMiddleware_Compliance(t *testing.T) {
	server, _, client := setupServer(t)
	mw := oidchttpx.AuthenticationMiddleware(server)

	protectedHandler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		claims, err := oidchttpx.GetClaims(r.Context())
		require.NoError(t, err)
		assert.NotEmpty(t, claims.Subject)
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("success"))
	}))

	t.Run("Missing Header", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api", nil)
		w := httptest.NewRecorder()
		protectedHandler.ServeHTTP(w, req)

		// 1. 验证状态码 401
		assert.Equal(t, http.StatusUnauthorized, w.Code)

		// 2. [关键] 验证 WWW-Authenticate 头 (RFC 6750)
		authHeader := w.Header().Get("WWW-Authenticate")
		assert.Contains(t, authHeader, `Bearer error="invalid_request"`)
		assert.Contains(t, authHeader, "Missing or invalid authorization header")
	})

	t.Run("Invalid Token", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api", nil)
		req.Header.Set("Authorization", "Bearer invalid-token.xyz")
		w := httptest.NewRecorder()

		protectedHandler.ServeHTTP(w, req)

		// 1. 验证状态码 401
		assert.Equal(t, http.StatusUnauthorized, w.Code)

		// 2. [关键] 验证 WWW-Authenticate 头
		authHeader := w.Header().Get("WWW-Authenticate")
		assert.Contains(t, authHeader, `Bearer error="invalid_token"`) // code 应该是 invalid_token
	})

	t.Run("Valid Token", func(t *testing.T) {
		// 生成一个有效 Token
		ctx := context.Background()
		// 使用 Server.Exchange 而不是不存在的 ExchangeClientCredentials
		tokenResp, err := server.Exchange(ctx, &oidc.TokenRequest{
			GrantType:    "client_credentials",
			ClientID:     client.GetID().String(),
			ClientSecret: "test_secret",
			Scope:        "openid",
		})
		require.NoError(t, err)

		req := httptest.NewRequest("GET", "/api", nil)
		req.Header.Set("Authorization", "Bearer "+tokenResp.AccessToken)
		w := httptest.NewRecorder()

		protectedHandler.ServeHTTP(w, req)
		assert.Equal(t, http.StatusOK, w.Code)
	})
}

// -----------------------------------------------------------------------------
// UserInfo Handler Integration
// -----------------------------------------------------------------------------

func TestUserInfoHandler(t *testing.T) {
	server, _, client := setupServer(t)
	mw := oidchttpx.AuthenticationMiddleware(server)
	handler := mw(oidchttpx.UserInfoHandler(server))

	// 生成 Access Token
	tokenResp, err := server.Exchange(context.Background(), &oidc.TokenRequest{
		GrantType:    "client_credentials",
		ClientID:     client.GetID().String(),
		ClientSecret: "test_secret",
		Scope:        "openid profile",
	})
	require.NoError(t, err)

	req := httptest.NewRequest("GET", "/userinfo", nil)
	req.Header.Set("Authorization", "Bearer "+tokenResp.AccessToken)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	var info oidc.UserInfo
	sonic.Unmarshal(w.Body.Bytes(), &info)
	assert.NotNil(t, info.Name)
	assert.Equal(t, "Test User", *info.Name)
}

// -----------------------------------------------------------------------------
// Introspection Handler Tests
// -----------------------------------------------------------------------------

func TestIntrospectionHandler(t *testing.T) {
	server, _, client := setupServer(t)
	handler := oidchttpx.IntrospectionHandler(server)

	// 1. 获取一个有效 Token
	tokenResp, err := server.Exchange(context.Background(), &oidc.TokenRequest{
		GrantType:    "client_credentials",
		ClientID:     client.GetID().String(),
		ClientSecret: "test_secret",
		Scope:        "openid",
	})
	require.NoError(t, err)

	// 2. 发起内省请求 (Basic Auth)
	v := url.Values{}
	v.Set("token", tokenResp.AccessToken)

	req := httptest.NewRequest("POST", "/introspect", strings.NewReader(v.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(client.GetID().String(), "test_secret")
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var intro oidc.IntrospectionResponse
	sonic.Unmarshal(w.Body.Bytes(), &intro)
	assert.True(t, intro.Active)
	assert.Equal(t, client.GetID().String(), intro.ClientID)
}
