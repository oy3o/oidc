package httpx_test

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/bytedance/sonic"
	"github.com/google/uuid"
	"github.com/oy3o/httpx"
	"github.com/oy3o/oidc"
	oidchttpx "github.com/oy3o/oidc/httpx"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// -----------------------------------------------------------------------------
// Helper: Authenticated Request Builder
// -----------------------------------------------------------------------------

func newAuthRequest(method, target string, form url.Values, clientID, clientSecret string) *http.Request {
	req := httptest.NewRequest(method, target, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	// Basic Auth
	auth := clientID + ":" + clientSecret
	basic := base64.StdEncoding.EncodeToString([]byte(auth))
	req.Header.Set("Authorization", "Basic "+basic)
	return req
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

func TestDiscoveryHandler(t *testing.T) {
	server, _, _ := setupServer(t)
	handler := oidchttpx.DiscoveryHandler(server)

	req := httptest.NewRequest("GET", "/.well-known/openid-configuration", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Header().Get("Content-Type"), "application/json")

	var disco oidc.Discovery
	err := sonic.Unmarshal(w.Body.Bytes(), &disco)
	require.NoError(t, err)
	assert.Equal(t, "https://auth.example.com", disco.Issuer)
	assert.Contains(t, disco.TokenEndpoint, "/token")
}

func TestJWKSHandler(t *testing.T) {
	server, _, _ := setupServer(t)
	handler := oidchttpx.JWKSHandler(server)

	req := httptest.NewRequest("GET", "/jwks.json", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var jwks oidc.JSONWebKeySet
	err := sonic.Unmarshal(w.Body.Bytes(), &jwks)
	require.NoError(t, err)
	assert.NotEmpty(t, jwks.Keys) // setupServer 会生成一个 Key
}

func TestTokenHandler_AuthCode(t *testing.T) {
	server, storage, client := setupServer(t)
	handler := oidchttpx.TokenHandler(server)
	ctx := context.Background()

	// 1. 在 Storage 中预置一个 Auth Code
	userID := oidc.BinaryUUID(uuid.New())
	userName := "testuser"
	err := storage.UserCreateInfo(ctx, &oidc.UserInfo{
		Subject: userID.String(),
		Name:    &userName,
	})
	require.NoError(t, err)

	code := "test-code-123"
	session := &oidc.AuthCodeSession{
		Code:        code,
		ClientID:    client.GetID(),
		UserID:      userID,
		RedirectURI: "https://client.com/cb",
		Scope:       "openid profile",
		ExpiresAt:   time.Now().Add(time.Minute),
		AuthTime:    time.Now(),
	}
	err = storage.AuthCodeSave(ctx, session)
	require.NoError(t, err)

	// 2. 发起请求
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", "https://client.com/cb")

	// 客户端认证 (HTTPX Test Client 是 Confidential)
	req := newAuthRequest("POST", "/token", form, client.GetID().String(), "test_secret") // setupServer 中 secret 是 "hashed_test_secret"

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	// 3. 验证
	assert.Equal(t, http.StatusOK, w.Code)

	var resp oidc.IssuerResponse
	err = sonic.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.NotEmpty(t, resp.AccessToken)
	assert.NotEmpty(t, resp.IDToken)
	assert.Equal(t, "Bearer", resp.TokenType)
}

func TestTokenHandler_ClientCredentials(t *testing.T) {
	server, _, client := setupServer(t)
	handler := oidchttpx.TokenHandler(server)

	form := url.Values{}
	form.Set("grant_type", "client_credentials")
	form.Set("scope", "openid")

	req := newAuthRequest("POST", "/token", form, client.GetID().String(), "test_secret")
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	var resp oidc.IssuerResponse
	sonic.Unmarshal(w.Body.Bytes(), &resp)
	assert.NotEmpty(t, resp.AccessToken)
	assert.Empty(t, resp.IDToken) // M2M 无 ID Token
}

func TestTokenHandler_InvalidGrant(t *testing.T) {
	server, _, client := setupServer(t)
	handler := oidchttpx.TokenHandler(server)

	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", "invalid-code")
	form.Set("redirect_uri", "https://client.com/cb")

	req := newAuthRequest("POST", "/token", form, client.GetID().String(), "test_secret")
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	var errResp oidc.Error
	sonic.Unmarshal(w.Body.Bytes(), &errResp)
	assert.Equal(t, "invalid_grant", errResp.Code)
}

func TestUserInfoHandler(t *testing.T) {
	server, storage, client := setupServer(t)
	ctx := context.Background()

	// 1. 创建用户并填充信息
	userID := oidc.BinaryUUID(uuid.New())
	name := "Alice"
	email := "alice@example.com"
	storage.UserCreateInfo(ctx, &oidc.UserInfo{
		Subject: userID.String(),
		Name:    &name,
		Email:   &email,
	})

	// 2. 发行 Token
	req := &oidc.IssuerRequest{
		ClientID: client.GetID(),
		UserID:   userID,
		Scopes:   "openid profile",
		Audience: []string{client.GetID().String()},
	}
	tokenResp, _ := server.Issuer().IssueOAuthTokens(ctx, req)

	// 3. 构建 UserInfo Handler (需要包装 Auth Middleware)
	// UserInfoHandler 本身假设 Token 已经通过中间件验证并注入 Context
	coreHandler := oidchttpx.UserInfoHandler(server)

	// 使用 httpx.Chain 组合中间件
	authMiddleware := oidchttpx.AuthenticationMiddleware(server)
	handler := httpx.Chain(coreHandler, authMiddleware)

	// 4. 发起请求
	r := httptest.NewRequest("GET", "/userinfo", nil)
	r.Header.Set("Authorization", "Bearer "+tokenResp.AccessToken)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, r)

	// 5. 验证
	require.Equal(t, http.StatusOK, w.Code, "status code mismatch, body: %s", w.Body.String())
	var info oidc.UserInfo
	err := sonic.Unmarshal(w.Body.Bytes(), &info)
	require.NoError(t, err)
	assert.Equal(t, userID.String(), info.Subject)
	if info.Name != nil {
		assert.Equal(t, "Alice", *info.Name)
	} else {
		assert.Fail(t, "info.Name is nil")
	}
}

func TestRevocationHandler(t *testing.T) {
	server, storage, client := setupServer(t)
	handler := oidchttpx.RevocationHandler(server)
	ctx := context.Background()

	// 1. 发行 Token
	req := &oidc.IssuerRequest{
		ClientID: client.GetID(),
		UserID:   oidc.BinaryUUID(uuid.New()),
		Scopes:   "openid",
	}
	tokenResp, _ := server.Issuer().IssueOAuthTokens(ctx, req)

	// 2. 撤销请求
	form := url.Values{}
	form.Set("token", tokenResp.AccessToken)
	form.Set("token_type_hint", "access_token")

	httpReq := newAuthRequest("POST", "/revoke", form, client.GetID().String(), "test_secret")
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, httpReq)

	assert.Equal(t, http.StatusOK, w.Code)

	// 3. 验证已撤销 (通过 Introspect 或直接查 Storage)
	// 解析 Token 拿 JTI
	claims, _ := server.ParseAccessToken(ctx, tokenResp.AccessToken)
	isRevoked, _ := storage.AccessTokenIsRevoked(ctx, claims.ID)
	assert.True(t, isRevoked, "token should be in revocation list")
}

func TestIntrospectionHandler(t *testing.T) {
	server, _, client := setupServer(t)
	handler := oidchttpx.IntrospectionHandler(server)
	ctx := context.Background()

	// 1. 发行 Token
	req := &oidc.IssuerRequest{
		ClientID: client.GetID(),
		UserID:   oidc.BinaryUUID(uuid.New()),
		Scopes:   "openid",
	}
	tokenResp, _ := server.Issuer().IssueOAuthTokens(ctx, req)

	// 2. Introspect 请求
	form := url.Values{}
	form.Set("token", tokenResp.AccessToken)

	httpReq := newAuthRequest("POST", "/introspect", form, client.GetID().String(), "test_secret")
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, httpReq)

	assert.Equal(t, http.StatusOK, w.Code)

	var intro oidc.IntrospectionResponse
	sonic.Unmarshal(w.Body.Bytes(), &intro)
	assert.True(t, intro.Active)
	assert.Equal(t, client.GetID().String(), intro.ClientID)
}

func TestPARHandler(t *testing.T) {
	server, _, client := setupServer(t)
	handler := oidchttpx.PARHandler(server)

	form := url.Values{}
	form.Set("response_type", "code")
	form.Set("client_id", client.GetID().String())
	form.Set("redirect_uri", "https://client.com/cb")
	form.Set("scope", "openid")
	form.Set("code_challenge", "xyz")
	form.Set("code_challenge_method", "S256")
	form.Set("nonce", "test-nonce")

	req := newAuthRequest("POST", "/par", form, client.GetID().String(), "test_secret")
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusCreated, w.Code)

	var resp oidc.PARResponse
	sonic.Unmarshal(w.Body.Bytes(), &resp)
	assert.NotEmpty(t, resp.RequestURI)
	assert.True(t, strings.HasPrefix(resp.RequestURI, "urn:ietf:params:oauth:request_uri:"))
	assert.Equal(t, 60, resp.ExpiresIn)
}

func TestDeviceAuthorizationHandler(t *testing.T) {
	server, _, client := setupServer(t)
	handler := oidchttpx.DeviceAuthorizationHandler(server)

	form := url.Values{}
	form.Set("client_id", client.GetID().String())
	form.Set("scope", "openid")

	// Device Auth 端点可以是 Public Client，也可以是 Confidential
	req := httptest.NewRequest("POST", "/device/authorize", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	// 模拟 Basic Auth (Confidential Client)
	auth := client.GetID().String() + ":test_secret"
	req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(auth)))

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp oidc.DeviceAuthorizationResponse
	sonic.Unmarshal(w.Body.Bytes(), &resp)
	assert.NotEmpty(t, resp.DeviceCode)
	assert.NotEmpty(t, resp.UserCode)
	assert.Contains(t, resp.VerificationURI, "/oauth/device")
}
