package oidc

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/bytedance/sonic"
	"github.com/golang-jwt/jwt/v5"
	"github.com/oy3o/oidc"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// -----------------------------------------------------------------------------
// Mock Server Helpers
// -----------------------------------------------------------------------------

// mockServerContext 包含测试所需的密钥和服务器实例
type mockServerContext struct {
	server     *httptest.Server
	privateKey *rsa.PrivateKey
	issuer     string
	// 用于记录请求，以便断言
	lastRequest *http.Request
	lastBody    map[string]interface{}
}

func setupMockOIDCServer(t *testing.T) *mockServerContext {
	// 1. 生成 RSA 密钥用于签名 ID Token
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	ctx := &mockServerContext{
		privateKey: privKey,
	}

	// 2. 创建 HTTP Server
	mux := http.NewServeMux()

	// /.well-known/openid-configuration
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		config := oidc.Discovery{
			Issuer:                             ctx.issuer, // 动态注入
			AuthorizationEndpoint:              ctx.issuer + "/authorize",
			TokenEndpoint:                      ctx.issuer + "/token",
			JWKSURI:                            ctx.issuer + "/jwks.json",
			UserInfoEndpoint:                   ctx.issuer + "/userinfo",
			RevocationEndpoint:                 ctx.issuer + "/revoke",
			IntrospectionEndpoint:              ctx.issuer + "/introspect",
			DeviceAuthorizationEndpoint:        ctx.issuer + "/device/authorize",
			PushedAuthorizationRequestEndpoint: ctx.issuer + "/par",
			EndSessionEndpoint:                 ctx.issuer + "/logout",
		}
		sonic.ConfigDefault.NewEncoder(w).Encode(config)
	})

	// /jwks.json
	mux.HandleFunc("/jwks.json", func(w http.ResponseWriter, r *http.Request) {
		jwk, _ := oidc.PublicKeyToJWK(privKey.Public(), "test-kid", "RS256")
		jwks := oidc.JSONWebKeySet{Keys: []oidc.JSONWebKey{jwk}}
		sonic.ConfigDefault.NewEncoder(w).Encode(jwks)
	})

	// /token
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		ctx.captureRequest(r)

		// 检查 Grant Type
		grantType := r.FormValue("grant_type")

		// 模拟 Device Flow 的 Polling 等待
		if grantType == "urn:ietf:params:oauth:grant-type:device_code" {
			if r.FormValue("device_code") == "pending_code" {
				// 第一次返回 pending
				w.WriteHeader(http.StatusBadRequest)
				sonic.ConfigDefault.NewEncoder(w).Encode(map[string]string{"error": "authorization_pending"})
				return
			}
		}

		// 生成 ID Token
		idToken := generateIDToken(t, ctx.issuer, "test-client", privKey)

		resp := Token{
			AccessToken:  "mock-access-token",
			TokenType:    "Bearer",
			RefreshToken: "mock-refresh-token",
			ExpiresIn:    3600,
			IDToken:      idToken,
			Scope:        "openid profile",
		}
		sonic.ConfigDefault.NewEncoder(w).Encode(resp)
	})

	// /par
	mux.HandleFunc("/par", func(w http.ResponseWriter, r *http.Request) {
		ctx.captureRequest(r)
		w.WriteHeader(http.StatusCreated)
		sonic.ConfigDefault.NewEncoder(w).Encode(map[string]interface{}{
			"request_uri": "urn:ietf:params:oauth:request_uri:mock-uuid",
			"expires_in":  60,
		})
	})

	// /device/authorize
	mux.HandleFunc("/device/authorize", func(w http.ResponseWriter, r *http.Request) {
		ctx.captureRequest(r)
		sonic.ConfigDefault.NewEncoder(w).Encode(oidc.DeviceAuthorizationResponse{
			DeviceCode:      "mock-device-code",
			UserCode:        "ABCD-1234",
			VerificationURI: ctx.issuer + "/device",
			ExpiresIn:       600,
			Interval:        1,
		})
	})

	// /userinfo
	mux.HandleFunc("/userinfo", func(w http.ResponseWriter, r *http.Request) {
		ctx.captureRequest(r)

		// 模拟 DPoP Nonce 校验
		if r.Header.Get("DPoP") != "" {
			var proof struct {
				Nonce string `json:"nonce"`
				ATH   string `json:"ath"`
			}
			parts := strings.Split(r.Header.Get("DPoP"), ".")
			if len(parts) == 3 {
				payload, _ := base64.RawURLEncoding.DecodeString(parts[1])
				sonic.Unmarshal(payload, &proof)
			}

			if proof.Nonce == "" {
				w.Header().Set("DPoP-Nonce", "next-nonce-123")
				w.WriteHeader(http.StatusUnauthorized)
				sonic.ConfigDefault.NewEncoder(w).Encode(map[string]string{"error": "use_dpop_nonce"})
				return
			}
		}

		// 检查 Authorization 头
		auth := r.Header.Get("Authorization")
		if auth == "" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		name := "Test User"
		sonic.ConfigDefault.NewEncoder(w).Encode(oidc.UserInfo{
			Subject: "user-123",
			Name:    &name,
		})
	})

	// /logout
	mux.HandleFunc("/logout", func(w http.ResponseWriter, r *http.Request) {
		ctx.captureRequest(r)
		w.WriteHeader(http.StatusOK)
	})

	// /revoke
	mux.HandleFunc("/revoke", func(w http.ResponseWriter, r *http.Request) {
		ctx.captureRequest(r)
		w.WriteHeader(http.StatusOK)
	})

	// /introspect
	mux.HandleFunc("/introspect", func(w http.ResponseWriter, r *http.Request) {
		ctx.captureRequest(r)
		sonic.ConfigDefault.NewEncoder(w).Encode(oidc.IntrospectionResponse{
			Active: true,
			Sub:    "user-123",
		})
	})

	ctx.server = httptest.NewServer(mux)
	ctx.issuer = ctx.server.URL // 必须在 server 启动后设置
	return ctx
}

func (c *mockServerContext) Close() {
	c.server.Close()
}

func (c *mockServerContext) captureRequest(r *http.Request) {
	r.ParseForm()
	c.lastRequest = r
	// 如果是 PostForm，也可以解析 Body
}

func generateIDToken(t *testing.T, issuer, clientID string, key *rsa.PrivateKey) string {
	now := time.Now()
	claims := oidc.IDTokenClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    issuer,
			Subject:   "user-123",
			Audience:  jwt.ClaimStrings{clientID},
			ExpiresAt: jwt.NewNumericDate(now.Add(time.Hour)),
			IssuedAt:  jwt.NewNumericDate(now),
		},
		AuthorizedParty: clientID,
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, &claims)
	token.Header["kid"] = "test-kid"
	s, err := token.SignedString(key)
	require.NoError(t, err)
	return s
}

// -----------------------------------------------------------------------------
// Client Tests
// -----------------------------------------------------------------------------

func TestNewClient_Discovery(t *testing.T) {
	mockCtx := setupMockOIDCServer(t)
	defer mockCtx.Close()

	cfg := ClientConfig{
		Issuer:   mockCtx.issuer,
		ClientID: "test-client",
	}

	client, err := NewClient(context.Background(), cfg, nil)
	require.NoError(t, err)
	assert.NotNil(t, client.discovery)
	assert.Equal(t, mockCtx.issuer+"/token", client.discovery.TokenEndpoint)
	assert.NotNil(t, client.verifier)
}

func TestClient_AuthCodeFlow(t *testing.T) {
	mockCtx := setupMockOIDCServer(t)
	defer mockCtx.Close()

	client, _ := NewClient(context.Background(), ClientConfig{
		Issuer:       mockCtx.issuer,
		ClientID:     "test-client",
		ClientSecret: "secret",
		RedirectURI:  "http://localhost/cb",
		Scopes:       []string{"openid", "profile"},
	}, nil)

	// 1. Auth Code URL
	urlStr := client.AuthCodeURL("state123", WithNonce("nonce123"))
	assert.Contains(t, urlStr, "response_type=code")
	assert.Contains(t, urlStr, "client_id=test-client")
	assert.Contains(t, urlStr, "state=state123")
	assert.Contains(t, urlStr, "nonce=nonce123")

	// 2. Exchange
	token, err := client.ExchangeAuthorizationCode(context.Background(), "auth-code", "pkce-verifier")
	require.NoError(t, err)

	// 验证请求参数
	require.NotNil(t, mockCtx.lastRequest)
	assert.Equal(t, "authorization_code", mockCtx.lastRequest.FormValue("grant_type"))
	assert.Equal(t, "auth-code", mockCtx.lastRequest.FormValue("code"))

	// 验证结果
	assert.Equal(t, "mock-access-token", token.AccessToken)
	assert.NotNil(t, token.IDTokenClaims)
	assert.Equal(t, "user-123", token.IDTokenClaims.Subject)
}

func TestClient_PAR(t *testing.T) {
	mockCtx := setupMockOIDCServer(t)
	defer mockCtx.Close()

	client, _ := NewClient(context.Background(), ClientConfig{
		Issuer:   mockCtx.issuer,
		ClientID: "test-client",
	}, nil)

	authURL, reqURI, err := client.PushAuthorize(context.Background(), "state-par")
	require.NoError(t, err)

	assert.Equal(t, "urn:ietf:params:oauth:request_uri:mock-uuid", reqURI)

	// 修复：解析 URL 来验证参数，自动处理 URL 编码问题
	u, err := url.Parse(authURL)
	require.NoError(t, err, "generated auth url should be valid")

	q := u.Query()
	assert.Equal(t, reqURI, q.Get("request_uri"), "request_uri param should match")
	assert.Equal(t, "test-client", q.Get("client_id"), "client_id param should match")

	// 验证 PAR 请求是 POST
	assert.Equal(t, http.MethodPost, mockCtx.lastRequest.Method)
	assert.Equal(t, "/par", mockCtx.lastRequest.URL.Path)
}

func TestClient_DPoP(t *testing.T) {
	mockCtx := setupMockOIDCServer(t)
	defer mockCtx.Close()

	// 生成客户端 DPoP 密钥
	dpopKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	client, _ := NewClient(context.Background(), ClientConfig{
		Issuer:   mockCtx.issuer,
		ClientID: "test-client",
	}, nil)

	// 启用 DPoP
	client.WithDPoP(dpopKey)

	// 1. Token Exchange with DPoP
	_, err := client.ExchangeClientCredentials(context.Background())
	require.NoError(t, err)

	// 验证 Server 收到了 DPoP Header
	dpopHeader := mockCtx.lastRequest.Header.Get("DPoP")
	assert.NotEmpty(t, dpopHeader, "DPoP header should be present")

	// 2. UserInfo with DPoP
	// 第一次 UserInfo 请求，没有 Nonce，Mock Server 会返回 401 并带上 Nonce
	_, err = client.UserInfo(context.Background(), "access-token")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "use_dpop_nonce")
	assert.Equal(t, "next-nonce-123", client.dpopNonce)

	// 第二次 UserInfo 请求，应该带上 Nonce 并成功
	userInfo, err := client.UserInfo(context.Background(), "access-token")
	require.NoError(t, err)
	assert.Equal(t, "Test User", *userInfo.Name)

	// 验证 UserInfo 请求头
	authHeader := mockCtx.lastRequest.Header.Get("Authorization")
	assert.True(t, strings.HasPrefix(authHeader, "DPoP "), "Authorization header should be DPoP type")
	assert.NotEmpty(t, mockCtx.lastRequest.Header.Get("DPoP"))

	// 验证 ATH 存在
	// 重新获取 DPoP Header (UserInfo 请求的)
	dpopHeader = mockCtx.lastRequest.Header.Get("DPoP")
	parts := strings.Split(dpopHeader, ".")
	payload, _ := base64.RawURLEncoding.DecodeString(parts[1])
	var proof map[string]interface{}
	sonic.Unmarshal(payload, &proof)
	assert.NotEmpty(t, proof["ath"], "ath claim should be present for resource access")

	// 3. Test DPoP Nonce Handling
	// 已经在上面 2 中验证了 Nonce 的捕获和携带
	assert.Equal(t, "next-nonce-123", client.dpopNonce)

	dpopHeader = mockCtx.lastRequest.Header.Get("DPoP")

	// 下一个请求应该带上 nonce
	_, err = client.UserInfo(context.Background(), "access-token")
	require.NoError(t, err)
	dpopHeader = mockCtx.lastRequest.Header.Get("DPoP")
	parts = strings.Split(dpopHeader, ".")
	payload, _ = base64.RawURLEncoding.DecodeString(parts[1])
	sonic.Unmarshal(payload, &proof)
	assert.Equal(t, "next-nonce-123", proof["nonce"])
}

func TestClient_PasswordGrant(t *testing.T) {
	mockCtx := setupMockOIDCServer(t)
	defer mockCtx.Close()

	client, _ := NewClient(context.Background(), ClientConfig{
		Issuer:   mockCtx.issuer,
		ClientID: "test-client",
	}, nil)

	token, err := client.ExchangePassword(context.Background(), "user", "pass")
	require.NoError(t, err)
	assert.NotEmpty(t, token.AccessToken)
	assert.Equal(t, "password", mockCtx.lastRequest.FormValue("grant_type"))
	assert.Equal(t, "user", mockCtx.lastRequest.FormValue("username"))
}

func TestClient_LogoutURL(t *testing.T) {
	mockCtx := setupMockOIDCServer(t)
	defer mockCtx.Close()

	client, _ := NewClient(context.Background(), ClientConfig{
		Issuer:   mockCtx.issuer,
		ClientID: "test-client",
	}, nil)

	logoutURL := client.LogoutURL("id-token", "http://post-logout", "state-key")
	assert.Contains(t, logoutURL, "/logout")
	assert.Contains(t, logoutURL, "id_token_hint=id-token")
	assert.Contains(t, logoutURL, "post_logout_redirect_uri=http%3A%2F%2Fpost-logout")
}

func TestClient_DeviceFlow(t *testing.T) {
	mockCtx := setupMockOIDCServer(t)
	defer mockCtx.Close()

	client, _ := NewClient(context.Background(), ClientConfig{
		Issuer:   mockCtx.issuer,
		ClientID: "test-client",
	}, nil)

	// 1. Request Code
	resp, err := client.RequestDeviceAuthorization(context.Background())
	require.NoError(t, err)
	assert.Equal(t, "mock-device-code", resp.DeviceCode)

	// 2. Poll Token
	// 我们在 mock server 中设置了第一次请求 device_code="pending_code" 返回 pending
	// 这里的测试用例为了快速通过，直接请求正常 code
	// 如果要测试 polling 逻辑，可以传 "pending_code" 并在 mock 中处理状态转换

	// 简单测试：直接成功
	token, err := client.PollDeviceToken(context.Background(), "mock-device-code", 1)
	require.NoError(t, err)
	assert.NotEmpty(t, token.AccessToken)
}

func TestClient_RevokeAndIntrospect(t *testing.T) {
	mockCtx := setupMockOIDCServer(t)
	defer mockCtx.Close()

	client, _ := NewClient(context.Background(), ClientConfig{
		Issuer:   mockCtx.issuer,
		ClientID: "test-client",
	}, nil)

	// AccessTokenRevoke
	err := client.AccessTokenRevoke(context.Background(), "some-token", "access_token")
	require.NoError(t, err)
	assert.Equal(t, "/revoke", mockCtx.lastRequest.URL.Path)

	// Introspect
	info, err := client.Introspect(context.Background(), "some-token")
	require.NoError(t, err)
	assert.True(t, info.Active)
	assert.Equal(t, "/introspect", mockCtx.lastRequest.URL.Path)
}

func TestClient_PKCEUtils(t *testing.T) {
	client := &Client{}
	verifier, challenge, err := client.GeneratePKCE()
	require.NoError(t, err)
	assert.NotEmpty(t, verifier)
	assert.NotEmpty(t, challenge)
	assert.NotEqual(t, verifier, challenge) // S256 should differ
}
