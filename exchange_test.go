package oidc_test

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/oy3o/oidc"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// setupExchangeTest 初始化测试环境
func setupExchangeTest(t *testing.T) (*oidc.Server, oidc.Storage, oidc.RegisteredClient) {
	storage := NewTestStorage(t)
	hasher := &mockHasher{} // 复用 authorize_test.go 中的 mockHasher，或者在此重新定义

	// 初始化 SecretManager 并添加 HMAC 密钥
	sm := oidc.NewSecretManager()
	// 32字节的 hex string
	err := sm.AddKey("test-hmac-key", "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff")
	require.NoError(t, err)

	cfg := oidc.ServerConfig{
		Issuer:          "https://auth.example.com",
		Storage:         storage,
		Hasher:          hasher,
		SecretManager:   sm,
		AccessTokenTTL:  1 * time.Hour,
		RefreshTokenTTL: 24 * time.Hour,
		IDTokenTTL:      1 * time.Hour,
	}

	server, err := oidc.NewServer(cfg)
	require.NoError(t, err)

	// 生成签名密钥
	_, err = server.KeyManager().Generate(context.Background(), oidc.KEY_RSA, true)
	require.NoError(t, err)

	// 创建机密客户端
	clientID := oidc.BinaryUUID(uuid.New())
	clientMeta := &oidc.ClientMetadata{
		ID:                      clientID,
		RedirectURIs:            []string{"https://client.example.com/cb"},
		GrantTypes:              []string{"authorization_code", "refresh_token", "client_credentials"},
		Scope:                   "openid profile offline_access",
		Name:                    "Test Client",
		IsConfidentialClient:    true,
		Secret:                  "test_secret", // MockHasher 不加密，直接存明文
		TokenEndpointAuthMethod: "client_secret_basic",
	}

	client, err := storage.ClientCreate(context.Background(), clientMeta)
	require.NoError(t, err)

	return server, storage, client
}

// -----------------------------------------------------------------------------
// 1. Authorization Code Grant Tests
// -----------------------------------------------------------------------------

func TestExchange_AuthCode_Success(t *testing.T) {
	server, storage, client := setupExchangeTest(t)
	ctx := context.Background()

	// 1. 模拟生成并存储 Authorization Code
	code := "test_auth_code"
	userID := oidc.BinaryUUID(uuid.New())
	session := &oidc.AuthCodeSession{
		Code:        code,
		ClientID:    client.GetID(),
		UserID:      userID,
		Scope:       "profile offline_access",
		RedirectURI: "https://client.example.com/cb",
		AuthTime:    time.Now(),
		ExpiresAt:   time.Now().Add(10 * time.Minute),
	}
	err := storage.AuthCodeSave(ctx, session)
	require.NoError(t, err)

	// 2. 发起 Exchange 请求
	req := &oidc.TokenRequest{
		GrantType:    "authorization_code",
		Code:         code,
		ClientID:     client.GetID().String(),
		ClientSecret: "test_secret",
		RedirectURI:  "https://client.example.com/cb",
	}

	resp, err := server.Exchange(ctx, req)
	require.NoError(t, err)

	// 3. 验证响应
	assert.NotEmpty(t, resp.AccessToken)
	assert.Empty(t, resp.IDToken)         // 因为 scope 不包含 openid
	assert.NotEmpty(t, resp.RefreshToken) // 因为 scope 包含 offline_access (且 Server 配置了默认 RT)
	assert.Equal(t, "Bearer", resp.TokenType)
	assert.Equal(t, int64(3600), resp.ExpiresIn)

	// 4. 验证 Code 已被消耗
	_, err = storage.AuthCodeConsume(ctx, code)
	assert.ErrorIs(t, err, oidc.ErrCodeNotFound)
}

func TestExchange_AuthCode_PKCE(t *testing.T) {
	server, storage, client := setupExchangeTest(t)
	ctx := context.Background()

	// 生成 PKCE 数据
	verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	challenge, _ := oidc.ComputePKCEChallenge(oidc.CodeChallengeMethodS256, verifier)

	code := "pkce_code"
	session := &oidc.AuthCodeSession{
		Code:                code,
		ClientID:            client.GetID(),
		UserID:              oidc.BinaryUUID(uuid.New()),
		Scope:               "",
		RedirectURI:         "https://client.example.com/cb",
		AuthTime:            time.Now(),
		ExpiresAt:           time.Now().Add(time.Minute),
		CodeChallenge:       challenge,
		CodeChallengeMethod: oidc.CodeChallengeMethodS256,
	}
	storage.AuthCodeSave(ctx, session)

	// Case 1: 正确的 Verifier
	req := &oidc.TokenRequest{
		GrantType:    "authorization_code",
		Code:         code,
		ClientID:     client.GetID().String(),
		ClientSecret: "test_secret",
		RedirectURI:  "https://client.example.com/cb",
		CodeVerifier: verifier,
	}
	resp, err := server.Exchange(ctx, req)
	require.NoError(t, err)
	assert.NotEmpty(t, resp.AccessToken)

	// Case 2: 错误的 Verifier
	// 重置 Code (因为上一步消耗了)
	code2 := "pkce_code_2"
	session.Code = code2
	storage.AuthCodeSave(ctx, session)

	req2 := &oidc.TokenRequest{
		GrantType:    "authorization_code",
		Code:         code2,
		ClientID:     client.GetID().String(),
		ClientSecret: "test_secret",
		RedirectURI:  "https://client.example.com/cb",
		CodeVerifier: "wrong_verifier",
	}
	_, err = server.Exchange(ctx, req2)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "pkce verification failed")
}

func TestExchange_AuthCode_RedirectURIMismatch(t *testing.T) {
	server, storage, client := setupExchangeTest(t)
	ctx := context.Background()

	code := "uri_code"
	session := &oidc.AuthCodeSession{
		Code:        code,
		ClientID:    client.GetID(),
		UserID:      oidc.BinaryUUID(uuid.New()),
		RedirectURI: "https://client.example.com/cb",
		ExpiresAt:   time.Now().Add(time.Minute),
	}
	storage.AuthCodeSave(ctx, session)

	req := &oidc.TokenRequest{
		GrantType:    "authorization_code",
		Code:         code,
		ClientID:     client.GetID().String(),
		ClientSecret: "test_secret",
		RedirectURI:  "https://attacker.com/cb", // Mismatch
	}

	_, err := server.Exchange(ctx, req)
	assert.ErrorIs(t, err, oidc.ErrInvalidGrant)
	assert.Contains(t, err.Error(), "redirect_uri mismatch")
}

func TestExchange_AuthCode_Replay(t *testing.T) {
	server, storage, client := setupExchangeTest(t)
	ctx := context.Background()

	code := "replay_code"
	session := &oidc.AuthCodeSession{
		Code:      code,
		ClientID:  client.GetID(),
		UserID:    oidc.BinaryUUID(uuid.New()),
		ExpiresAt: time.Now().Add(time.Minute),
	}
	storage.AuthCodeSave(ctx, session)

	req := &oidc.TokenRequest{
		GrantType:    "authorization_code",
		Code:         code,
		ClientID:     client.GetID().String(),
		ClientSecret: "test_secret",
	}

	// 第一次：成功
	_, err := server.Exchange(ctx, req)
	require.NoError(t, err)

	// 第二次：失败 (Code Not Found)
	_, err = server.Exchange(ctx, req)
	assert.ErrorIs(t, err, oidc.ErrInvalidGrant)
	assert.Contains(t, err.Error(), "invalid or expired code")
}

func TestExchange_AuthCode_DPoPBinding(t *testing.T) {
	server, storage, client := setupExchangeTest(t)
	ctx := context.Background()

	jkt := "test-thumbprint"
	code := "dpop_code"

	createSession := func(jkt string) {
		session := &oidc.AuthCodeSession{
			Code:      code,
			ClientID:  client.GetID(),
			UserID:    oidc.BinaryUUID(uuid.New()),
			ExpiresAt: time.Now().Add(time.Minute),
			DPoPJKT:   jkt, // Code 绑定了 DPoP Key
		}
		storage.AuthCodeSave(ctx, session)
	}

	// Case 1: 缺少 DPoP Key
	createSession(jkt)
	req1 := &oidc.TokenRequest{
		GrantType:    "authorization_code",
		Code:         code,
		ClientID:     client.GetID().String(),
		ClientSecret: "test_secret",
	}
	_, err := server.Exchange(ctx, req1)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "DPoP key mismatch")

	// Case 2: DPoP Key 不匹配
	createSession(jkt)
	req2 := &oidc.TokenRequest{
		GrantType:    "authorization_code",
		Code:         code,
		ClientID:     client.GetID().String(),
		ClientSecret: "test_secret",
		DPoPJKT:      "wrong-thumbprint",
	}
	_, err = server.Exchange(ctx, req2)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "DPoP key mismatch")

	// Case 3: 匹配
	createSession(jkt)
	req3 := &oidc.TokenRequest{
		GrantType:    "authorization_code",
		Code:         code,
		ClientID:     client.GetID().String(),
		ClientSecret: "test_secret",
		DPoPJKT:      jkt,
	}
	resp, err := server.Exchange(ctx, req3)
	require.NoError(t, err)

	// 验证 Access Token 包含 cnf.jkt
	claims, err := server.ParseAccessToken(ctx, resp.AccessToken)
	require.NoError(t, err)
	assert.Equal(t, jkt, claims.Confirmation["jkt"])
}

// -----------------------------------------------------------------------------
// 2. Refresh Token Grant Tests
// -----------------------------------------------------------------------------

func TestExchange_RefreshToken_Success(t *testing.T) {
	server, storage, client := setupExchangeTest(t)
	ctx := context.Background()

	// 1. 预先创建一个 Refresh Token
	// 注意：Exchange 逻辑中，请求的 RT 字符串会先被哈希，再去 DB 查找
	// 我们需要模拟 IssueStructuredRefreshToken 的过程得到原始串，然后存哈希
	rtRaw, err := oidc.IssueStructuredRefreshToken(ctx, server.Issuer().SecretManager(), "user-1", 24*time.Hour)
	require.NoError(t, err)

	rtHash := oidc.RefreshToken(rtRaw).HashForDB()
	session := &oidc.RefreshTokenSession{
		ID:        rtHash,
		ClientID:  client.GetID(),
		UserID:    oidc.BinaryUUID(uuid.New()),
		Scope:     "openid profile",
		ExpiresAt: time.Now().Add(24 * time.Hour),
	}
	storage.RefreshTokenCreate(ctx, session)

	// 2. 发起刷新请求
	req := &oidc.TokenRequest{
		GrantType:    "refresh_token",
		RefreshToken: string(rtRaw),
		ClientID:     client.GetID().String(),
		ClientSecret: "test_secret",
	}

	resp, err := server.Exchange(ctx, req)
	require.NoError(t, err)

	// 3. 验证结果
	assert.NotEmpty(t, resp.AccessToken)
	assert.NotEmpty(t, resp.RefreshToken)
	assert.NotEqual(t, string(rtRaw), resp.RefreshToken) // 应该轮换了

	// 4. 验证旧 Token 被删除 (MockStorage 简单实现轮换是删除旧的)
	_, err = storage.RefreshTokenGet(ctx, rtHash)
	assert.ErrorIs(t, err, oidc.ErrTokenNotFound)
}

func TestExchange_RefreshToken_ReuseDetection(t *testing.T) {
	server, _, client := setupExchangeTest(t)
	ctx := context.Background()

	rt, err := oidc.IssueStructuredRefreshToken(ctx, server.SecretManager(), "user-1", 24*time.Hour)
	require.NoError(t, err)
	// 尝试使用一个不存在（或已被轮换删除）的 Token
	req := &oidc.TokenRequest{
		GrantType:    "refresh_token",
		RefreshToken: string(rt),
		ClientID:     client.GetID().String(),
		ClientSecret: "test_secret",
	}

	// 应该失败
	_, err = server.Exchange(ctx, req)
	// 在 MockStorage 中找不到 key 会返回 ErrTokenNotFound，
	// Exchange 逻辑会将其包装为 ErrInvalidGrant
	assert.ErrorIs(t, err, oidc.ErrInvalidGrant)
	assert.Contains(t, err.Error(), "invalid refresh token")
}

func TestExchange_RefreshToken_InvalidFormat(t *testing.T) {
	server, _, client := setupExchangeTest(t)
	ctx := context.Background()

	// Request by Client B (setupExchangeTest 创建的 client)
	req := &oidc.TokenRequest{
		GrantType:    "refresh_token",
		RefreshToken: "invalid_token",
		ClientID:     client.GetID().String(),
		ClientSecret: "test_secret",
	}

	_, err := server.Exchange(ctx, req)
	assert.ErrorIs(t, err, oidc.ErrTokenFormatInvalid)
}

func TestExchange_RefreshToken_ClientMismatch(t *testing.T) {
	server, storage, client := setupExchangeTest(t)
	ctx := context.Background()

	// Token 属于 User A, Client A
	rtRaw, _ := oidc.IssueStructuredRefreshToken(ctx, server.Issuer().SecretManager(), "user-1", 24*time.Hour)
	rtHash := oidc.RefreshToken(rtRaw).HashForDB()
	session := &oidc.RefreshTokenSession{
		ID:        rtHash,
		ClientID:  oidc.BinaryUUID(uuid.New()), // Different Client
		UserID:    oidc.BinaryUUID(uuid.New()),
		ExpiresAt: time.Now().Add(24 * time.Hour),
	}
	storage.RefreshTokenCreate(ctx, session)

	// Request by Client B (setupExchangeTest 创建的 client)
	req := &oidc.TokenRequest{
		GrantType:    "refresh_token",
		RefreshToken: string(rtRaw),
		ClientID:     client.GetID().String(),
		ClientSecret: "test_secret",
	}

	_, err := server.Exchange(ctx, req)
	assert.ErrorIs(t, err, oidc.ErrInvalidClient)
	assert.Contains(t, err.Error(), "client mismatch")
}

func TestExchange_RefreshToken_ScopeDownscoping(t *testing.T) {
	server, storage, client := setupExchangeTest(t)
	ctx := context.Background()

	rtRaw, _ := oidc.IssueStructuredRefreshToken(ctx, server.Issuer().SecretManager(), "user-1", 24*time.Hour)
	rtHash := oidc.RefreshToken(rtRaw).HashForDB()
	session := &oidc.RefreshTokenSession{
		ID:        rtHash,
		ClientID:  client.GetID(),
		UserID:    oidc.BinaryUUID(uuid.New()),
		Scope:     "openid profile email", // 原有 Scope
		ExpiresAt: time.Now().Add(24 * time.Hour),
	}
	storage.RefreshTokenCreate(ctx, session)

	// 1. 请求缩减 Scope
	req := &oidc.TokenRequest{
		GrantType:    "refresh_token",
		RefreshToken: string(rtRaw),
		ClientID:     client.GetID().String(),
		ClientSecret: "test_secret",
		Scope:        "openid", // 只要 openid
	}

	resp, err := server.Exchange(ctx, req)
	require.NoError(t, err)
	assert.Equal(t, "openid", resp.Scope)

	// 2. 验证新 Token 的 Scope 确实变了
	newRTHash := oidc.RefreshToken(resp.RefreshToken).HashForDB()
	newSession, err := storage.RefreshTokenGet(ctx, newRTHash)
	require.NoError(t, err)
	assert.Equal(t, "openid", newSession.Scope)

	// 3. 尝试请求未授权的 Scope (Up-scoping, 应禁止)
	// 恢复环境
	storage.RefreshTokenCreate(ctx, session)
	req.Scope = "openid admin"
	req.RefreshToken = string(rtRaw)

	_, err = server.Exchange(ctx, req)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid_scope")
}

// -----------------------------------------------------------------------------
// 3. Client Credentials Grant Tests
// -----------------------------------------------------------------------------

func TestExchange_ClientCredentials_Success(t *testing.T) {
	server, _, client := setupExchangeTest(t)
	ctx := context.Background()

	req := &oidc.TokenRequest{
		GrantType:    "client_credentials",
		ClientID:     client.GetID().String(),
		ClientSecret: "test_secret",
		Scope:        "openid", // 请求范围
	}

	resp, err := server.Exchange(ctx, req)
	require.NoError(t, err)

	assert.NotEmpty(t, resp.AccessToken)
	assert.Empty(t, resp.RefreshToken) // M2M 通常没有 RT
	assert.Empty(t, resp.IDToken)      // Client Credentials 不发 ID Token
	assert.Equal(t, "openid", resp.Scope)

	// 验证 Token 内容
	claims, err := server.ParseAccessToken(ctx, resp.AccessToken)
	require.NoError(t, err)
	assert.Equal(t, client.GetID().String(), claims.Subject) // sub == client_id
}

func TestExchange_ClientCredentials_InvalidSecret(t *testing.T) {
	server, _, client := setupExchangeTest(t)
	ctx := context.Background()

	req := &oidc.TokenRequest{
		GrantType:    "client_credentials",
		ClientID:     client.GetID().String(),
		ClientSecret: "wrong_secret",
	}

	_, err := server.Exchange(ctx, req)
	assert.ErrorIs(t, err, oidc.ErrInvalidClient)
}

func TestExchange_UnsupportedGrantType(t *testing.T) {
	server, _, _ := setupExchangeTest(t)
	ctx := context.Background()

	req := &oidc.TokenRequest{
		GrantType: "urn:ietf:params:oauth:grant-type:unknown",
	}

	_, err := server.Exchange(ctx, req)
	assert.ErrorIs(t, err, oidc.ErrUnsupportedGrantType)
}

func TestExchange_ClientCredentials_DPoP(t *testing.T) {
	server, _, client := setupExchangeTest(t) // 复用 exchange_test.go 的 setup
	ctx := context.Background()

	// 模拟 DPoP JKT (通常由 Middleware 提取)
	dpopJKT := "test-thumbprint-123"

	req := &oidc.TokenRequest{
		GrantType:    oidc.GrantTypeClientCredentials,
		ClientID:     client.GetID().String(),
		ClientSecret: "test_secret",
		Scope:        "openid",
		DPoPJKT:      dpopJKT, // 传入 JKT
	}

	// 执行 Exchange
	resp, err := server.Exchange(ctx, req)
	require.NoError(t, err)
	assert.NotEmpty(t, resp.AccessToken)

	// 验证 Access Token 中是否包含 cnf.jkt
	claims, err := server.ParseAccessToken(ctx, resp.AccessToken)
	require.NoError(t, err)

	require.NotNil(t, claims.Confirmation, "cnf claim missing")
	assert.Equal(t, dpopJKT, claims.Confirmation["jkt"], "jkt mismatch in M2M token")
}
