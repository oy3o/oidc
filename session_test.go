package oidc_test

import (
	"context"
	"net/url"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/oy3o/oidc"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// setupSessionTest 初始化 Session 测试环境
func setupSessionTest(t *testing.T) (*oidc.Server, oidc.Storage, oidc.RegisteredClient) {
	storage := NewTestStorage(t)
	hasher := &mockHasher{} // 假设已在 authorize_test.go 定义

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
		IDTokenTTL:      1 * time.Hour,
		RefreshTokenTTL: 24 * time.Hour,
	}

	server, err := oidc.NewServer(cfg)
	require.NoError(t, err)

	// 生成签名密钥
	_, err = server.KeyManager().Generate(context.Background(), oidc.KEY_RSA, true)
	require.NoError(t, err)

	// 创建客户端
	// 注意：session.go 中简化了逻辑，暂时复用 RedirectURIs 作为 PostLogoutRedirectURIs 的白名单
	clientID := oidc.BinaryUUID(uuid.New())
	clientMeta := oidc.ClientMetadata{
		ID:           clientID,
		RedirectURIs: []string{"https://client.example.com/cb", "https://client.example.com/logout_cb"},
		GrantTypes:   []string{"authorization_code"},
		Scope:        "openid profile",
		Name:         "Session Test Client",
	}

	client, err := storage.CreateClient(context.Background(), clientMeta)
	require.NoError(t, err)

	return server, storage, client
}

func TestEndSession_Success(t *testing.T) {
	server, storage, client := setupSessionTest(t)
	ctx := context.Background()

	// 1. 准备数据：生成用户的 Token
	userID := oidc.BinaryUUID(uuid.New())

	// 生成 OIDC Token 套件 (ID Token + AT + RT)
	issueReq := &oidc.IssuerRequest{
		ClientID: client.GetID(),
		UserID:   userID,
		Scopes:   "openid profile",
		Audience: []string{client.GetID().String()},
		Nonce:    "test-nonce",
	}
	tokens, err := server.Issuer().IssueOIDCTokens(ctx, issueReq)
	require.NoError(t, err)

	// 手动保存 RT 到存储 (模拟 Exchange 过程)
	rtHash := oidc.RefreshToken(tokens.RefreshToken).HashForDB()
	storage.CreateRefreshToken(ctx, &oidc.RefreshTokenSession{
		ID:        rtHash,
		ClientID:  client.GetID(),
		UserID:    userID,
		ExpiresAt: time.Now().Add(24 * time.Hour),
	})

	// 2. 构造 EndSessionRequest
	req := &oidc.EndSessionRequest{
		IDTokenHint:           tokens.IDToken,
		PostLogoutRedirectURI: "https://client.example.com/logout_cb",
		State:                 "logout-state",
		AccessToken:           tokens.AccessToken, // 同时请求撤销 AT
	}

	// 3. 执行登出
	// Server 实现了 TokenVerifier 接口
	redirectURL, err := oidc.EndSession(ctx, storage, server, req)
	require.NoError(t, err)

	// 4. 验证重定向 URL
	assert.NotEmpty(t, redirectURL)
	u, _ := url.Parse(redirectURL)
	assert.Equal(t, "https://client.example.com/logout_cb", u.Scheme+"://"+u.Host+u.Path)
	assert.Equal(t, "logout-state", u.Query().Get("state"))

	// 5. 验证 Refresh Token 是否被撤销 (RevokeTokensForUser)
	_, err = storage.GetRefreshToken(ctx, rtHash)
	assert.ErrorIs(t, err, oidc.ErrTokenNotFound, "Refresh token should be revoked")

	// 6. 验证 Access Token 是否被加入黑名单 (Revoke)
	claims, _ := server.ParseAccessToken(ctx, tokens.AccessToken)
	isRevoked, err := storage.IsRevoked(ctx, claims.ID)
	require.NoError(t, err)
	assert.True(t, isRevoked, "Access token JTI should be blacklisted")
}

func TestEndSession_InvalidRedirectURI(t *testing.T) {
	server, storage, client := setupSessionTest(t)
	ctx := context.Background()

	// 1. 生成 ID Token
	issueReq := &oidc.IssuerRequest{
		ClientID: client.GetID(),
		UserID:   oidc.BinaryUUID(uuid.New()),
		Scopes:   "openid",
	}
	tokens, _ := server.Issuer().IssueOIDCTokens(ctx, issueReq)

	// 2. 请求未注册的 Redirect URI
	req := &oidc.EndSessionRequest{
		IDTokenHint:           tokens.IDToken,
		PostLogoutRedirectURI: "https://attacker.com/logout",
		State:                 "xyz",
	}

	redirectURL, err := oidc.EndSession(ctx, storage, server, req)
	require.NoError(t, err)

	// 3. 验证不返回重定向 URL (但在内部可能已经执行了登出逻辑)
	assert.Empty(t, redirectURL, "Should not return redirect URL for unregistered URI")
}

func TestEndSession_NoHint(t *testing.T) {
	server, storage, _ := setupSessionTest(t)
	ctx := context.Background()

	// 1. 没有 ID Token Hint
	req := &oidc.EndSessionRequest{
		PostLogoutRedirectURI: "https://client.example.com/logout_cb",
	}

	// 2. 执行
	redirectURL, err := oidc.EndSession(ctx, storage, server, req)
	require.NoError(t, err)

	// 3. 验证
	// 因为无法确定 ClientID，无法验证 Redirect URI，所以返回空
	assert.Empty(t, redirectURL)
}

func TestEndSession_InvalidHint(t *testing.T) {
	server, storage, _ := setupSessionTest(t)
	ctx := context.Background()

	// 1. 损坏的 ID Token
	req := &oidc.EndSessionRequest{
		IDTokenHint:           "invalid.jwt.token",
		PostLogoutRedirectURI: "https://client.example.com/logout_cb",
	}

	// 2. 执行
	redirectURL, err := oidc.EndSession(ctx, storage, server, req)
	// session.go 的实现通常会忽略无效的 hint 并继续处理（避免登出阻塞），
	// 但由于解析失败，拿不到 ClientID，所以无法构建重定向
	require.NoError(t, err)
	assert.Empty(t, redirectURL)
}

func TestEndSession_RevokeOnlyAccessToken(t *testing.T) {
	server, storage, client := setupSessionTest(t)
	ctx := context.Background()

	// 1. 生成 Token (不使用 ID Token Hint，只传 Access Token)
	issueReq := &oidc.IssuerRequest{
		ClientID: client.GetID(),
		UserID:   oidc.BinaryUUID(uuid.New()),
		Scopes:   "openid",
	}
	tokens, _ := server.Issuer().IssueOAuthTokens(ctx, issueReq)

	// 2. 请求
	req := &oidc.EndSessionRequest{
		AccessToken: tokens.AccessToken,
	}

	// 3. 执行
	_, err := oidc.EndSession(ctx, storage, server, req)
	require.NoError(t, err)

	// 4. 验证 Access Token 黑名单
	claims, _ := server.ParseAccessToken(ctx, tokens.AccessToken)
	isRevoked, _ := storage.IsRevoked(ctx, claims.ID)
	assert.True(t, isRevoked, "Access token should be revoked even without id_token_hint")
}
