package oidc_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/oy3o/oidc"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// -----------------------------------------------------------------------------
// 1. Server Initialization & Config Tests
// -----------------------------------------------------------------------------

func TestNewServer_Validation(t *testing.T) {
	storage := NewTestStorage(t)
	hasher := &mockHasher{}

	tests := []struct {
		name    string
		cfg     oidc.ServerConfig
		wantErr string
	}{
		{
			name: "Missing Issuer",
			cfg: oidc.ServerConfig{
				Issuer:  "",
				Storage: storage,
				Hasher:  hasher,
			},
			wantErr: "issuer url is required",
		},
		{
			name: "Missing Storage",
			cfg: oidc.ServerConfig{
				Issuer:  "https://test.com",
				Storage: nil,
				Hasher:  hasher,
			},
			wantErr: "storage implementation is required",
		},
		{
			name: "Missing Hasher",
			cfg: oidc.ServerConfig{
				Issuer:  "https://test.com",
				Storage: storage,
				Hasher:  nil,
			},
			wantErr: "hasher implementation is required",
		},
		{
			name: "Valid Config",
			cfg: oidc.ServerConfig{
				Issuer:  "https://test.com",
				Storage: storage,
				Hasher:  hasher,
			},
			wantErr: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := oidc.NewServer(tt.cfg)
			if tt.wantErr != "" {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestServer_Defaults(t *testing.T) {
	storage := NewTestStorage(t)
	hasher := &mockHasher{}

	// 初始化 SecretManager 并添加 HMAC 密钥
	sm := oidc.NewSecretManager()
	// 32字节的 hex string
	err := sm.AddKey("test-hmac-key", "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff")
	require.NoError(t, err)

	cfg := oidc.ServerConfig{
		Issuer:        "https://test.com",
		Storage:       storage,
		Hasher:        hasher,
		SecretManager: sm,
		// Leave TTLs as 0
	}

	server, err := oidc.NewServer(cfg)
	require.NoError(t, err)

	// 验证默认 TTL 是否被正确设置
	assert.Equal(t, 5*time.Minute, server.Config().CodeTTL)
	assert.Equal(t, 1*time.Hour, server.Config().AccessTokenTTL)
	assert.Equal(t, 1*time.Hour, server.Config().IDTokenTTL)
	assert.Equal(t, 30*24*time.Hour, server.Config().RefreshTokenTTL)
	assert.NotEmpty(t, server.Config().SupportedSigningAlgs)
}

// -----------------------------------------------------------------------------
// 2. Key Management Integration Tests
// -----------------------------------------------------------------------------

func TestServer_ValidateKeys(t *testing.T) {
	storage := NewTestStorage(t)
	hasher := &mockHasher{}

	// 初始化 SecretManager 并添加 HMAC 密钥
	sm := oidc.NewSecretManager()
	// 32字节的 hex string
	err := sm.AddKey("test-hmac-key", "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff")
	require.NoError(t, err)

	cfg := oidc.ServerConfig{
		Issuer:        "https://test.com",
		Storage:       storage,
		Hasher:        hasher,
		SecretManager: sm,
	}

	server, err := oidc.NewServer(cfg)
	require.NoError(t, err)

	// 1. 初始状态：没有密钥
	ctx := context.Background()
	err = server.ValidateKeys(ctx)
	assert.ErrorIs(t, err, oidc.ErrNoSigningKey)

	// 2. 添加密钥
	kid, err := server.KeyManager().Generate(ctx, oidc.KEY_RSA, true)
	require.NoError(t, err)
	assert.NotEmpty(t, kid)

	// 3. 再次验证：应该成功
	err = server.ValidateKeys(ctx)
	assert.NoError(t, err)
}

// -----------------------------------------------------------------------------
// 3. Discovery Tests
// -----------------------------------------------------------------------------

func TestServer_Discovery(t *testing.T) {
	storage := NewTestStorage(t)
	hasher := &mockHasher{}
	issuer := "https://auth.example.com"

	// 初始化 SecretManager 并添加 HMAC 密钥
	sm := oidc.NewSecretManager()
	// 32字节的 hex string
	err := sm.AddKey("test-hmac-key", "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff")
	require.NoError(t, err)

	cfg := oidc.ServerConfig{
		Issuer:        issuer,
		Storage:       storage,
		Hasher:        hasher,
		SecretManager: sm,
	}

	server, err := oidc.NewServer(cfg)
	require.NoError(t, err)

	disco := server.Discovery()

	assert.Equal(t, issuer, disco.Issuer)
	assert.Equal(t, issuer+"/authorize", disco.AuthorizationEndpoint)
	assert.Equal(t, issuer+"/token", disco.TokenEndpoint)
	assert.Equal(t, issuer+"/jwks.json", disco.JWKSURI)
	assert.Equal(t, issuer+"/par", disco.PushedAuthorizationRequestEndpoint)

	assert.Contains(t, disco.ResponseTypesSupported, "code")
	assert.Contains(t, disco.GrantTypesSupported, "authorization_code")
	assert.Contains(t, disco.CodeChallengeMethodsSupported, "S256")
	assert.Contains(t, disco.IDTokenSigningAlgValuesSupported, "RS256")
}

// -----------------------------------------------------------------------------
// 4. Token Verification Tests (Server as Verifier)
// -----------------------------------------------------------------------------

func TestServer_VerifyAccessToken(t *testing.T) {
	storage := NewTestStorage(t)
	hasher := &mockHasher{}
	issuerURL := "https://auth.example.com"

	// 初始化 SecretManager 并添加 HMAC 密钥
	sm := oidc.NewSecretManager()
	// 32字节的 hex string
	err := sm.AddKey("test-hmac-key", "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff")
	require.NoError(t, err)

	cfg := oidc.ServerConfig{
		Issuer:        issuerURL,
		Storage:       storage,
		Hasher:        hasher,
		SecretManager: sm,
	}

	server, err := oidc.NewServer(cfg)
	require.NoError(t, err)

	// 生成密钥
	ctx := context.Background()
	_, err = server.KeyManager().Generate(ctx, oidc.KEY_RSA, true)
	require.NoError(t, err)

	// 准备一个 Token Request 来生成合法的 Access Token
	clientID := oidc.BinaryUUID(uuid.New())
	userID := oidc.BinaryUUID(uuid.New())

	req := &oidc.IssuerRequest{
		ClientID: clientID,
		UserID:   userID,
		Scopes:   "openid profile",
		Audience: []string{"https://api.example.com"},
	}

	// 直接调用内部 issuer 生成 token
	resp, err := server.Issuer().IssueOAuthTokens(ctx, req)
	require.NoError(t, err)
	validToken := resp.AccessToken

	// Case 1: 验证有效 Token
	claims, err := server.VerifyAccessToken(ctx, validToken)
	require.NoError(t, err)
	assert.Equal(t, issuerURL, claims.Issuer)
	assert.Equal(t, userID.String(), claims.Subject)
	assert.NotEmpty(t, claims.ID) // JTI 必须存在

	// Case 2: 验证无效签名 (篡改 Token)
	parts := strings.Split(validToken, ".")
	tamperedToken := parts[0] + "." + parts[1] + "." + "tamperedsignature"
	_, err = server.VerifyAccessToken(ctx, tamperedToken)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "could not base64 decode signature") // 取决于底层库错误信息，或者是 crypto error

	// Case 3: 验证撤销 (Revocation)
	// 将 Token 的 JTI 加入黑名单
	err = storage.Revoke(ctx, claims.ID, time.Now().Add(1*time.Hour))
	require.NoError(t, err)

	_, err = server.VerifyAccessToken(ctx, validToken)
	assert.ErrorIs(t, err, oidc.ErrTokenRevoked)
}

func TestServer_VerifyAccessToken_Expired(t *testing.T) {
	storage := NewTestStorage(t)
	hasher := &mockHasher{}

	// 初始化 SecretManager 并添加 HMAC 密钥
	sm := oidc.NewSecretManager()
	// 32字节的 hex string
	err := sm.AddKey("test-hmac-key", "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff")
	require.NoError(t, err)

	cfg := oidc.ServerConfig{
		Issuer:        "https://auth.example.com",
		Storage:       storage,
		Hasher:        hasher,
		SecretManager: sm,
		// 设置极短的有效期
		AccessTokenTTL: 1 * time.Millisecond,
	}

	server, err := oidc.NewServer(cfg)
	require.NoError(t, err)

	ctx := context.Background()
	_, err = server.KeyManager().Generate(ctx, oidc.KEY_RSA, true)
	require.NoError(t, err)

	req := &oidc.IssuerRequest{
		ClientID: oidc.BinaryUUID(uuid.New()),
		UserID:   oidc.BinaryUUID(uuid.New()),
		Scopes:   "openid",
	}

	resp, err := server.Issuer().IssueOAuthTokens(ctx, req)
	require.NoError(t, err)

	// 等待过期
	time.Sleep(10 * time.Millisecond)

	_, err = server.VerifyAccessToken(ctx, resp.AccessToken)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "token is expired")
}

// -----------------------------------------------------------------------------
// 5. Introspection Test
// -----------------------------------------------------------------------------
func TestServer_Introspect(t *testing.T) {
	storage := NewTestStorage(t)
	hasher := &mockHasher{}

	// 初始化 SecretManager 并添加 HMAC 密钥
	sm := oidc.NewSecretManager()
	// 32字节的 hex string
	err := sm.AddKey("test-hmac-key", "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff")
	require.NoError(t, err)

	cfg := oidc.ServerConfig{
		Issuer:        "https://auth.example.com",
		Storage:       storage,
		Hasher:        hasher,
		SecretManager: sm,
	}
	server, _ := oidc.NewServer(cfg)
	ctx := context.Background()
	_, err = server.KeyManager().Generate(ctx, oidc.KEY_RSA, true)
	require.NoError(t, err)

	// 0. 准备：创建一个机密客户端用于内省
	// Introspection 必须由已认证的客户端调用
	clientID := oidc.BinaryUUID(uuid.New())
	clientSecret := "test_secret"
	clientMeta := oidc.ClientMetadata{
		ID:             clientID,
		IsConfidential: true,
		Secret:         oidc.String(clientSecret), // MockHasher 直接比对，存明文即可
		RedirectURIs:   []string{"https://client.com/cb"},
	}
	_, err = storage.CreateClient(ctx, clientMeta)
	require.NoError(t, err)

	// 1. 生成 Access Token (用于被内省)
	req := &oidc.IssuerRequest{
		ClientID: clientID,
		UserID:   oidc.BinaryUUID(uuid.New()),
		Scopes:   "read:data",
		Audience: []string{clientID.String()},
	}
	resp, _ := server.Issuer().IssueOAuthTokens(ctx, req)

	// 2. Case: 成功内省 (有效 Token + 正确凭证)
	info, err := server.Introspect(ctx, resp.AccessToken, clientID.String(), clientSecret)
	require.NoError(t, err)
	assert.True(t, info.Active)
	assert.Equal(t, "read:data", info.Scope)
	assert.Equal(t, clientID.String(), info.ClientID)
	assert.Equal(t, "Bearer", info.TokenType)

	// 3. Case: 客户端认证失败 (错误 Secret)
	_, err = server.Introspect(ctx, resp.AccessToken, clientID.String(), "wrong_secret")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid client") // 或者是 unauthorized_client

	// 4. Case: Token 无效但客户端认证成功 -> 返回 Active: false
	// RFC 7662 要求：如果 Token 无效（过期/格式错误），只要 Client 认证通过，应返回 200 OK {"active": false}
	infoInvalid, err := server.Introspect(ctx, "invalid.token.string", clientID.String(), clientSecret)
	require.NoError(t, err)
	assert.False(t, infoInvalid.Active)

	// 5. Case: Token 已撤销 -> 返回 Active: false
	// 先解析获取 JTI
	claims, err := server.ParseAccessToken(ctx, resp.AccessToken)
	require.NoError(t, err, "ParseAccessToken failed")
	require.NotEmpty(t, claims.ID, "JTI is missing")

	err = storage.Revoke(ctx, claims.ID, time.Now().Add(time.Hour))
	require.NoError(t, err)

	infoRevoked, err := server.Introspect(ctx, resp.AccessToken, clientID.String(), clientSecret)
	require.NoError(t, err)
	assert.False(t, infoRevoked.Active)
}
