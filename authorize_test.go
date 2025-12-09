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

// mockHasher 用于测试的简单哈希器
type mockHasher struct{}

func (m *mockHasher) Hash(ctx context.Context, password []byte) ([]byte, error) {
	return password, nil // 测试时不进行实际哈希
}

func (m *mockHasher) Compare(ctx context.Context, hashedPassword []byte, password []byte) error {
	if string(hashedPassword) != string(password) {
		return oidc.ErrInvalidGrant
	}
	return nil
}

// setupAuthorizeTest 初始化 Server 和 Storage，并注册一个默认客户端
func setupAuthorizeTest(t *testing.T) (*oidc.Server, oidc.Storage, oidc.RegisteredClient) {
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
		CodeTTL:       10 * time.Minute,
	}

	server, err := oidc.NewServer(cfg)
	require.NoError(t, err)

	// 添加签名密钥 (NewServer 后必须步骤)
	_, err = server.KeyManager().Generate(context.Background(), oidc.KEY_RSA, true)
	require.NoError(t, err)

	// 创建一个测试客户端
	clientID := oidc.BinaryUUID(uuid.New())
	clientMeta := &oidc.ClientMetadata{
		ID:           clientID,
		RedirectURIs: []string{"https://client.example.com/cb"},
		GrantTypes:   []string{"authorization_code"},
		Scope:        "openid profile email",
		Name:         "Test Client",
	}

	client, err := storage.ClientCreate(context.Background(), clientMeta)
	require.NoError(t, err)

	return server, storage, client
}

func TestRequestAuthorize_Valid(t *testing.T) {
	server, _, client := setupAuthorizeTest(t)
	ctx := context.Background()

	req := &oidc.AuthorizeRequest{
		ClientID:            client.GetID().String(),
		RedirectURI:         "https://client.example.com/cb",
		ResponseType:        "code",
		Scope:               "openid profile",
		State:               "state123",
		Nonce:               "nonce123",
		CodeChallenge:       "challenge_string",
		CodeChallengeMethod: "S256",
	}

	gotClient, err := server.RequestAuthorize(ctx, req)
	assert.NoError(t, err)
	assert.Equal(t, client.GetID(), gotClient.GetID())
}

func TestRequestAuthorize_InvalidClient(t *testing.T) {
	server, _, _ := setupAuthorizeTest(t)
	ctx := context.Background()

	req := &oidc.AuthorizeRequest{
		ClientID:     uuid.New().String(), // 不存在的 ID
		RedirectURI:  "https://client.example.com/cb",
		ResponseType: "code",
	}

	_, err := server.RequestAuthorize(ctx, req)
	assert.Error(t, err)
	// 注意：为了防止枚举攻击，RequestAuthorize 可能会继续验证后续逻辑
	// 但最终会因为找不到 Client 或 RedirectURI 匹配失败而报错
	// 具体错误取决于实现细节，通常至少包含 invalid_request 或 client not found
}

func TestRequestAuthorize_RedirectURIMismatch(t *testing.T) {
	server, _, client := setupAuthorizeTest(t)
	ctx := context.Background()

	req := &oidc.AuthorizeRequest{
		ClientID:     client.GetID().String(),
		RedirectURI:  "https://attacker.com/cb", // 未注册的 URI
		ResponseType: "code",
	}

	_, err := server.RequestAuthorize(ctx, req)
	assert.ErrorIs(t, err, oidc.ErrInvalidRequest)
	assert.Contains(t, err.Error(), "mismatch redirect_uri")
}

func TestRequestAuthorize_UnsupportedResponseType(t *testing.T) {
	server, _, client := setupAuthorizeTest(t)
	ctx := context.Background()

	req := &oidc.AuthorizeRequest{
		ClientID:     client.GetID().String(),
		RedirectURI:  "https://client.example.com/cb",
		ResponseType: "token", // 仅支持 code
	}

	_, err := server.RequestAuthorize(ctx, req)
	assert.ErrorIs(t, err, oidc.ErrUnsupportedGrantType)
}

func TestRequestAuthorize_InvalidScope(t *testing.T) {
	server, _, client := setupAuthorizeTest(t)
	ctx := context.Background()

	req := &oidc.AuthorizeRequest{
		ClientID:     client.GetID().String(),
		RedirectURI:  "https://client.example.com/cb",
		ResponseType: "code",
		Scope:        "openid admin", // admin 不在允许列表中
	}

	_, err := server.RequestAuthorize(ctx, req)
	assert.ErrorIs(t, err, oidc.ErrInvalidScope)
}

func TestRequestAuthorize_MissingNonceForOpenID(t *testing.T) {
	server, _, client := setupAuthorizeTest(t)
	ctx := context.Background()

	req := &oidc.AuthorizeRequest{
		ClientID:     client.GetID().String(),
		RedirectURI:  "https://client.example.com/cb",
		ResponseType: "code",
		Scope:        "openid",
		Nonce:        "", // OpenID 需要 nonce
	}

	_, err := server.RequestAuthorize(ctx, req)
	assert.ErrorIs(t, err, oidc.ErrInvalidRequest)
	assert.Contains(t, err.Error(), "nonce is required")
}

func TestRequestAuthorize_PKCERequired(t *testing.T) {
	server, _, client := setupAuthorizeTest(t)
	ctx := context.Background()

	req := &oidc.AuthorizeRequest{
		ClientID:      client.GetID().String(),
		RedirectURI:   "https://client.example.com/cb",
		ResponseType:  "code",
		Scope:         "openid",
		Nonce:         "nonce",
		CodeChallenge: "", // 缺少 PKCE
	}

	_, err := server.RequestAuthorize(ctx, req)
	assert.ErrorIs(t, err, oidc.ErrInvalidRequest)
	assert.Contains(t, err.Error(), "code_challenge is required")
}

func TestRequestAuthorize_PAR(t *testing.T) {
	server, storage, client := setupAuthorizeTest(t)
	ctx := context.Background()

	// 1. 预先存储 PAR Session
	requestURI := "urn:ietf:params:oauth:request_uri:test-uuid"
	parReq := &oidc.AuthorizeRequest{
		ClientID:            client.GetID().String(),
		RedirectURI:         "https://client.example.com/cb",
		ResponseType:        "code",
		Scope:               "openid",
		State:               "par-state",
		Nonce:               "par-nonce",
		CodeChallenge:       "challenge",
		CodeChallengeMethod: "S256",
	}
	err := storage.PARSessionSave(ctx, requestURI, parReq, time.Minute)
	require.NoError(t, err)

	// 2. 使用 request_uri 发起请求
	req := &oidc.AuthorizeRequest{
		ClientID:   client.GetID().String(), // ClientID 仍需提供以查找 Client
		RequestURI: requestURI,
	}

	gotClient, err := server.RequestAuthorize(ctx, req)
	assert.NoError(t, err)
	assert.Equal(t, client.GetID(), gotClient.GetID())

	// 3. 验证 req 对象已被 PAR 内容填充
	assert.Equal(t, "openid", req.Scope)
	assert.Equal(t, "par-state", req.State)

	// 4. 验证 request_uri 只能使用一次 (Storage 应该删除它)
	_, err = storage.PARSessionConsume(ctx, requestURI)
	assert.Error(t, err, "PAR session should be deleted after use")
}

func TestResponseAuthorized_Success(t *testing.T) {
	server, storage, client := setupAuthorizeTest(t)
	ctx := context.Background()

	userID := uuid.New().String()
	authTime := time.Now()

	req := &oidc.AuthorizeRequest{
		ClientID:            client.GetID().String(),
		RedirectURI:         "https://client.example.com/cb",
		ResponseType:        "code",
		Scope:               "openid profile",
		State:               "xyz",
		Nonce:               "nonce123",
		CodeChallenge:       "challenge",
		CodeChallengeMethod: "S256",
		UserID:              userID,
		AuthTime:            authTime,
	}

	// 执行
	redirectURL, err := server.ResponseAuthorized(ctx, req)
	assert.NoError(t, err)

	// 验证 URL
	assert.Contains(t, redirectURL, "https://client.example.com/cb")
	assert.Contains(t, redirectURL, "code=")
	assert.Contains(t, redirectURL, "state=xyz")

	// 从 URL 提取 Code
	url, err := url.Parse(redirectURL)
	require.NoError(t, err)
	code := url.Query().Get("code")

	// 验证 Code 是否存在
	session, err := storage.AuthCodeConsume(ctx, code)
	require.NoError(t, err)

	require.NotNil(t, session)
	assert.Equal(t, client.GetID(), session.ClientID)
	assert.Equal(t, userID, session.UserID.String())
	assert.Equal(t, "openid profile", session.Scope)
	assert.WithinDuration(t, authTime, session.AuthTime, time.Second)
}

func TestResponseAuthorized_MissingUserID(t *testing.T) {
	server, _, client := setupAuthorizeTest(t)
	ctx := context.Background()

	req := &oidc.AuthorizeRequest{
		ClientID:     client.GetID().String(),
		RedirectURI:  "https://client.example.com/cb",
		ResponseType: "code",
		// UserID: "" // 缺少用户 ID
	}

	_, err := server.ResponseAuthorized(ctx, req)
	assert.ErrorIs(t, err, oidc.ErrUserIDRequired)
}

func TestResponseAuthorized_FinalScope(t *testing.T) {
	server, storage, client := setupAuthorizeTest(t)
	ctx := context.Background()

	req := &oidc.AuthorizeRequest{
		ClientID:            client.GetID().String(),
		RedirectURI:         "https://client.example.com/cb",
		ResponseType:        "code",
		Scope:               "openid profile email", // 请求的 scope
		FinalScope:          "openid profile",       // 用户同意的 scope (移除了 email)
		State:               "xyz",
		CodeChallenge:       "challenge",
		CodeChallengeMethod: "S256",
		UserID:              uuid.New().String(),
		AuthTime:            time.Now(),
	}

	redirectURL, err := server.ResponseAuthorized(ctx, req)
	assert.NoError(t, err)
	// 从 URL 提取 Code
	url, err := url.Parse(redirectURL)
	require.NoError(t, err)
	code := url.Query().Get("code")
	session, err := storage.AuthCodeConsume(ctx, code)
	require.NoError(t, err)
	require.NotNil(t, session)
	assert.Equal(t, "openid profile", session.Scope)
}
