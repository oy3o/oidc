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

// setupDeviceFlowTest 初始化设备流测试环境
func setupDeviceFlowTest(t *testing.T) (*oidc.Server, oidc.Storage, oidc.RegisteredClient) {
	storage, _ := NewTestStorage(t)
	hasher := &mockHasher{}

	// 初始化 SecretManager 并添加 HMAC 密钥
	sm := oidc.NewSecretManager()
	// 32字节的 hex string
	err := sm.AddKey("test-hmac-key", "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff")
	require.NoError(t, err)

	cfg := oidc.ServerConfig{
		Issuer:         "https://auth.example.com",
		Storage:        storage,
		Hasher:         hasher,
		SecretManager:  sm,
		AccessTokenTTL: 1 * time.Hour,
		IDTokenTTL:     1 * time.Hour,
	}

	server, err := oidc.NewServer(cfg)
	require.NoError(t, err)

	// 生成签名密钥
	_, err = server.KeyManager().Generate(context.Background(), oidc.KEY_RSA, true)
	require.NoError(t, err)

	// 创建支持设备流的客户端
	clientID := oidc.BinaryUUID(uuid.New())
	clientMeta := &oidc.ClientMetadata{
		ID:                      clientID,
		GrantTypes:              []string{"urn:ietf:params:oauth:grant-type:device_code"},
		Scope:                   "openid profile",
		Name:                    "Device Client",
		IsConfidentialClient:    false, // 公共客户端常见于设备流
		TokenEndpointAuthMethod: "none",
	}

	client, err := storage.ClientCreate(context.Background(), clientMeta)
	require.NoError(t, err)

	return server, storage, client
}

func TestDeviceAuthorization_Success(t *testing.T) {
	server, storage, client := setupDeviceFlowTest(t)
	ctx := context.Background()

	req := &oidc.DeviceAuthorizationRequest{
		ClientID: client.GetID().String(),
		Scope:    "openid profile",
	}

	// 1. 发起授权请求
	resp, err := server.DeviceAuthorization(ctx, req)
	require.NoError(t, err)

	// 2. 验证响应
	assert.NotEmpty(t, resp.DeviceCode)
	assert.NotEmpty(t, resp.UserCode)
	assert.Equal(t, "https://auth.example.com/oauth/device", resp.VerificationURI)
	assert.Equal(t, 600, resp.ExpiresIn)
	assert.Equal(t, 5, resp.Interval)

	// 3. 验证存储
	session, err := storage.DeviceCodeGet(ctx, resp.DeviceCode)
	require.NoError(t, err)
	assert.Equal(t, client.GetID(), session.ClientID)
	assert.Equal(t, oidc.DeviceCodeStatusPending, session.Status)
	assert.Equal(t, resp.UserCode, session.UserCode)

	// 验证 UserCode 索引
	sessionByUser, err := storage.DeviceCodeGetByUserCode(ctx, resp.UserCode)
	require.NoError(t, err)
	assert.Equal(t, resp.DeviceCode, sessionByUser.DeviceCode)
}

func TestDeviceAuthorization_InvalidClient(t *testing.T) {
	server, _, _ := setupDeviceFlowTest(t)
	ctx := context.Background()

	req := &oidc.DeviceAuthorizationRequest{
		ClientID: uuid.New().String(), // 不存在的 Client
		Scope:    "openid",
	}

	_, err := server.DeviceAuthorization(ctx, req)
	assert.ErrorIs(t, err, oidc.ErrInvalidClient)
}

func TestDeviceTokenExchange_Pending(t *testing.T) {
	server, storage, client := setupDeviceFlowTest(t)
	ctx := context.Background()

	// 1. 创建 Pending 状态的 Session
	deviceCode := "pending_code"
	session := &oidc.DeviceCodeSession{
		DeviceCode: deviceCode,
		UserCode:   "USER-CODE",
		ClientID:   client.GetID(),
		Scope:      "openid",
		Status:     oidc.DeviceCodeStatusPending,
		ExpiresAt:  time.Now().Add(10 * time.Minute),
	}
	err := storage.DeviceCodeSave(ctx, session)
	require.NoError(t, err)

	// 2. 尝试换取 Token
	req := &oidc.TokenRequest{
		GrantType:  oidc.GrantTypeDeviceCode,
		DeviceCode: deviceCode,
		ClientID:   client.GetID().String(),
	}

	_, err = server.Exchange(ctx, req)
	assert.ErrorIs(t, err, oidc.ErrAuthorizationPending)
}

func TestDeviceTokenExchange_Success(t *testing.T) {
	server, storage, client := setupDeviceFlowTest(t)
	ctx := context.Background()
	userID := oidc.BinaryUUID(uuid.New())

	// 1. 创建 Allowed 状态的 Session (模拟用户已在前端同意)
	deviceCode := "allowed_code"
	session := &oidc.DeviceCodeSession{
		DeviceCode:      deviceCode,
		UserCode:        "USER-CODE",
		ClientID:        client.GetID(),
		Scope:           "openid profile",
		AuthorizedScope: "openid profile", // 用户授权的 Scope
		Status:          oidc.DeviceCodeStatusAllowed,
		ExpiresAt:       time.Now().Add(10 * time.Minute),
		UserID:          userID, // 绑定用户
	}
	err := storage.DeviceCodeSave(ctx, session)
	require.NoError(t, err)

	// 2. 换取 Token
	req := &oidc.TokenRequest{
		GrantType:  oidc.GrantTypeDeviceCode,
		DeviceCode: deviceCode,
		ClientID:   client.GetID().String(),
	}

	resp, err := server.Exchange(ctx, req)
	require.NoError(t, err)

	// 3. 验证 Token
	assert.NotEmpty(t, resp.AccessToken)
	assert.NotEmpty(t, resp.IDToken) // scope 包含 openid

	// 解析 Token 验证 Subject
	claims, err := server.ParseAccessToken(ctx, resp.AccessToken)
	require.NoError(t, err)
	assert.Equal(t, userID.String(), claims.Subject)
}

func TestDeviceTokenExchange_Denied(t *testing.T) {
	server, storage, client := setupDeviceFlowTest(t)
	ctx := context.Background()

	// 1. 创建 Denied 状态的 Session
	deviceCode := "denied_code"
	session := &oidc.DeviceCodeSession{
		DeviceCode: deviceCode,
		ClientID:   client.GetID(),
		Status:     oidc.DeviceCodeStatusDenied,
		ExpiresAt:  time.Now().Add(10 * time.Minute),
	}
	storage.DeviceCodeSave(ctx, session)

	// 2. 尝试换取 Token
	req := &oidc.TokenRequest{
		GrantType:  oidc.GrantTypeDeviceCode,
		DeviceCode: deviceCode,
		ClientID:   client.GetID().String(),
	}

	_, err := server.Exchange(ctx, req)
	assert.ErrorIs(t, err, oidc.ErrAccessDenied)
}

func TestDeviceTokenExchange_Expired(t *testing.T) {
	server, storage, client := setupDeviceFlowTest(t)
	ctx := context.Background()

	// 1. 创建已过期的 Session
	deviceCode := "expired_code"
	session := &oidc.DeviceCodeSession{
		DeviceCode: deviceCode,
		ClientID:   client.GetID(),
		Status:     oidc.DeviceCodeStatusPending,
		ExpiresAt:  time.Now().Add(-1 * time.Minute),
	}
	storage.DeviceCodeSave(ctx, session)

	// 2. 尝试换取 Token
	req := &oidc.TokenRequest{
		GrantType:  oidc.GrantTypeDeviceCode,
		DeviceCode: deviceCode,
		ClientID:   client.GetID().String(),
	}

	_, err := server.Exchange(ctx, req)
	assert.ErrorIs(t, err, oidc.ErrInvalidGrant)
}

func TestDeviceTokenExchange_InvalidCode(t *testing.T) {
	server, _, client := setupDeviceFlowTest(t)
	ctx := context.Background()

	req := &oidc.TokenRequest{
		GrantType:  oidc.GrantTypeDeviceCode,
		DeviceCode: "invalid_code",
		ClientID:   client.GetID().String(),
	}

	_, err := server.Exchange(ctx, req)
	assert.ErrorIs(t, err, oidc.ErrInvalidGrant)
	assert.Contains(t, err.Error(), "invalid device_code")
}
