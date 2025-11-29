package oidc_test

import (
	"context"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/oy3o/oidc"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// setupPARTest 初始化 PAR 测试环境
func setupPARTest(t *testing.T) (oidc.Storage, oidc.RegisteredClient, oidc.Hasher) {
	storage := NewTestStorage(t)
	hasher := &mockHasher{} // 假设 mockHasher 已在 authorize_test.go 中定义，同一包下可见

	// 创建一个机密客户端
	clientID := oidc.BinaryUUID(uuid.New())
	clientMeta := oidc.ClientMetadata{
		ID:           clientID,
		RedirectURIs: []string{"https://client.example.com/cb"},
		GrantTypes:   []string{"authorization_code"},
		Scope:        "openid profile",
		Name:         "PAR Test Client",
		// 必须是机密客户端才能使用 PAR (通常要求身份验证)
		IsConfidential:          true,
		Secret:                  "test_secret",
		TokenEndpointAuthMethod: "client_secret_basic",
	}

	client, err := storage.CreateClient(context.Background(), clientMeta)
	require.NoError(t, err)

	return storage, client, hasher
}

func TestPushedAuthorization_Success(t *testing.T) {
	storage, client, hasher := setupPARTest(t)
	ctx := context.Background()

	req := &oidc.PARRequest{
		ClientID:            client.GetID().String(),
		ClientSecret:        "test_secret",
		RedirectURI:         "https://client.example.com/cb",
		ResponseType:        "code",
		Scope:               "openid profile",
		State:               "xyz",
		Nonce:               "nonce123",
		CodeChallenge:       "challenge",
		CodeChallengeMethod: "S256",
	}

	// 1. 推送请求
	resp, err := oidc.PushedAuthorization(ctx, storage, hasher, req)
	require.NoError(t, err)

	// 2. 验证响应
	assert.NotEmpty(t, resp.RequestURI)
	assert.True(t, strings.HasPrefix(resp.RequestURI, "urn:ietf:params:oauth:request_uri:"))
	assert.Equal(t, 60, resp.ExpiresIn) // 默认 TTL

	// 3. 验证存储
	// 通过直接查询 mock storage 验证
	// 也可以通过 LoadPARSession 验证（见 TestLoadPARSession_Lifecycle）
	_, err = oidc.LoadPARSession(ctx, storage, resp.RequestURI)
	require.NoError(t, err)
}

func TestPushedAuthorization_ClientAuthFailed(t *testing.T) {
	storage, client, hasher := setupPARTest(t)
	ctx := context.Background()

	req := &oidc.PARRequest{
		ClientID:     client.GetID().String(),
		ClientSecret: "wrong_secret", // 错误密钥
		RedirectURI:  "https://client.example.com/cb",
		ResponseType: "code",
	}

	_, err := oidc.PushedAuthorization(ctx, storage, hasher, req)
	assert.ErrorIs(t, err, oidc.ErrUnauthorizedClient)
}

func TestPushedAuthorization_InvalidParams(t *testing.T) {
	storage, client, hasher := setupPARTest(t)
	ctx := context.Background()

	// 1. Redirect URI 不匹配
	req1 := &oidc.PARRequest{
		ClientID:     client.GetID().String(),
		ClientSecret: "test_secret",
		RedirectURI:  "https://attacker.com",
		ResponseType: "code",
	}
	_, err := oidc.PushedAuthorization(ctx, storage, hasher, req1)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "mismatch redirect_uri")

	// 2. 缺少必要参数 (Code Challenge)
	// 假设 RequestAuthorize 强制检查 PKCE
	req2 := &oidc.PARRequest{
		ClientID:     client.GetID().String(),
		ClientSecret: "test_secret",
		RedirectURI:  "https://client.example.com/cb",
		ResponseType: "code",
		Scope:        "openid",
		Nonce:        "n",
		// CodeChallenge: "", // Missing
	}
	_, err = oidc.PushedAuthorization(ctx, storage, hasher, req2)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "code_challenge is required")
}

func TestPushedAuthorization_PayloadTooLarge(t *testing.T) {
	storage, client, hasher := setupPARTest(t)
	ctx := context.Background()

	// 构造超大 Payload (> 100KB)
	hugeState := strings.Repeat("a", 101*1024)

	req := &oidc.PARRequest{
		ClientID:            client.GetID().String(),
		ClientSecret:        "test_secret",
		RedirectURI:         "https://client.example.com/cb",
		ResponseType:        "code",
		State:               hugeState,
		CodeChallenge:       "challenge",
		CodeChallengeMethod: "S256",
	}

	_, err := oidc.PushedAuthorization(ctx, storage, hasher, req)
	assert.ErrorIs(t, err, oidc.ErrInvalidRequest)
	assert.Contains(t, err.Error(), "payload too large")
}

func TestLoadPARSession_Lifecycle(t *testing.T) {
	storage, client, hasher := setupPARTest(t)
	ctx := context.Background()

	// 1. 创建 PAR
	parReq := &oidc.PARRequest{
		ClientID:            client.GetID().String(),
		ClientSecret:        "test_secret",
		RedirectURI:         "https://client.example.com/cb",
		ResponseType:        "code",
		Scope:               "openid",
		State:               "state-123",
		Nonce:               "nonce-123",
		CodeChallenge:       "challenge",
		CodeChallengeMethod: "S256",
	}
	resp, err := oidc.PushedAuthorization(ctx, storage, hasher, parReq)
	require.NoError(t, err)
	requestURI := resp.RequestURI

	// 2. 第一次加载 (Consume) - 应该成功
	authReq, err := oidc.LoadPARSession(ctx, storage, requestURI)
	require.NoError(t, err)
	assert.Equal(t, client.GetID().String(), authReq.ClientID)
	assert.Equal(t, "state-123", authReq.State)
	assert.Equal(t, "nonce-123", authReq.Nonce)

	// 3. 第二次加载 (Replay) - 应该失败 (One-time use)
	_, err = oidc.LoadPARSession(ctx, storage, requestURI)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not found or expired")
}

func TestLoadPARSession_Invalid(t *testing.T) {
	storage, _, _ := setupPARTest(t)
	ctx := context.Background()

	// 1. 格式错误
	_, err := oidc.LoadPARSession(ctx, storage, "not-a-valid-urn")
	assert.ErrorIs(t, err, oidc.ErrInvalidRequest)
	assert.Contains(t, err.Error(), "invalid request_uri format")

	// 2. 不存在
	_, err = oidc.LoadPARSession(ctx, storage, "urn:ietf:params:oauth:request_uri:non-existent")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

func TestPAR_Concurrency_OneTimeUse(t *testing.T) {
	storage := NewTestStorage(t)
	ctx := context.Background()

	// 1. 创建一个 PAR Session
	requestURI := "urn:ietf:params:oauth:request_uri:concurrent-test"
	req := &oidc.AuthorizeRequest{ClientID: "client-1", State: "state-1"}
	err := storage.SavePARSession(ctx, requestURI, req, time.Minute)
	require.NoError(t, err)

	// 2. 并发尝试获取并删除
	const concurrency = 50
	var successCount atomic.Int32
	var wg sync.WaitGroup
	wg.Add(concurrency)

	for i := 0; i < concurrency; i++ {
		go func() {
			defer wg.Done()
			// 调用原子操作 LoadPARSession (内部调用 GetAndDelete)
			if _, err := oidc.LoadPARSession(ctx, storage, requestURI); err == nil {
				successCount.Add(1)
			}
		}()
	}

	wg.Wait()

	// 3. 验证：只能有一次成功
	assert.Equal(t, int32(1), successCount.Load(), "PAR request_uri MUST be usable only once")
}

func TestLoadPARSession_Expired(t *testing.T) {
	storage := NewTestStorage(t)
	ctx := context.Background()

	requestURI := "urn:ietf:params:oauth:request_uri:expired"
	req := &oidc.AuthorizeRequest{ClientID: "client-1"}

	err := storage.SavePARSession(ctx, requestURI, req, 10*time.Millisecond)
	require.NoError(t, err)
	time.Sleep(100 * time.Millisecond)
	_, err = oidc.LoadPARSession(ctx, storage, requestURI)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "expired")
}
