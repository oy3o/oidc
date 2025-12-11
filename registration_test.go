package oidc_test

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/oy3o/oidc"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// regTestHasher 是仅用于 Registration 测试的哈希器
// 模拟 Hash 操作添加前缀，Compare 操作去除前缀
type regTestHasher struct{}

func (h *regTestHasher) Hash(ctx context.Context, password []byte) ([]byte, error) {
	return []byte("hashed_" + string(password)), nil
}

func (h *regTestHasher) Compare(ctx context.Context, hashedPassword []byte, password []byte) error {
	// 在 Registration 流程中主要用到 Hash，Compare 较少用到
	if string(hashedPassword) == "hashed_"+string(password) {
		return nil
	}
	return oidc.ErrInvalidGrant
}

func TestRegisterClient_Confidential(t *testing.T) {
	storage, _ := NewTestStorage(t)
	hasher := &regTestHasher{}
	ctx := context.Background()

	req := &oidc.ClientRegistrationRequest{
		ClientName:              "My App",
		RedirectURIs:            []string{"https://client.example.com/cb"},
		GrantTypes:              []string{"authorization_code", "refresh_token"},
		ResponseTypes:           []string{"code"},
		Scope:                   "openid profile",
		TokenEndpointAuthMethod: "client_secret_basic", // 机密客户端
	}

	// 1. 注册
	resp, err := oidc.RegisterClient(ctx, storage, hasher, req)
	require.NoError(t, err)

	// 2. 验证响应
	assert.NotEmpty(t, resp.ClientID)
	assert.NotEmpty(t, resp.ClientSecret, "Confidential client must return a secret")
	assert.Equal(t, req.ClientName, resp.ClientName)
	assert.Equal(t, req.TokenEndpointAuthMethod, resp.TokenEndpointAuthMethod)

	// 3. 验证存储 (Secret 应该是哈希过的)
	storedClient, err := storage.ClientFindByID(ctx, oidc.BinaryUUID(uuid.MustParse(resp.ClientID)))
	require.NoError(t, err)

	// MockStorage 存储的是 RegisteredClient 接口，我们需要断言具体的实现或行为
	// 这里我们通过 ValidateSecret 来间接验证
	// resp.ClientSecret 是明文，存储的是哈希
	err = storedClient.ValidateSecret(ctx, hasher, resp.ClientSecret)
	assert.NoError(t, err, "Stored hashed secret should match returned plain secret")

	// 直接检查 MockStorage 内部数据 (如果需要白盒测试)
	mockClient := storedClient.(*oidc.ClientMetadata)
	assert.Equal(t, "hashed_"+resp.ClientSecret, string(mockClient.Secret))
}

func TestRegisterClient_Public(t *testing.T) {
	storage, _ := NewTestStorage(t)
	hasher := &regTestHasher{}
	ctx := context.Background()

	req := &oidc.ClientRegistrationRequest{
		ClientName:              "My SPA",
		RedirectURIs:            []string{"http://localhost:3000/cb"},
		TokenEndpointAuthMethod: "none", // 公共客户端
	}

	// 1. 注册
	resp, err := oidc.RegisterClient(ctx, storage, hasher, req)
	require.NoError(t, err)

	// 2. 验证响应
	assert.NotEmpty(t, resp.ClientID)
	assert.Empty(t, resp.ClientSecret, "Public client should not have a secret")

	// 3. 验证存储
	storedClient, err := storage.ClientFindByID(ctx, oidc.BinaryUUID(uuid.MustParse(resp.ClientID)))
	require.NoError(t, err)
	assert.False(t, storedClient.IsConfidential())
}

func TestRegisterClient_ValidationFailures(t *testing.T) {
	storage, _ := NewTestStorage(t)
	hasher := &regTestHasher{}
	ctx := context.Background()

	tests := []struct {
		name      string
		req       *oidc.ClientRegistrationRequest
		wantError string
	}{
		{
			name: "Missing Name",
			req: &oidc.ClientRegistrationRequest{
				RedirectURIs: []string{"https://valid.com"},
			},
			wantError: "client_name is required",
		},
		{
			name: "Missing Redirect URIs",
			req: &oidc.ClientRegistrationRequest{
				ClientName: "Test App",
			},
			wantError: "redirect_uri is required",
		},
		{
			name: "Invalid Redirect URI (HTTP non-local)",
			req: &oidc.ClientRegistrationRequest{
				ClientName:   "Test App",
				RedirectURIs: []string{"http://example.com/cb"},
			},
			wantError: "http scheme only allowed for localhost",
		},
		{
			name: "Invalid Redirect URI (Fragment)",
			req: &oidc.ClientRegistrationRequest{
				ClientName:   "Test App",
				RedirectURIs: []string{"https://example.com/cb#fragment"},
			},
			wantError: "must not contain fragment",
		},
		{
			name: "Invalid Redirect URI (Dangerous Scheme)",
			req: &oidc.ClientRegistrationRequest{
				ClientName:   "Test App",
				RedirectURIs: []string{"javascript:alert(1)"},
			},
			wantError: "invalid redirect_uri scheme",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := oidc.RegisterClient(ctx, storage, hasher, tt.req)
			assert.Error(t, err)
			if err != nil {
				assert.Contains(t, err.Error(), tt.wantError)
			}
		})
	}
}

func TestClientUpdate_Success(t *testing.T) {
	storage, _ := NewTestStorage(t)
	hasher := &regTestHasher{}
	ctx := context.Background()

	// 1. 先注册一个客户端
	createReq := &oidc.ClientRegistrationRequest{
		ClientName:              "Original Name",
		RedirectURIs:            []string{"https://old.com"},
		TokenEndpointAuthMethod: "client_secret_basic",
	}
	createResp, _ := oidc.RegisterClient(ctx, storage, hasher, createReq)
	clientID := createResp.ClientID
	originalSecret := createResp.ClientSecret

	// 2. 更新请求
	updateReq := &oidc.ClientRegistrationRequest{
		ClientName:              "New Name",
		RedirectURIs:            []string{"https://new.com"},
		TokenEndpointAuthMethod: "client_secret_basic",
		Scope:                   "new_scope",
	}

	// 3. 执行更新
	updateResp, err := oidc.ClientUpdate(ctx, storage, &oidc.ClientUpdateRequest{clientID, updateReq})
	require.NoError(t, err)

	// 4. 验证响应
	assert.Equal(t, clientID, updateResp.ClientID)
	assert.Equal(t, "New Name", updateResp.ClientName)
	assert.Equal(t, []string{"https://new.com"}, updateResp.RedirectURIs)

	// 5. 验证存储中的 Secret 未改变 (Update 不应重置 Secret)
	storedClient, _ := storage.ClientFindByID(ctx, oidc.BinaryUUID(uuid.MustParse(clientID)))
	err = storedClient.ValidateSecret(ctx, hasher, originalSecret)
	assert.NoError(t, err, "Secret should persist after update")
}

func TestClientUpdate_NotFound(t *testing.T) {
	storage, _ := NewTestStorage(t)
	ctx := context.Background()
	randomID := uuid.New().String()

	req := &oidc.ClientRegistrationRequest{
		ClientName:   "New Name",
		RedirectURIs: []string{"https://new.com"},
	}

	_, err := oidc.ClientUpdate(ctx, storage, &oidc.ClientUpdateRequest{randomID, req})
	assert.ErrorIs(t, err, oidc.ErrClientNotFound)
}

func TestUnregisterClient(t *testing.T) {
	storage, _ := NewTestStorage(t)
	hasher := &regTestHasher{}
	ctx := context.Background()

	// 1. 注册
	req := &oidc.ClientRegistrationRequest{
		ClientName:   "To JWKDelete",
		RedirectURIs: []string{"https://delete.com"},
	}
	resp, _ := oidc.RegisterClient(ctx, storage, hasher, req)
	clientID := resp.ClientID

	// 2. 验证存在
	_, err := storage.ClientFindByID(ctx, oidc.BinaryUUID(uuid.MustParse(clientID)))
	require.NoError(t, err)

	// 3. 注销
	err = oidc.UnregisterClient(ctx, storage, clientID)
	require.NoError(t, err)

	// 4. 验证不存在
	_, err = storage.ClientFindByID(ctx, oidc.BinaryUUID(uuid.MustParse(clientID)))
	assert.ErrorIs(t, err, oidc.ErrClientNotFound)
}

func TestValidateRegistrationRequest_RedirectURISchemes(t *testing.T) {
	tests := []struct {
		uri   string
		valid bool
	}{
		{"https://example.com/cb", true},
		{"http://localhost:8080/cb", true},
		{"http://127.0.0.1/cb", true},
		{"http://example.com/cb", false}, // HTTP 仅允许 localhost
		{"custom.scheme:/cb", false},
		{"com.app:/cb", true},
		{"javascript:alert(1)", false},
		{"data:text/html,bad", false},
		{"file:///etc/passwd", false},
		{"vbscript:exec", false},
		{"https://example.com/cb#fragment", false},
		{"/relative/path", false},
	}

	for _, tt := range tests {
		req := &oidc.ClientRegistrationRequest{
			ClientName:   "Test",
			RedirectURIs: []string{tt.uri},
		}
		err := oidc.ValidateRegistrationRequest(req, map[string]struct{}{
			"com.app": {},
		})
		if tt.valid {
			assert.NoError(t, err, "URI should be valid: %s", tt.uri)
		} else {
			assert.Error(t, err, "URI should be invalid: %s", tt.uri)
		}
	}
}
