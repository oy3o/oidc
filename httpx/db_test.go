package httpx_test

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/oy3o/o11y"
	"github.com/oy3o/oidc"
	"github.com/stretchr/testify/require"
)

func TestMain(m *testing.M) {
	cfg := o11y.Config{
		Enabled:     true,
		Service:     "oidc-httpx-test",
		Environment: "test",
		Log: o11y.LogConfig{
			Level:         "fatal",
			EnableConsole: false,
		},
		Trace:  o11y.TraceConfig{Enabled: false, Exporter: "none"},
		Metric: o11y.MetricConfig{Enabled: false},
	}
	shutdown, _ := o11y.Init(cfg)
	defer shutdown(context.Background())

	m.Run()
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

// mockStorage 是一个为了 HTTPX 测试准备的纯内存实现，不用起容器。
type mockStorage struct {
	oidc.Storage // 注意：未实现的方法会直接 panic
	
	mu             sync.Mutex
	clients        map[oidc.BinaryUUID]*oidc.ClientMetadata
	jwks           map[string]jwk.Key
	signingKeyID   string
	users          map[string]*oidc.UserInfo
	authCodes      map[string]*oidc.AuthCodeSession
	refreshTokens  map[string]*oidc.RefreshTokenSession
	revokedTokens  map[string]time.Time
	replayCache    map[string]time.Time
	parSessions    map[string]*oidc.AuthorizeRequest
	deviceSessions map[string]*oidc.DeviceCodeSession
}

func newMockStorage() *mockStorage {
	return &mockStorage{
		clients:        make(map[oidc.BinaryUUID]*oidc.ClientMetadata),
		jwks:           make(map[string]jwk.Key),
		users:          make(map[string]*oidc.UserInfo),
		authCodes:      make(map[string]*oidc.AuthCodeSession),
		refreshTokens:  make(map[string]*oidc.RefreshTokenSession),
		revokedTokens:  make(map[string]time.Time),
		replayCache:    make(map[string]time.Time),
		parSessions:    make(map[string]*oidc.AuthorizeRequest),
		deviceSessions: make(map[string]*oidc.DeviceCodeSession),
	}
}

func (m *mockStorage) ClientCreate(ctx context.Context, metadata *oidc.ClientMetadata) (oidc.RegisteredClient, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.clients[metadata.ID] = metadata
	return metadata, nil
}

func (m *mockStorage) ClientGetByID(ctx context.Context, clientID oidc.BinaryUUID) (oidc.RegisteredClient, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if c, ok := m.clients[clientID]; ok {
		return c, nil
	}
	return nil, oidc.ErrClientNotFound
}

func (m *mockStorage) JWKSave(ctx context.Context, key jwk.Key) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.jwks[key.KeyID()] = key
	return nil
}

func (m *mockStorage) JWKMarkSigning(ctx context.Context, kid string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.signingKeyID = kid
	return nil
}

func (m *mockStorage) JWKGetSigning(ctx context.Context) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.signingKeyID == "" {
		return "", errors.New("no signing key marked")
	}
	return m.signingKeyID, nil
}

func (m *mockStorage) JWKGet(ctx context.Context, kid string) (jwk.Key, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if k, ok := m.jwks[kid]; ok {
		return k, nil
	}
	return nil, errors.New("key not found")
}

func (m *mockStorage) JWKList(ctx context.Context) ([]jwk.Key, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var keys []jwk.Key
	for _, k := range m.jwks {
		keys = append(keys, k)
	}
	return keys, nil
}

func (m *mockStorage) UserCreateInfo(ctx context.Context, userInfo *oidc.UserInfo) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.users[userInfo.Subject] = userInfo
	return nil
}

func (m *mockStorage) UserGetInfoByID(ctx context.Context, userID oidc.BinaryUUID, scopes []string) (*oidc.UserInfo, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if u, ok := m.users[userID.String()]; ok {
		return u, nil
	}
	return nil, errors.New("user not found")
}

func (m *mockStorage) AuthCodeSave(ctx context.Context, session *oidc.AuthCodeSession) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.authCodes[session.Code] = session
	return nil
}

func (m *mockStorage) AuthCodeConsume(ctx context.Context, code string) (*oidc.AuthCodeSession, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if session, ok := m.authCodes[code]; ok {
		delete(m.authCodes, code)
		return session, nil
	}
	return nil, oidc.ErrCodeNotFound
}

func (m *mockStorage) RefreshTokenCreate(ctx context.Context, session *oidc.RefreshTokenSession) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.refreshTokens[string(session.ID)] = session
	return nil
}

func (m *mockStorage) RefreshTokenGet(ctx context.Context, tokenID oidc.Hash256) (*oidc.RefreshTokenSession, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if s, ok := m.refreshTokens[string(tokenID)]; ok {
		return s, nil
	}
	return nil, oidc.ErrTokenNotFound
}

func (m *mockStorage) RefreshTokenRotate(ctx context.Context, oldTokenID oidc.Hash256, newSession *oidc.RefreshTokenSession, gracePeriod time.Duration) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.refreshTokens, string(oldTokenID))
	m.refreshTokens[string(newSession.ID)] = newSession
	return nil
}

func (m *mockStorage) AccessTokenIsRevoked(ctx context.Context, jti string) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	exp, ok := m.revokedTokens[jti]
	if !ok || time.Now().After(exp) {
		return false, nil
	}
	return true, nil
}

func (m *mockStorage) AccessTokenRevoke(ctx context.Context, jti string, expiration time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.revokedTokens[jti] = expiration
	return nil
}

func (m *mockStorage) CheckAndStore(ctx context.Context, jti string, ttl time.Duration) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	exp, ok := m.replayCache[jti]
	if ok && time.Now().Before(exp) {
		return true, nil
	}
	m.replayCache[jti] = time.Now().Add(ttl)
	return false, nil
}

func (m *mockStorage) PARSessionSave(ctx context.Context, requestURI string, req *oidc.AuthorizeRequest, ttl time.Duration) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.parSessions[requestURI] = req
	return nil
}

func (m *mockStorage) PARSessionConsume(ctx context.Context, requestURI string) (*oidc.AuthorizeRequest, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if s, ok := m.parSessions[requestURI]; ok {
		delete(m.parSessions, requestURI)
		return s, nil
	}
	return nil, errors.New("PAR session not found")
}

func (m *mockStorage) DeviceCodeSave(ctx context.Context, session *oidc.DeviceCodeSession) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.deviceSessions[session.DeviceCode] = session
	return nil
}

// setupServer 创建一个完全配置的 OIDC Server 用于测试
func setupServer(t *testing.T) (*oidc.Server, oidc.Storage, oidc.RegisteredClient) {
	storage := newMockStorage()
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
	clientMeta := &oidc.ClientMetadata{
		ID:                      clientID,
		RedirectURIs:            oidc.StringSlice{"https://client.com/cb"},
		GrantTypes:              oidc.StringSlice{"authorization_code", "client_credentials"},
		Scope:                   "openid profile",
		Name:                    "HTTPX Test Client",
		IsConfidentialClient:    true,
		Secret:                  "hashed_test_secret",
		TokenEndpointAuthMethod: "client_secret_basic",
	}

	client, err := storage.ClientCreate(context.Background(), clientMeta)
	require.NoError(t, err)

	return server, storage, client
}
