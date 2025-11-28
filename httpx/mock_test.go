package httpx_test

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/oy3o/oidc"
)

// mockStorage 是用于 httpx 测试的内存存储
// 它完整实现了 oidc.Storage 接口
type mockStorage struct {
	mu sync.RWMutex

	clients       map[string]*mockClient
	refreshTokens map[string]*oidc.RefreshTokenSession
	keys          map[string]jwk.Key
	signingKeyID  string
	revokedJTIs   map[string]time.Time
}

func newMockStorage() *mockStorage {
	return &mockStorage{
		clients:       make(map[string]*mockClient),
		refreshTokens: make(map[string]*oidc.RefreshTokenSession),
		keys:          make(map[string]jwk.Key),
		revokedJTIs:   make(map[string]time.Time),
	}
}

// --- ClientStorage ---

type mockClient struct {
	ID           oidc.BinaryUUID
	RedirectURIs []string
	GrantTypes   []string
	Scope        string
	Secret       string
	Confidential bool
}

func (m *mockClient) GetID() oidc.BinaryUUID    { return m.ID }
func (m *mockClient) GetRedirectURIs() []string { return m.RedirectURIs }
func (m *mockClient) GetGrantTypes() []string   { return m.GrantTypes }
func (m *mockClient) GetScope() string          { return m.Scope }
func (m *mockClient) IsConfidential() bool      { return m.Confidential }
func (m *mockClient) ValidateSecret(ctx context.Context, hasher oidc.Hasher, secret string) error {
	if !m.IsConfidential() {
		return nil
	}
	return hasher.Compare(ctx, []byte(m.Secret), []byte(secret))
}

func (m *mockStorage) GetClient(ctx context.Context, clientID oidc.BinaryUUID) (oidc.RegisteredClient, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if c, ok := m.clients[clientID.String()]; ok {
		return c, nil
	}
	return nil, oidc.ErrClientNotFound
}

func (m *mockStorage) CreateClient(ctx context.Context, metadata oidc.ClientMetadata) (oidc.RegisteredClient, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	c := &mockClient{
		ID:           metadata.ID,
		RedirectURIs: metadata.RedirectURIs,
		GrantTypes:   metadata.GrantTypes,
		Scope:        metadata.Scope,
		Secret:       string(metadata.Secret),
		Confidential: metadata.IsConfidential,
	}
	m.clients[metadata.ID.String()] = c
	return c, nil
}

// 存根实现其他 ClientStorage 方法
func (m *mockStorage) UpdateClient(ctx context.Context, clientID oidc.BinaryUUID, metadata oidc.ClientMetadata) (oidc.RegisteredClient, error) {
	return nil, nil
}
func (m *mockStorage) DeleteClient(ctx context.Context, clientID oidc.BinaryUUID) error { return nil }
func (m *mockStorage) ListClientsByOwner(ctx context.Context, ownerID oidc.BinaryUUID) ([]oidc.RegisteredClient, error) {
	return nil, nil
}

func (m *mockStorage) ListClients(ctx context.Context, query oidc.ListQuery) ([]oidc.RegisteredClient, error) {
	return nil, nil
}

// --- TokenStorage ---

func (m *mockStorage) CreateRefreshToken(ctx context.Context, session *oidc.RefreshTokenSession) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.refreshTokens[session.ID.String()] = session
	return nil
}

func (m *mockStorage) GetRefreshToken(ctx context.Context, tokenID oidc.Hash256) (*oidc.RefreshTokenSession, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if s, ok := m.refreshTokens[tokenID.String()]; ok {
		return s, nil
	}
	return nil, oidc.ErrTokenNotFound
}

func (m *mockStorage) RotateRefreshToken(ctx context.Context, oldID oidc.Hash256, newSession *oidc.RefreshTokenSession) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.refreshTokens, oldID.String())
	m.refreshTokens[newSession.ID.String()] = newSession
	return nil
}

func (m *mockStorage) RevokeRefreshToken(ctx context.Context, tokenID oidc.Hash256) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.refreshTokens, tokenID.String())
	return nil
}

func (m *mockStorage) RevokeTokensForUser(ctx context.Context, userID oidc.BinaryUUID) error {
	return nil
}

// --- KeyStorage ---

func (m *mockStorage) Save(ctx context.Context, key jwk.Key) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.keys[key.KeyID()] = key
	return nil
}

func (m *mockStorage) Get(ctx context.Context, kid string) (jwk.Key, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if k, ok := m.keys[kid]; ok {
		return k, nil
	}
	return nil, oidc.ErrKeyNotFound
}

func (m *mockStorage) List(ctx context.Context) ([]jwk.Key, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var keys []jwk.Key
	for _, k := range m.keys {
		keys = append(keys, k)
	}
	return keys, nil
}

func (m *mockStorage) Delete(ctx context.Context, kid string) error { return nil }

func (m *mockStorage) SaveSigningKeyID(ctx context.Context, kid string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.signingKeyID = kid
	return nil
}

func (m *mockStorage) GetSigningKeyID(ctx context.Context) (string, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.signingKeyID, nil
}

// --- RevocationStorage ---

func (m *mockStorage) Revoke(ctx context.Context, jti string, expiration time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.revokedJTIs[jti] = expiration
	return nil
}

func (m *mockStorage) IsRevoked(ctx context.Context, jti string) (bool, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	_, ok := m.revokedJTIs[jti]
	return ok, nil
}

// --- UserInfoGetter ---

func (m *mockStorage) GetUserInfo(ctx context.Context, userID oidc.BinaryUUID, scopes []string) (*oidc.UserInfo, error) {
	name := "Test User"
	return &oidc.UserInfo{
		Subject: userID.String(),
		Name:    &name,
	}, nil
}

// --- Other Interfaces (Stubs) ---

func (m *mockStorage) Cleanup(ctx context.Context) (int64, error) { return 0, nil }

func (m *mockStorage) GetUser(ctx context.Context, u, p string) (oidc.BinaryUUID, error) {
	return oidc.BinaryUUID{}, errors.New("not implemented")
}
func (m *mockStorage) SaveAuthCode(ctx context.Context, s *oidc.AuthCodeSession) error { return nil }
func (m *mockStorage) LoadAndConsumeAuthCode(ctx context.Context, code string) (*oidc.AuthCodeSession, error) {
	return nil, errors.New("not implemented")
}

func (m *mockStorage) SaveDeviceCode(ctx context.Context, s *oidc.DeviceCodeSession) error {
	return nil
}

func (m *mockStorage) GetDeviceCodeSession(ctx context.Context, c string) (*oidc.DeviceCodeSession, error) {
	return nil, errors.New("not implemented")
}

func (m *mockStorage) GetDeviceCodeSessionByUserCode(ctx context.Context, c string) (*oidc.DeviceCodeSession, error) {
	return nil, errors.New("not implemented")
}

func (m *mockStorage) UpdateDeviceCodeSession(ctx context.Context, c string, s *oidc.DeviceCodeSession) error {
	return nil
}

func (m *mockStorage) Lock(ctx context.Context, k string, t time.Duration) (bool, error) {
	return true, nil
}
func (m *mockStorage) Unlock(ctx context.Context, k string) error { return nil }
func (m *mockStorage) SavePARSession(ctx context.Context, u string, r *oidc.AuthorizeRequest, t time.Duration) error {
	return nil
}

func (m *mockStorage) GetAndDeletePARSession(ctx context.Context, u string) (*oidc.AuthorizeRequest, error) {
	return nil, nil
}

func (m *mockStorage) CheckAndStore(ctx context.Context, j string, t time.Duration) (bool, error) {
	return false, nil
}

func (m *mockStorage) MarkRefreshTokenAsRotating(ctx context.Context, t oidc.Hash256, d time.Duration) error {
	return nil
}

func (m *mockStorage) IsInGracePeriod(ctx context.Context, t oidc.Hash256) (bool, error) {
	return false, nil
}

func (m *mockStorage) SaveClient(ctx context.Context, c oidc.RegisteredClient, t time.Duration) error {
	return nil
}
func (m *mockStorage) InvalidateClient(ctx context.Context, id oidc.BinaryUUID) error { return nil }
func (m *mockStorage) SaveRefreshToken(ctx context.Context, s *oidc.RefreshTokenSession, t time.Duration) error {
	return nil
}

func (m *mockStorage) InvalidateRefreshToken(ctx context.Context, id oidc.Hash256) error {
	return nil
}
