package oidc

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwk"
)

// MockStorage 是用于测试的内存存储实现
type MockStorage struct {
	mu sync.RWMutex

	// Client storage
	clients map[string]*MockClient

	// Auth code storage
	authCodes map[string]*AuthCodeSession

	// Token storage
	refreshTokens map[string]*RefreshTokenSession
	revokedJTIs   map[string]time.Time

	// Device flow storage
	deviceCodes      map[string]*DeviceCodeSession
	userCodeToDevice map[string]string

	// DPoP replay cache
	dpopJTIs map[string]time.Time

	// PAR storage
	parSessions map[string]*parSession

	// Key storage
	keys         map[string]jwk.Key
	signingKeyID string

	// Distributed lock
	locks map[string]*lockEntry
}

type parSession struct {
	req       *AuthorizeRequest
	expiresAt time.Time
}

type lockEntry struct {
	expiresAt time.Time
}

// MockClient 实现 RegisteredClient 接口
type MockClient struct {
	ID           BinaryUUID
	RedirectURIs []string
	GrantTypes   []string
	Scope        string
	Secret       string
	Confidential bool
}

func (m *MockClient) GetID() BinaryUUID         { return m.ID }
func (m *MockClient) GetRedirectURIs() []string { return m.RedirectURIs }
func (m *MockClient) GetGrantTypes() []string   { return m.GrantTypes }
func (m *MockClient) GetScope() string          { return m.Scope }
func (m *MockClient) IsConfidential() bool      { return m.Confidential }
func (m *MockClient) ValidateSecret(ctx context.Context, hasher Hasher, secret string) error {
	// 如果是 Public Client，无需验证
	if !m.IsConfidential() {
		return nil
	}
	if hasher == nil {
		return errors.New("hasher not configured in storage")
	}
	return hasher.Compare(ctx, []byte(m.Secret), []byte(secret))
}

func NewMockStorage() *MockStorage {
	return &MockStorage{
		clients:          make(map[string]*MockClient),
		authCodes:        make(map[string]*AuthCodeSession),
		refreshTokens:    make(map[string]*RefreshTokenSession),
		revokedJTIs:      make(map[string]time.Time),
		deviceCodes:      make(map[string]*DeviceCodeSession),
		userCodeToDevice: make(map[string]string),
		dpopJTIs:         make(map[string]time.Time),
		parSessions:      make(map[string]*parSession),
		keys:             make(map[string]jwk.Key),
		locks:            make(map[string]*lockEntry),
	}
}

// Cleanup implements the Persistence.Cleanup interface for tests.
// Since this is a mock, it does nothing and returns successfully.
func (m *MockStorage) Cleanup(ctx context.Context) (int64, error) {
	// For tests, we don't need actual cleanup logic
	// Tests can verify GC worker behavior with real storage implementations
	return 0, nil
}

// ClientStorage 实现

func (m *MockStorage) GetClient(ctx context.Context, clientID BinaryUUID) (RegisteredClient, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	client, ok := m.clients[clientID.String()]
	if !ok {
		return nil, ErrClientNotFound
	}
	return client, nil
}

func (m *MockStorage) CreateClient(ctx context.Context, metadata ClientMetadata) (RegisteredClient, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	client := &MockClient{
		ID:           metadata.ID,
		RedirectURIs: metadata.RedirectURIs,
		GrantTypes:   metadata.GrantTypes,
		Scope:        metadata.Scope,
		Secret:       string(metadata.Secret),
		Confidential: metadata.IsConfidential,
	}
	m.clients[metadata.ID.String()] = client
	return client, nil
}

func (m *MockStorage) UpdateClient(ctx context.Context, clientID BinaryUUID, metadata ClientMetadata) (RegisteredClient, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	client, ok := m.clients[clientID.String()]
	if !ok {
		return nil, ErrClientNotFound
	}

	client.RedirectURIs = metadata.RedirectURIs
	client.GrantTypes = metadata.GrantTypes
	client.Scope = metadata.Scope
	if metadata.Secret != "" {
		client.Secret = string(metadata.Secret)
	}
	client.Confidential = metadata.IsConfidential
	return client, nil
}

func (m *MockStorage) DeleteClient(ctx context.Context, clientID BinaryUUID) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	delete(m.clients, clientID.String())
	return nil
}

func (m *MockStorage) ListClientsByOwner(ctx context.Context, ownerID BinaryUUID) ([]RegisteredClient, error) {
	// Not implemented for tests
	return nil, errors.New("not implemented")
}

func (m *MockStorage) ListClients(ctx context.Context, query ListQuery) ([]RegisteredClient, error) {
	// Not implemented for tests
	return nil, errors.New("not implemented")
}

// AuthCodeStorage 实现

func (m *MockStorage) SaveAuthCode(ctx context.Context, session *AuthCodeSession) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.authCodes[session.Code] = session
	return nil
}

func (m *MockStorage) LoadAndConsumeAuthCode(ctx context.Context, code string) (*AuthCodeSession, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	session, ok := m.authCodes[code]
	if !ok {
		return nil, ErrCodeNotFound
	}

	if time.Now().After(session.ExpiresAt) {
		delete(m.authCodes, code)
		return nil, ErrCodeNotFound
	}

	delete(m.authCodes, code)
	return session, nil
}

// TokenStorage 实现

func (m *MockStorage) CreateRefreshToken(ctx context.Context, session *RefreshTokenSession) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.refreshTokens[session.ID.String()] = session
	return nil
}

func (m *MockStorage) GetRefreshToken(ctx context.Context, tokenID Hash256) (*RefreshTokenSession, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	session, ok := m.refreshTokens[tokenID.String()]
	if !ok {
		return nil, ErrTokenNotFound
	}

	if time.Now().After(session.ExpiresAt) {
		return nil, ErrTokenNotFound
	}

	return session, nil
}

func (m *MockStorage) RotateRefreshToken(ctx context.Context, oldTokenID Hash256, newSession *RefreshTokenSession) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	delete(m.refreshTokens, oldTokenID.String())
	m.refreshTokens[newSession.ID.String()] = newSession
	return nil
}

func (m *MockStorage) RevokeRefreshToken(ctx context.Context, tokenID Hash256) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	delete(m.refreshTokens, tokenID.String())
	return nil
}

func (m *MockStorage) RevokeTokensForUser(ctx context.Context, userID BinaryUUID) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	for id, session := range m.refreshTokens {
		if session.UserID == userID {
			delete(m.refreshTokens, id)
		}
	}
	return nil
}

func (m *MockStorage) MarkRefreshTokenAsRotating(ctx context.Context, tokenID Hash256, gracePeriod time.Duration) error {
	// Simplified: not implemented for tests
	return nil
}

func (m *MockStorage) IsInGracePeriod(ctx context.Context, tokenID Hash256) (bool, error) {
	return false, nil
}

// RevocationStorage 实现

func (m *MockStorage) Revoke(ctx context.Context, jti string, expiration time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.revokedJTIs[jti] = expiration
	return nil
}

func (m *MockStorage) IsRevoked(ctx context.Context, jti string) (bool, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	exp, ok := m.revokedJTIs[jti]
	if !ok {
		return false, nil
	}

	if time.Now().After(exp) {
		return false, nil
	}

	return true, nil
}

// DeviceCodeStorage 实现

func (m *MockStorage) SaveDeviceCode(ctx context.Context, session *DeviceCodeSession) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.deviceCodes[session.DeviceCode] = session
	m.userCodeToDevice[session.UserCode] = session.DeviceCode
	return nil
}

func (m *MockStorage) GetDeviceCodeSession(ctx context.Context, deviceCode string) (*DeviceCodeSession, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	session, ok := m.deviceCodes[deviceCode]
	if !ok {
		return nil, ErrTokenNotFound
	}
	return session, nil
}

func (m *MockStorage) GetDeviceCodeSessionByUserCode(ctx context.Context, userCode string) (*DeviceCodeSession, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	deviceCode, ok := m.userCodeToDevice[userCode]
	if !ok {
		return nil, ErrTokenNotFound
	}

	return m.GetDeviceCodeSession(ctx, deviceCode)
}

func (m *MockStorage) UpdateDeviceCodeSession(ctx context.Context, deviceCode string, session *DeviceCodeSession) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.deviceCodes[deviceCode] = session
	return nil
}

// UserInfoGetter 实现

func (m *MockStorage) GetUserInfo(ctx context.Context, userID BinaryUUID, scopes []string) (*UserInfo, error) {
	// 模拟一个全量的用户信息
	fullInfo := &UserInfo{
		Subject:           userID.String(),
		Name:              StringPtr("Test User"),
		Email:             StringPtr("test@example.com"),
		EmailVerified:     BoolPtr(true),
		PhoneNumber:       StringPtr("+1234567890"),
		PreferredUsername: StringPtr("tester"),
	}

	// 如果没有 scope 限制，返回空或者只有 sub (取决于业务逻辑，这里假设至少返回 sub)
	if len(scopes) == 0 {
		return &UserInfo{Subject: userID.String()}, nil
	}

	// 根据 Scope 过滤字段
	result := &UserInfo{Subject: userID.String()}

	// 简单的包含判断
	hasScope := func(s string) bool {
		for _, scope := range scopes {
			if scope == s {
				return true
			}
		}
		return false
	}

	if hasScope("profile") {
		result.Name = fullInfo.Name
		result.PreferredUsername = fullInfo.PreferredUsername
	}
	if hasScope("email") {
		result.Email = fullInfo.Email
		result.EmailVerified = fullInfo.EmailVerified
	}
	if hasScope("phone") {
		result.PhoneNumber = fullInfo.PhoneNumber
	}

	return result, nil
}

// 辅助函数
func StringPtr(s string) *string { return &s }
func BoolPtr(b bool) *bool       { return &b }

// UserAuthenticator 实现

func (m *MockStorage) GetUser(ctx context.Context, username, password string) (BinaryUUID, error) {
	// Simplified for tests
	return BinaryUUID{}, ErrUserNotFound
}

// ReplayCache 实现

func (m *MockStorage) CheckAndStore(ctx context.Context, jti string, ttl time.Duration) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.dpopJTIs[jti]; exists {
		return true, nil
	}

	m.dpopJTIs[jti] = time.Now().Add(ttl)
	return false, nil
}

// PARStorage 实现

func (m *MockStorage) SavePARSession(ctx context.Context, requestURI string, req *AuthorizeRequest, ttl time.Duration) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.parSessions[requestURI] = &parSession{
		req:       req,
		expiresAt: time.Now().Add(ttl),
	}
	return nil
}

func (m *MockStorage) GetAndDeletePARSession(ctx context.Context, requestURI string) (*AuthorizeRequest, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	session, ok := m.parSessions[requestURI]
	if !ok {
		return nil, errors.New("PAR session not found")
	}

	if time.Now().After(session.expiresAt) {
		delete(m.parSessions, requestURI)
		return nil, errors.New("PAR session expired")
	}

	delete(m.parSessions, requestURI)
	return session.req, nil
}

// KeyStorage 实现

func (m *MockStorage) Save(ctx context.Context, key jwk.Key) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if key.KeyID() == "" {
		return errors.New("key must have a kid")
	}

	m.keys[key.KeyID()] = key
	return nil
}

func (m *MockStorage) Get(ctx context.Context, kid string) (jwk.Key, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	key, ok := m.keys[kid]
	if !ok {
		return nil, ErrKeyNotFound
	}
	return key, nil
}

func (m *MockStorage) List(ctx context.Context) ([]jwk.Key, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	keys := make([]jwk.Key, 0, len(m.keys))
	for _, key := range m.keys {
		keys = append(keys, key)
	}
	return keys, nil
}

func (m *MockStorage) Delete(ctx context.Context, kid string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	delete(m.keys, kid)
	return nil
}

func (m *MockStorage) SaveSigningKeyID(ctx context.Context, kid string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.signingKeyID = kid
	return nil
}

func (m *MockStorage) GetSigningKeyID(ctx context.Context) (string, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.signingKeyID == "" {
		return "", ErrKeyNotFound
	}
	return m.signingKeyID, nil
}

// DistributedLock 实现

func (m *MockStorage) Lock(ctx context.Context, key string, ttl time.Duration) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	entry, exists := m.locks[key]
	if exists && time.Now().Before(entry.expiresAt) {
		return false, nil
	}

	m.locks[key] = &lockEntry{
		expiresAt: time.Now().Add(ttl),
	}
	return true, nil
}

func (m *MockStorage) Unlock(ctx context.Context, key string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	delete(m.locks, key)
	return nil
}

// ---------------------------------------------------------------------------
// ClientCache Implementation
// ---------------------------------------------------------------------------

func (m *MockStorage) SaveClient(ctx context.Context, client RegisteredClient, ttl time.Duration) error {
	// For mock, we can just save it to the map, ignoring TTL or storing it if we want to test expiration.
	// Since MockStorage is often used as Persistence, saving here might overwrite persistence data if we share the map.
	// But for tests, this is usually fine or desired.
	// However, `client` is an interface. We need to cast it to *MockClient to store it in `m.clients`.
	// Or we should update `m.clients` to hold `RegisteredClient` interface?
	// `m.clients` is `map[string]*MockClient`.
	// If we change `m.clients` to `map[string]RegisteredClient`, it would be more flexible.
	// But that requires changing struct definition and other methods.
	//
	// Alternative: Try to cast.
	mc, ok := client.(*MockClient)
	if ok {
		m.mu.Lock()
		m.clients[client.GetID().String()] = mc
		m.mu.Unlock()
		return nil
	}
	// If not MockClient, maybe we can't store it in this specific mock implementation's map.
	// But for cache, maybe we should have a separate cache map?
	// To keep it simple and avoid breaking changes, I'll just return nil (simulate success)
	// or maybe store in a separate `clientCache` map if needed.
	// Given this is a Mock, returning nil is probably sufficient for now unless we specifically test cache behavior.
	return nil
}

func (m *MockStorage) InvalidateClient(ctx context.Context, clientID BinaryUUID) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.clients, clientID.String())
	return nil
}

// ---------------------------------------------------------------------------
// TokenCache Implementation
// ---------------------------------------------------------------------------

func (m *MockStorage) SaveRefreshToken(ctx context.Context, session *RefreshTokenSession, ttl time.Duration) error {
	// Reuse CreateRefreshToken logic but ignore TTL for now, or store it.
	return m.CreateRefreshToken(ctx, session)
}

func (m *MockStorage) InvalidateRefreshToken(ctx context.Context, tokenID Hash256) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.refreshTokens, tokenID.String())
	return nil
}
