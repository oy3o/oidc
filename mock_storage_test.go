package oidc_test

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/oy3o/oidc"
)

type mockHasher struct{}

func (m *mockHasher) Hash(ctx context.Context, password []byte) ([]byte, error) {
	return password, nil
}

func (m *mockHasher) Compare(ctx context.Context, hashedPassword []byte, password []byte) error {
	if string(hashedPassword) != string(password) {
		return oidc.ErrInvalidGrant
	}
	return nil
}

func (m *mockHasher) DummyCompare(ctx context.Context) error {
	return nil
}

type parEntry struct {
	req *oidc.AuthorizeRequest
	exp time.Time
}

type MockStorage struct {
	oidc.Storage

	mu             sync.Mutex
	timeOffset     time.Duration
	clients        map[string]*oidc.ClientMetadata
	jwks           map[string]jwk.Key
	signingKeyID   string
	users          map[string]*oidc.UserInfo
	authCodes      map[string]*oidc.AuthCodeSession
	refreshTokens  map[string]*oidc.RefreshTokenSession
	revokedTokens  map[string]time.Time
	replayCache    map[string]time.Time
	parSessions    map[string]parEntry
	deviceSessions map[string]*oidc.DeviceCodeSession
}

func NewMockStorage() *MockStorage {
	return &MockStorage{
		clients:        make(map[string]*oidc.ClientMetadata),
		jwks:           make(map[string]jwk.Key),
		users:          make(map[string]*oidc.UserInfo),
		authCodes:      make(map[string]*oidc.AuthCodeSession),
		refreshTokens:  make(map[string]*oidc.RefreshTokenSession),
		revokedTokens:  make(map[string]time.Time),
		replayCache:    make(map[string]time.Time),
		parSessions:    make(map[string]parEntry),
		deviceSessions: make(map[string]*oidc.DeviceCodeSession),
	}
}

func (m *MockStorage) FastForward(d time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.timeOffset += d
}

func (m *MockStorage) now() time.Time {
	return time.Now().Add(m.timeOffset)
}

// Client Methods
func (m *MockStorage) ClientCreate(ctx context.Context, metadata *oidc.ClientMetadata) (oidc.RegisteredClient, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.clients[metadata.ID.String()] = metadata
	return metadata, nil
}

func (m *MockStorage) ClientGetByID(ctx context.Context, clientID oidc.BinaryUUID) (oidc.RegisteredClient, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if c, ok := m.clients[clientID.String()]; ok {
		return c, nil
	}
	return nil, oidc.ErrClientNotFound
}

func (m *MockStorage) ClientUpdate(ctx context.Context, metadata *oidc.ClientMetadata) (oidc.RegisteredClient, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.clients[metadata.ID.String()] = metadata
	return metadata, nil
}

func (m *MockStorage) ClientDeleteByID(ctx context.Context, clientID oidc.BinaryUUID) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.clients, clientID.String())
	return nil
}

func (m *MockStorage) ClientSave(ctx context.Context, client oidc.RegisteredClient, ttl time.Duration) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.clients[client.GetID().String()] = client.(*oidc.ClientMetadata)
	return nil
}

func (m *MockStorage) ClientInvalidate(ctx context.Context, clientID oidc.BinaryUUID) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.clients, clientID.String())
	return nil
}

// JWK Methods
func (m *MockStorage) JWKSave(ctx context.Context, key jwk.Key) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.jwks[key.KeyID()] = key
	return nil
}

func (m *MockStorage) JWKMarkSigning(ctx context.Context, kid string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.signingKeyID = kid
	return nil
}

func (m *MockStorage) JWKGetSigning(ctx context.Context) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.signingKeyID == "" {
		return "", oidc.ErrKeyNotFound
	}
	return m.signingKeyID, nil
}

func (m *MockStorage) JWKGet(ctx context.Context, kid string) (jwk.Key, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if k, ok := m.jwks[kid]; ok {
		return k, nil
	}
	return nil, oidc.ErrKeyNotFound
}

func (m *MockStorage) JWKList(ctx context.Context) ([]jwk.Key, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var keys []jwk.Key
	for _, k := range m.jwks {
		keys = append(keys, k)
	}
	return keys, nil
}

func (m *MockStorage) JWKDelete(ctx context.Context, kid string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.jwks[kid]; !ok {
		return oidc.ErrKeyNotFound
	}
	delete(m.jwks, kid)
	if m.signingKeyID == kid {
		m.signingKeyID = ""
	}
	return nil
}

// Distributed Lock
func (m *MockStorage) Lock(ctx context.Context, key string, ttl time.Duration) (bool, error) {
	return true, nil
}

func (m *MockStorage) Unlock(ctx context.Context, key string) error {
	return nil
}

// User Info
func (m *MockStorage) UserCreateInfo(ctx context.Context, userInfo *oidc.UserInfo) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.users[userInfo.Subject] = userInfo
	return nil
}

func (m *MockStorage) UserGetInfoByID(ctx context.Context, userID oidc.BinaryUUID, scopes []string) (*oidc.UserInfo, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	u, ok := m.users[userID.String()]
	if !ok {
		return nil, errors.New("user not found")
	}

	scopeMap := make(map[string]bool)
	for _, s := range scopes {
		scopeMap[s] = true
	}

	filtered := &oidc.UserInfo{
		Subject: u.Subject,
	}

	if scopeMap["profile"] {
		filtered.Name = u.Name
		filtered.FamilyName = u.FamilyName
		filtered.GivenName = u.GivenName
		filtered.Nickname = u.Nickname
		filtered.PreferredUsername = u.PreferredUsername
		filtered.Profile = u.Profile
		filtered.Picture = u.Picture
		filtered.Website = u.Website
		filtered.Email = u.Email // Email is often loosely grouped if not strictly conforming, but let's strictly adhere
		filtered.Gender = u.Gender
		filtered.Birthdate = u.Birthdate
		filtered.Zoneinfo = u.Zoneinfo
		filtered.Locale = u.Locale
		filtered.UpdatedAt = u.UpdatedAt
	}

	if scopeMap["email"] {
		filtered.Email = u.Email
		filtered.EmailVerified = u.EmailVerified
	}

	if scopeMap["phone"] {
		filtered.PhoneNumber = u.PhoneNumber
		filtered.PhoneNumberVerified = u.PhoneNumberVerified
	}

	// Remove email from profile block above to be strictly correct with OIDC
	if scopeMap["profile"] {
		filtered.Email = nil // Was just set, override to correct
	}

	return filtered, nil
}

// Auth Code
func (m *MockStorage) AuthCodeSave(ctx context.Context, session *oidc.AuthCodeSession) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.authCodes[session.Code] = session
	return nil
}

func (m *MockStorage) AuthCodeConsume(ctx context.Context, code string) (*oidc.AuthCodeSession, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if session, ok := m.authCodes[code]; ok {
		delete(m.authCodes, code)
		return session, nil
	}
	return nil, oidc.ErrCodeNotFound
}

// Refresh Token
func (m *MockStorage) RefreshTokenCreate(ctx context.Context, session *oidc.RefreshTokenSession) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.refreshTokens[string(session.ID)] = session
	return nil
}

func (m *MockStorage) RefreshTokenGet(ctx context.Context, tokenID oidc.Hash256) (*oidc.RefreshTokenSession, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if s, ok := m.refreshTokens[string(tokenID)]; ok {
		return s, nil
	}
	return nil, oidc.ErrTokenNotFound
}

func (m *MockStorage) RefreshTokenRotate(ctx context.Context, oldTokenID oidc.Hash256, newSession *oidc.RefreshTokenSession, gracePeriod time.Duration) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.refreshTokens, string(oldTokenID))
	m.refreshTokens[string(newSession.ID)] = newSession
	return nil
}

func (m *MockStorage) RefreshTokenSave(ctx context.Context, session *oidc.RefreshTokenSession, ttl time.Duration) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.refreshTokens[string(session.ID)] = session
	return nil
}

func (m *MockStorage) RefreshTokenInvalidate(ctx context.Context, tokenID oidc.Hash256) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.refreshTokens, string(tokenID))
	return nil
}

func (m *MockStorage) RefreshTokensInvalidate(ctx context.Context, tokenIDs []oidc.Hash256) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, id := range tokenIDs {
		delete(m.refreshTokens, string(id))
	}
	return nil
}

func (m *MockStorage) RefreshTokenRevoke(ctx context.Context, tokenID oidc.Hash256) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.refreshTokens, string(tokenID))
	return nil
}

func (m *MockStorage) RefreshTokenRevokeUser(ctx context.Context, userID oidc.BinaryUUID) ([]oidc.Hash256, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var revoked []oidc.Hash256
	for id, s := range m.refreshTokens {
		if s.UserID == userID {
			delete(m.refreshTokens, id)
			revoked = append(revoked, oidc.Hash256(id))
		}
	}
	return revoked, nil
}

func (m *MockStorage) RefreshTokenListByUser(ctx context.Context, userID oidc.BinaryUUID) ([]*oidc.RefreshTokenSession, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var list []*oidc.RefreshTokenSession
	for _, s := range m.refreshTokens {
		if s.UserID == userID {
			list = append(list, s)
		}
	}
	return list, nil
}

// Revocation (Access Token)
func (m *MockStorage) AccessTokenIsRevoked(ctx context.Context, jti string) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	exp, ok := m.revokedTokens[jti]
	if !ok || m.now().After(exp) {
		return false, nil
	}
	return true, nil
}

func (m *MockStorage) AccessTokenRevoke(ctx context.Context, jti string, expiration time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.revokedTokens[jti] = expiration
	return nil
}

// Replay Cache (DPoP)
func (m *MockStorage) CheckAndStore(ctx context.Context, jti string, ttl time.Duration) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	exp, ok := m.replayCache[jti]
	if ok && m.now().Before(exp) {
		return true, nil
	}
	m.replayCache[jti] = m.now().Add(ttl)
	return false, nil
}

// PAR
func (m *MockStorage) PARSessionSave(ctx context.Context, requestURI string, req *oidc.AuthorizeRequest, ttl time.Duration) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.parSessions[requestURI] = parEntry{req: req, exp: m.now().Add(ttl)}
	return nil
}

func (m *MockStorage) PARSessionConsume(ctx context.Context, requestURI string) (*oidc.AuthorizeRequest, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if e, ok := m.parSessions[requestURI]; ok {
		delete(m.parSessions, requestURI)
		if m.now().After(e.exp) {
			return nil, errors.New("PAR session expired")
		}
		return e.req, nil
	}
	return nil, errors.New("PAR session not found")
}

// Device Flow
func (m *MockStorage) DeviceCodeSave(ctx context.Context, session *oidc.DeviceCodeSession) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.deviceSessions[session.DeviceCode] = session
	return nil
}

func (m *MockStorage) DeviceCodeDelete(ctx context.Context, deviceCode string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.deviceSessions, deviceCode)
	return nil
}

func (m *MockStorage) DeviceCodeGet(ctx context.Context, deviceCode string) (*oidc.DeviceCodeSession, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if s, ok := m.deviceSessions[deviceCode]; ok {
		return s, nil
	}
	return nil, errors.New("device code not found")
}

func (m *MockStorage) DeviceCodeGetByUserCode(ctx context.Context, userCode string) (*oidc.DeviceCodeSession, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, session := range m.deviceSessions {
		if session.UserCode == userCode {
			return session, nil
		}
	}
	return nil, errors.New("user code not found")
}

func (m *MockStorage) DeviceCodeUpdate(ctx context.Context, deviceCode string, session *oidc.DeviceCodeSession) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.deviceSessions[deviceCode] = session
	return nil
}
