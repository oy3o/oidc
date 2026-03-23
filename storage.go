package oidc

import (
	"context"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/rs/zerolog/log"
)

const (
	DefaultClientCacheTTL = time.Hour
)

// TieredStorage implements a two-layer storage strategy.
//
// Consistency guarantees:
//   - Reads:   Read-Through with version check
//   - Creates: Write-Through (fresh data, no race)
//   - Updates: Cache-Aside with version stamp
//   - Deletes: DB → invalidate cache
//
// All cache failures are logged but never block the caller.
// TTL acts as the ultimate consistency backstop.
type TieredStorage struct {
	db    Persistence
	cache Cache

	ClientCacheTTL time.Duration
}

type TieredStorageOption func(*TieredStorage)

func WithClientCacheTTL(ttl time.Duration) TieredStorageOption {
	return func(s *TieredStorage) { s.ClientCacheTTL = ttl }
}

func NewTieredStorage(db Persistence, cache Cache, opts ...TieredStorageOption) *TieredStorage {
	s := &TieredStorage{
		db:             db,
		cache:          cache,
		ClientCacheTTL: DefaultClientCacheTTL,
	}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

var _ Storage = (*TieredStorage)(nil)

// ---------------------------------------------------------------------------
// Other Storage Methods
// ---------------------------------------------------------------------------

func (s *TieredStorage) AuthenticateByPassword(ctx context.Context, username, password string) (BinaryUUID, string, error) {
	return s.db.AuthenticateByPassword(ctx, username, password)
}

func (s *TieredStorage) DeviceCodeSave(ctx context.Context, session *DeviceCodeSession) error {
	return s.cache.DeviceCodeSave(ctx, session)
}

func (s *TieredStorage) DeviceCodeGet(ctx context.Context, deviceCode string) (*DeviceCodeSession, error) {
	return s.cache.DeviceCodeGet(ctx, deviceCode)
}

func (s *TieredStorage) DeviceCodeGetByUserCode(ctx context.Context, userCode string) (*DeviceCodeSession, error) {
	return s.cache.DeviceCodeGetByUserCode(ctx, userCode)
}

func (s *TieredStorage) DeviceCodeUpdate(ctx context.Context, deviceCode string, session *DeviceCodeSession) error {
	return s.cache.DeviceCodeUpdate(ctx, deviceCode, session)
}

func (s *TieredStorage) DeviceCodeDelete(ctx context.Context, deviceCode string) error {
	return s.cache.DeviceCodeDelete(ctx, deviceCode)
}

func (s *TieredStorage) UserCreateInfo(ctx context.Context, userInfo *UserInfo) error {
	return s.db.UserCreateInfo(ctx, userInfo)
}

func (s *TieredStorage) UserGetInfoByID(ctx context.Context, userID BinaryUUID, scopes []string) (*UserInfo, error) {
	return s.db.UserGetInfoByID(ctx, userID, scopes)
}

func (s *TieredStorage) ClientSave(ctx context.Context, client RegisteredClient, ttl time.Duration) error {
	return s.cache.ClientSave(ctx, client, ttl)
}

func (s *TieredStorage) ClientInvalidate(ctx context.Context, clientID BinaryUUID) error {
	return s.cache.ClientInvalidate(ctx, clientID)
}

func (s *TieredStorage) RefreshTokenSave(ctx context.Context, session *RefreshTokenSession, ttl time.Duration) error {
	return s.cache.RefreshTokenSave(ctx, session, ttl)
}

func (s *TieredStorage) RefreshTokenInvalidate(ctx context.Context, tokenID Hash256) error {
	return s.cache.RefreshTokenInvalidate(ctx, tokenID)
}

func (s *TieredStorage) RefreshTokensInvalidate(ctx context.Context, tokenIDs []Hash256) error {
	return s.cache.RefreshTokensInvalidate(ctx, tokenIDs)
}

func (s *TieredStorage) RefreshTokenListByUser(ctx context.Context, userID BinaryUUID) ([]*RefreshTokenSession, error) {
	return s.db.RefreshTokenListByUser(ctx, userID)
}

func (s *TieredStorage) CheckAndStore(ctx context.Context, jti string, ttl time.Duration) (bool, error) {
	return s.cache.CheckAndStore(ctx, jti, ttl)
}

func (s *TieredStorage) PARSessionSave(ctx context.Context, requestURI string, req *AuthorizeRequest, ttl time.Duration) error {
	return s.cache.PARSessionSave(ctx, requestURI, req, ttl)
}

func (s *TieredStorage) PARSessionConsume(ctx context.Context, requestURI string) (*AuthorizeRequest, error) {
	return s.cache.PARSessionConsume(ctx, requestURI)
}

func (s *TieredStorage) Lock(ctx context.Context, key string, ttl time.Duration) (bool, error) {
	return s.cache.Lock(ctx, key, ttl)
}

func (s *TieredStorage) Unlock(ctx context.Context, key string) error {
	return s.cache.Unlock(ctx, key)
}

// ---------------------------------------------------------------------------
// AuthCodeStorage
// ---------------------------------------------------------------------------

func (s *TieredStorage) AuthCodeSave(ctx context.Context, session *AuthCodeSession) error {
	return s.cache.AuthCodeSave(ctx, session)
}

func (s *TieredStorage) AuthCodeConsume(ctx context.Context, code string) (*AuthCodeSession, error) {
	return s.cache.AuthCodeConsume(ctx, code)
}

// ---------------------------------------------------------------------------
// RevocationStorage
// ---------------------------------------------------------------------------

func (s *TieredStorage) AccessTokenRevoke(ctx context.Context, jti string, expiration time.Time) error {
	return s.cache.AccessTokenRevoke(ctx, jti, expiration)
}

func (s *TieredStorage) AccessTokenIsRevoked(ctx context.Context, jti string) (bool, error) {
	return s.cache.AccessTokenIsRevoked(ctx, jti)
}

func (s *TieredStorage) Cleanup(ctx context.Context) (int64, error) {
	return s.db.Cleanup(ctx)
}

func (s *TieredStorage) Close() {
	s.db.Close()
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

func logCacheErr(err error, msg string) {
	if err != nil {
		log.Error().Err(err).Msg(msg)
	}
}

func clampTTL(expiry time.Time) time.Duration {
	if ttl := time.Until(expiry); ttl > 0 {
		return ttl
	}
	return 0
}

// ---------------------------------------------------------------------------
// ClientStorage
// ---------------------------------------------------------------------------

func (s *TieredStorage) ClientGetByID(ctx context.Context, clientID BinaryUUID) (RegisteredClient, error) {
	// Read-Through: try cache first
	cached, cacheErr := s.cache.ClientGetByID(ctx, clientID)
	if cacheErr == nil {
		// 可选：版本校验。如果 RegisteredClient 带 UpdatedAt/Version 字段，
		// 可以异步或按概率与 DB 比对，发现不一致时主动失效。
		return cached, nil
	}

	// Cache miss → DB
	client, err := s.db.ClientGetByID(ctx, clientID)
	if err != nil {
		return nil, err
	}

	logCacheErr(s.cache.ClientSave(ctx, client, s.ClientCacheTTL), "failed to cache client")
	return client, nil
}

func (s *TieredStorage) ClientCreate(ctx context.Context, metadata *ClientMetadata) (RegisteredClient, error) {
	client, err := s.db.ClientCreate(ctx, metadata)
	if err != nil {
		return nil, err
	}

	// Write-Through: 新建记录不存在竞争，安全写入缓存
	logCacheErr(s.cache.ClientSave(ctx, client, s.ClientCacheTTL), "failed to cache new client")
	return client, nil
}

func (s *TieredStorage) ClientUpdate(ctx context.Context, metadata *ClientMetadata) (RegisteredClient, error) {
	client, err := s.db.ClientUpdate(ctx, metadata)
	if err != nil {
		return nil, err
	}

	// Cache-Aside: 失效而非覆写，避免并发写入覆盖更新版本
	// 双删策略：立即删 + 延迟删，收窄不一致窗口
	logCacheErr(s.cache.ClientInvalidate(ctx, metadata.ID), "failed to invalidate client cache")

	// 延迟二次删除：覆盖在第一次删除与下次读取之间被旧并发请求重新填充的脏缓存
	go func() {
		time.Sleep(500 * time.Millisecond)
		bgCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		logCacheErr(s.cache.ClientInvalidate(bgCtx, metadata.ID), "failed delayed client cache invalidation")
	}()

	return client, nil
}

func (s *TieredStorage) ClientDeleteByID(ctx context.Context, clientID BinaryUUID) error {
	if err := s.db.ClientDeleteByID(ctx, clientID); err != nil {
		return err
	}

	logCacheErr(s.cache.ClientInvalidate(ctx, clientID), "failed to invalidate client cache")
	return nil
}

func (s *TieredStorage) ClientListByOwner(ctx context.Context, ownerID BinaryUUID, query ListQuery) ([]RegisteredClient, error) {
	return s.db.ClientListByOwner(ctx, ownerID, query)
}

func (s *TieredStorage) ClientListAll(ctx context.Context, query ListQuery) ([]RegisteredClient, error) {
	return s.db.ClientListAll(ctx, query)
}

// ---------------------------------------------------------------------------
// TokenStorage
// ---------------------------------------------------------------------------

func (s *TieredStorage) RefreshTokenCreate(ctx context.Context, session *RefreshTokenSession) error {
	if err := s.db.RefreshTokenCreate(ctx, session); err != nil {
		return err
	}

	if ttl := clampTTL(session.ExpiresAt); ttl > 0 {
		logCacheErr(s.cache.RefreshTokenSave(ctx, session, ttl), "failed to cache refresh token")
	}
	return nil
}

func (s *TieredStorage) RefreshTokenGet(ctx context.Context, tokenID Hash256) (*RefreshTokenSession, error) {
	if sess, err := s.cache.RefreshTokenGet(ctx, tokenID); err == nil {
		return sess, nil
	}

	sess, err := s.db.RefreshTokenGet(ctx, tokenID)
	if err != nil {
		return nil, err
	}

	if ttl := clampTTL(sess.ExpiresAt); ttl > 0 {
		logCacheErr(s.cache.RefreshTokenSave(ctx, sess, ttl), "failed to cache refresh token")
	}
	return sess, nil
}

func (s *TieredStorage) RefreshTokenRotate(
	ctx context.Context,
	oldTokenID Hash256,
	newSession *RefreshTokenSession,
	gracePeriod time.Duration,
) error {
	if err := s.db.RefreshTokenRotate(ctx, oldTokenID, newSession, gracePeriod); err != nil {
		return err
	}

	logCacheErr(
		s.cache.RefreshTokenRotate(ctx, oldTokenID, newSession, gracePeriod),
		"failed to rotate refresh token in cache",
	)
	return nil
}

func (s *TieredStorage) RefreshTokenRevoke(ctx context.Context, tokenID Hash256) error {
	if err := s.db.RefreshTokenRevoke(ctx, tokenID); err != nil {
		return err
	}

	logCacheErr(s.cache.RefreshTokenInvalidate(ctx, tokenID), "failed to invalidate refresh token cache")
	return nil
}

func (s *TieredStorage) RefreshTokenRevokeUser(ctx context.Context, userID BinaryUUID) ([]Hash256, error) {
	ids, err := s.db.RefreshTokenRevokeUser(ctx, userID)
	if err != nil {
		return nil, err
	}

	logCacheErr(s.cache.RefreshTokensInvalidate(ctx, ids), "failed to invalidate user refresh tokens cache")
	return ids, nil
}

// ---------------------------------------------------------------------------
// KeyStorage
// ---------------------------------------------------------------------------

func (s *TieredStorage) JWKSave(ctx context.Context, key jwk.Key) error {
	if err := s.db.JWKSave(ctx, key); err != nil {
		return err
	}

	logCacheErr(s.cache.JWKSave(ctx, key), "failed to cache JWK")
	return nil
}

func (s *TieredStorage) JWKGet(ctx context.Context, kid string) (jwk.Key, error) {
	if key, err := s.cache.JWKGet(ctx, kid); err == nil {
		return key, nil
	}

	key, err := s.db.JWKGet(ctx, kid)
	if err != nil {
		return nil, err
	}

	logCacheErr(s.cache.JWKSave(ctx, key), "failed to cache JWK")
	return key, nil
}

func (s *TieredStorage) JWKList(ctx context.Context) ([]jwk.Key, error) {
	return s.db.JWKList(ctx)
}

func (s *TieredStorage) JWKDelete(ctx context.Context, kid string) error {
	if err := s.db.JWKDelete(ctx, kid); err != nil {
		return err
	}

	logCacheErr(s.cache.JWKDelete(ctx, kid), "failed to delete JWK from cache")
	return nil
}

func (s *TieredStorage) JWKMarkSigning(ctx context.Context, kid string) error {
	if err := s.db.JWKMarkSigning(ctx, kid); err != nil {
		return err
	}

	logCacheErr(s.cache.JWKMarkSigning(ctx, kid), "failed to mark signing JWK in cache")
	return nil
}

func (s *TieredStorage) JWKGetSigning(ctx context.Context) (string, error) {
	if id, err := s.cache.JWKGetSigning(ctx); err == nil {
		return id, nil
	}

	id, err := s.db.JWKGetSigning(ctx)
	if err != nil {
		return "", err
	}

	logCacheErr(s.cache.JWKMarkSigning(ctx, id), "failed to cache signing JWK ID")
	return id, nil
}
