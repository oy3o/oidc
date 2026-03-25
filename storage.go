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
	Persistence
	Cache

	ClientCacheTTL time.Duration
}

type TieredStorageOption func(*TieredStorage)

func WithClientCacheTTL(ttl time.Duration) TieredStorageOption {
	return func(s *TieredStorage) { s.ClientCacheTTL = ttl }
}

func NewTieredStorage(db Persistence, cache Cache, opts ...TieredStorageOption) *TieredStorage {
	s := &TieredStorage{
		Persistence:    db,
		Cache:          cache,
		ClientCacheTTL: DefaultClientCacheTTL,
	}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

var _ Storage = (*TieredStorage)(nil)

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
	cached, cacheErr := s.ClientGetByID(ctx, clientID)
	if cacheErr == nil {
		// 可选：版本校验。如果 RegisteredClient 带 UpdatedAt/Version 字段，
		// 可以异步或按概率与 DB 比对，发现不一致时主动失效。
		return cached, nil
	}

	// Cache miss → DB
	client, err := s.ClientGetByID(ctx, clientID)
	if err != nil {
		return nil, err
	}

	logCacheErr(s.ClientSave(ctx, client, s.ClientCacheTTL), "failed to cache client")
	return client, nil
}

func (s *TieredStorage) ClientCreate(ctx context.Context, metadata *ClientMetadata) (RegisteredClient, error) {
	client, err := s.ClientCreate(ctx, metadata)
	if err != nil {
		return nil, err
	}

	// Write-Through: 新建记录不存在竞争，安全写入缓存
	logCacheErr(s.ClientSave(ctx, client, s.ClientCacheTTL), "failed to cache new client")
	return client, nil
}

func (s *TieredStorage) ClientUpdate(ctx context.Context, metadata *ClientMetadata) (RegisteredClient, error) {
	client, err := s.ClientUpdate(ctx, metadata)
	if err != nil {
		return nil, err
	}

	// Cache-Aside: 失效而非覆写，避免并发写入覆盖更新版本
	// 双删策略：立即删 + 延迟删，收窄不一致窗口
	logCacheErr(s.ClientInvalidate(ctx, metadata.ID), "failed to invalidate client cache")

	// 延迟二次删除：覆盖在第一次删除与下次读取之间被旧并发请求重新填充的脏缓存
	go func() {
		time.Sleep(500 * time.Millisecond)
		bgCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Second)
		defer cancel()
		logCacheErr(s.ClientInvalidate(bgCtx, metadata.ID), "failed delayed client cache invalidation")
	}()

	return client, nil
}

func (s *TieredStorage) ClientDeleteByID(ctx context.Context, clientID BinaryUUID) error {
	if err := s.ClientDeleteByID(ctx, clientID); err != nil {
		return err
	}

	logCacheErr(s.ClientInvalidate(ctx, clientID), "failed to invalidate client cache")
	return nil
}

func (s *TieredStorage) ClientListByOwner(ctx context.Context, ownerID BinaryUUID, query ListQuery) ([]RegisteredClient, error) {
	return s.ClientListByOwner(ctx, ownerID, query)
}

func (s *TieredStorage) ClientListAll(ctx context.Context, query ListQuery) ([]RegisteredClient, error) {
	return s.ClientListAll(ctx, query)
}

// ---------------------------------------------------------------------------
// TokenStorage
// ---------------------------------------------------------------------------

func (s *TieredStorage) RefreshTokenCreate(ctx context.Context, session *RefreshTokenSession) error {
	if err := s.RefreshTokenCreate(ctx, session); err != nil {
		return err
	}

	if ttl := clampTTL(session.ExpiresAt); ttl > 0 {
		logCacheErr(s.RefreshTokenSave(ctx, session, ttl), "failed to cache refresh token")
	}
	return nil
}

func (s *TieredStorage) RefreshTokenGet(ctx context.Context, tokenID Hash256) (*RefreshTokenSession, error) {
	if sess, err := s.RefreshTokenGet(ctx, tokenID); err == nil {
		return sess, nil
	}

	sess, err := s.RefreshTokenGet(ctx, tokenID)
	if err != nil {
		return nil, err
	}

	if ttl := clampTTL(sess.ExpiresAt); ttl > 0 {
		logCacheErr(s.RefreshTokenSave(ctx, sess, ttl), "failed to cache refresh token")
	}
	return sess, nil
}

func (s *TieredStorage) RefreshTokenRotate(
	ctx context.Context,
	oldTokenID Hash256,
	newSession *RefreshTokenSession,
	gracePeriod time.Duration,
) error {
	if err := s.RefreshTokenRotate(ctx, oldTokenID, newSession, gracePeriod); err != nil {
		return err
	}

	logCacheErr(
		s.RefreshTokenRotate(ctx, oldTokenID, newSession, gracePeriod),
		"failed to rotate refresh token in cache",
	)
	return nil
}

func (s *TieredStorage) RefreshTokenRevoke(ctx context.Context, tokenID Hash256) error {
	if err := s.RefreshTokenRevoke(ctx, tokenID); err != nil {
		return err
	}

	logCacheErr(s.RefreshTokenInvalidate(ctx, tokenID), "failed to invalidate refresh token cache")
	return nil
}

func (s *TieredStorage) RefreshTokenRevokeUser(ctx context.Context, userID BinaryUUID) ([]Hash256, error) {
	ids, err := s.RefreshTokenRevokeUser(ctx, userID)
	if err != nil {
		return nil, err
	}

	logCacheErr(s.RefreshTokensInvalidate(ctx, ids), "failed to invalidate user refresh tokens cache")
	return ids, nil
}

// ---------------------------------------------------------------------------
// KeyStorage
// ---------------------------------------------------------------------------

func (s *TieredStorage) JWKSave(ctx context.Context, key jwk.Key) error {
	if err := s.JWKSave(ctx, key); err != nil {
		return err
	}

	logCacheErr(s.JWKSave(ctx, key), "failed to cache JWK")
	return nil
}

func (s *TieredStorage) JWKGet(ctx context.Context, kid string) (jwk.Key, error) {
	if key, err := s.JWKGet(ctx, kid); err == nil {
		return key, nil
	}

	key, err := s.JWKGet(ctx, kid)
	if err != nil {
		return nil, err
	}

	logCacheErr(s.JWKSave(ctx, key), "failed to cache JWK")
	return key, nil
}

func (s *TieredStorage) JWKList(ctx context.Context) ([]jwk.Key, error) {
	return s.JWKList(ctx)
}

func (s *TieredStorage) JWKDelete(ctx context.Context, kid string) error {
	if err := s.JWKDelete(ctx, kid); err != nil {
		return err
	}

	logCacheErr(s.JWKDelete(ctx, kid), "failed to delete JWK from cache")
	return nil
}

func (s *TieredStorage) JWKMarkSigning(ctx context.Context, kid string) error {
	if err := s.JWKMarkSigning(ctx, kid); err != nil {
		return err
	}

	logCacheErr(s.JWKMarkSigning(ctx, kid), "failed to mark signing JWK in cache")
	return nil
}

func (s *TieredStorage) JWKGetSigning(ctx context.Context) (string, error) {
	if id, err := s.JWKGetSigning(ctx); err == nil {
		return id, nil
	}

	id, err := s.JWKGetSigning(ctx)
	if err != nil {
		return "", err
	}

	logCacheErr(s.JWKMarkSigning(ctx, id), "failed to cache signing JWK ID")
	return id, nil
}
