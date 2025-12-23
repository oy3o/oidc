package oidc

import (
	"context"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/rs/zerolog/log"
)

// TieredStorage implements a storage strategy that uses a fast Cache layer
// backed by a persistent Database layer.
//
// Strategy:
//   - Reads: Read-Through (Cache -> Miss? -> DB -> Set Cache)
//   - Writes: Cache-Aside (DB -> Invalidate Cache on success)
//     After DB commit, we invalidate cache. If invalidation fails, we log the error but don't fail the request.
//     This ensures eventual consistency and prevents stale cache data.
//   - Deletes: DB -> Cache JWKDelete
type TieredStorage struct {
	Persistence
	Cache
}

// NewTieredStorage creates a new TieredStorage instance.
func NewTieredStorage(db Persistence, cache Cache) *TieredStorage {
	return &TieredStorage{
		Persistence: db,
		Cache:       cache,
	}
}

// Ensure TieredStorage implements Storage interface
var _ Storage = (*TieredStorage)(nil)

// ---------------------------------------------------------------------------
// ClientStorage Implementation (Read-Through / Write-Through)
// ---------------------------------------------------------------------------

func (s *TieredStorage) ClientGetByID(ctx context.Context, clientID BinaryUUID) (RegisteredClient, error) {
	// 1. Try Cache (Read-Through)
	client, err := s.Cache.ClientGetByID(ctx, clientID)
	if err == nil {
		return client, nil
	}
	// Ignore cache miss/error, proceed to DB

	// 2. Fetch from DB
	client, err = s.Persistence.ClientGetByID(ctx, clientID)
	if err != nil {
		return nil, err
	}

	// 3. Populate Cache (Async or Sync? Sync for Read-Through usually)
	// We use a short TTL or standard TTL. Let's assume 1 hour for clients.
	_ = s.Cache.ClientSave(ctx, client, time.Hour)

	return client, nil
}

func (s *TieredStorage) ClientCreate(ctx context.Context, metadata *ClientMetadata) (RegisteredClient, error) {
	// 1. Write DB (Write-Through)
	client, err := s.Persistence.ClientCreate(ctx, metadata)
	if err != nil {
		return nil, err
	}

	// 2. Write Cache
	_ = s.Cache.ClientSave(ctx, client, time.Hour)
	return client, nil
}

func (s *TieredStorage) ClientUpdate(ctx context.Context, metadata *ClientMetadata) (RegisteredClient, error) {
	// 1. Write DB
	client, err := s.Persistence.ClientUpdate(ctx, metadata)
	if err != nil {
		return nil, err
	}

	// 2. Invalidate Cache (Cache-Aside)
	// If cache invalidation fails, log but don't fail the request (eventual consistency)
	if err := s.Cache.ClientInvalidate(ctx, metadata.ID); err != nil {
		log.Error().Err(err).Msg("Failed to invalidate client cache")
	}
	return client, nil
}

func (s *TieredStorage) ClientDeleteByID(ctx context.Context, clientID BinaryUUID) error {
	// 1. JWKDelete DB
	if err := s.Persistence.ClientDeleteByID(ctx, clientID); err != nil {
		return err
	}

	// 2. JWKDelete Cache
	if err := s.Cache.ClientInvalidate(ctx, clientID); err != nil {
		log.Error().Err(err).Msg("Failed to invalidate client cache")
	}
	return nil
}

func (s *TieredStorage) ClientListByOwner(ctx context.Context, ownerID BinaryUUID, query ListQuery) ([]RegisteredClient, error) {
	// No caching for lists usually, unless complex. Direct to DB.
	return s.Persistence.ClientListByOwner(ctx, ownerID, query)
}

func (s *TieredStorage) ClientListAll(ctx context.Context, query ListQuery) ([]RegisteredClient, error) {
	return s.Persistence.ClientListAll(ctx, query)
}

// ---------------------------------------------------------------------------
// TokenStorage Implementation (Read-Through / Write-Through)
// ---------------------------------------------------------------------------

func (s *TieredStorage) RefreshTokenCreate(ctx context.Context, session *RefreshTokenSession) error {
	// 1. Write DB
	if err := s.Persistence.RefreshTokenCreate(ctx, session); err != nil {
		return err
	}

	// 2. Write Cache
	// Refresh Tokens are long-lived, but we might want to cache them for shorter duration if accessed frequently.
	// Or cache for full duration.
	ttl := time.Until(session.ExpiresAt)
	if ttl > 0 {
		_ = s.Cache.RefreshTokenSave(ctx, session, ttl)
	}
	return nil
}

func (s *TieredStorage) RefreshTokenGet(ctx context.Context, tokenID Hash256) (*RefreshTokenSession, error) {
	// 1. Try Cache
	session, err := s.Cache.RefreshTokenGet(ctx, tokenID)
	if err == nil {
		return session, nil
	}

	// 2. Fetch DB
	session, err = s.Persistence.RefreshTokenGet(ctx, tokenID)
	if err != nil {
		return nil, err
	}

	// 3. Populate Cache
	ttl := time.Until(session.ExpiresAt)
	if ttl > 0 {
		_ = s.Cache.RefreshTokenSave(ctx, session, ttl)
	}

	return session, nil
}

func (s *TieredStorage) RefreshTokenRotate(ctx context.Context, oldTokenID Hash256, newSession *RefreshTokenSession, gracePeriod time.Duration) error {
	// 1. Write DB (Transaction ideally handled by DB layer)
	if err := s.Persistence.RefreshTokenRotate(ctx, oldTokenID, newSession, 0); err != nil {
		return err
	}

	// 2. Write Cache,
	if err := s.Cache.RefreshTokenRotate(ctx, oldTokenID, newSession, gracePeriod); err != nil {
		log.Error().Err(err).Msg("Failed to invalidate refresh token cache")
	}

	return nil
}

func (s *TieredStorage) RefreshTokenRevoke(ctx context.Context, tokenID Hash256) error {
	// 1. DB
	if err := s.Persistence.RefreshTokenRevoke(ctx, tokenID); err != nil {
		return err
	}
	// 2. Cache (log failure but don't block)
	if err := s.Cache.RefreshTokenInvalidate(ctx, tokenID); err != nil {
		log.Error().Err(err).Msg("Failed to invalidate refresh token cache")
	}
	return nil
}

func (s *TieredStorage) RefreshTokenRevokeUser(ctx context.Context, userID BinaryUUID) ([]Hash256, error) {
	// 1. DB
	ids, err := s.Persistence.RefreshTokenRevokeUser(ctx, userID)
	if err != nil {
		return nil, err
	}
	// 2. Cache
	if err := s.Cache.RefreshTokensInvalidate(ctx, ids); err != nil {
		log.Error().Err(err).Msg("Failed to invalidate refresh token cache")
	}
	return ids, nil
}

// ---------------------------------------------------------------------------
// KeyStorage Implementation (Read-Through / Write-Through)
// ---------------------------------------------------------------------------

func (s *TieredStorage) JWKSave(ctx context.Context, key jwk.Key) error {
	if err := s.Persistence.JWKSave(ctx, key); err != nil {
		return err
	}
	// Redis KeyStorage JWKSave is already implemented in RedisStorage, so we can call it.
	// But `s.cache` is `Cache` interface which embeds `KeyStorage`.
	return s.Cache.JWKSave(ctx, key)
}

func (s *TieredStorage) JWKGet(ctx context.Context, kid string) (jwk.Key, error) {
	key, err := s.Cache.JWKGet(ctx, kid)
	if err == nil {
		return key, nil
	}
	key, err = s.Persistence.JWKGet(ctx, kid)
	if err != nil {
		return nil, err
	}
	_ = s.Cache.JWKSave(ctx, key)
	return key, nil
}

func (s *TieredStorage) JWKList(ctx context.Context) ([]jwk.Key, error) {
	// JWKList from DB is safer for source of truth
	return s.Persistence.JWKList(ctx)
}

func (s *TieredStorage) JWKDelete(ctx context.Context, kid string) error {
	if err := s.Persistence.JWKDelete(ctx, kid); err != nil {
		return err
	}
	return s.Cache.JWKDelete(ctx, kid)
}

func (s *TieredStorage) JWKMarkSigning(ctx context.Context, kid string) error {
	if err := s.Persistence.JWKMarkSigning(ctx, kid); err != nil {
		return err
	}
	return s.Cache.JWKMarkSigning(ctx, kid)
}

func (s *TieredStorage) JWKGetSigning(ctx context.Context) (string, error) {
	id, err := s.Cache.JWKGetSigning(ctx)
	if err == nil {
		return id, nil
	}
	id, err = s.Persistence.JWKGetSigning(ctx)
	if err != nil {
		return "", err
	}
	_ = s.Cache.JWKMarkSigning(ctx, id)
	return id, nil
}
