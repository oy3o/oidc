package redis

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/google/uuid"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/oy3o/oidc"
	"github.com/oy3o/oidc/gorm"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type clientFactory struct{}

func (f *clientFactory) New() oidc.RegisteredClient {
	return &gorm.ClientModel{}
}

// setupRedis 初始化 miniredis 和 Storage
func setupRedis(t *testing.T) (*miniredis.Miniredis, *RedisStorage) {
	// 启动内存 Redis
	s := miniredis.RunT(t)

	// 连接到 mock redis
	rdb := redis.NewClient(&redis.Options{
		Addr: s.Addr(),
	})

	return s, NewRedisStorage(rdb, &clientFactory{})
}

// ---------------------------------------------------------------------------
// AuthCodeStorage Tests
// ---------------------------------------------------------------------------

func TestRedis_AuthCode(t *testing.T) {
	_, storage := setupRedis(t)
	ctx := context.Background()

	code := "test_auth_code"
	session := &oidc.AuthCodeSession{
		Code:      code,
		ClientID:  oidc.BinaryUUID(uuid.New()),
		ExpiresAt: time.Now().Add(10 * time.Minute),
		Scope:     "openid",
	}

	// 1. Save
	err := storage.SaveAuthCode(ctx, session)
	require.NoError(t, err)

	// 2. Load and Consume (Success)
	loaded, err := storage.LoadAndConsumeAuthCode(ctx, code)
	require.NoError(t, err)
	assert.Equal(t, session.ClientID, loaded.ClientID)

	// 3. Load and Consume again (Should fail - Replay attack prevention)
	_, err = storage.LoadAndConsumeAuthCode(ctx, code)
	assert.ErrorIs(t, err, oidc.ErrCodeNotFound)
}

func TestRedis_AuthCode_Expired(t *testing.T) {
	s, storage := setupRedis(t)
	ctx := context.Background()

	code := "expired_code"
	session := &oidc.AuthCodeSession{
		Code:      code,
		ExpiresAt: time.Now().Add(1 * time.Second),
	}

	storage.SaveAuthCode(ctx, session)

	// 快进时间 (miniredis 特性)
	s.FastForward(2 * time.Second)

	_, err := storage.LoadAndConsumeAuthCode(ctx, code)
	assert.ErrorIs(t, err, oidc.ErrCodeNotFound)
}

// ---------------------------------------------------------------------------
// DeviceCodeStorage Tests
// ---------------------------------------------------------------------------

func TestRedis_DeviceCode(t *testing.T) {
	_, storage := setupRedis(t)
	ctx := context.Background()

	deviceCode := "device-123"
	userCode := "USER-123"
	clientID := oidc.BinaryUUID(uuid.New())

	session := &oidc.DeviceCodeSession{
		DeviceCode: deviceCode,
		UserCode:   userCode,
		ClientID:   clientID,
		ExpiresAt:  time.Now().Add(10 * time.Minute),
		Status:     oidc.DeviceCodeStatusPending,
	}

	// 1. Save
	err := storage.SaveDeviceCode(ctx, session)
	require.NoError(t, err)

	// 2. Get by Device Code
	got, err := storage.GetDeviceCodeSession(ctx, deviceCode)
	require.NoError(t, err)
	assert.Equal(t, clientID, got.ClientID)

	// 3. Get by User Code
	gotByUser, err := storage.GetDeviceCodeSessionByUserCode(ctx, userCode)
	require.NoError(t, err)
	assert.Equal(t, deviceCode, gotByUser.DeviceCode)

	// 4. Update
	session.Status = oidc.DeviceCodeStatusAllowed
	err = storage.UpdateDeviceCodeSession(ctx, deviceCode, session)
	require.NoError(t, err)

	updated, err := storage.GetDeviceCodeSession(ctx, deviceCode)
	require.NoError(t, err)
	assert.Equal(t, oidc.DeviceCodeStatusAllowed, updated.Status)
}

// ---------------------------------------------------------------------------
// PARStorage Tests
// ---------------------------------------------------------------------------

func TestRedis_PAR(t *testing.T) {
	_, storage := setupRedis(t)
	ctx := context.Background()

	uri := "urn:ietf:params:oauth:request_uri:123"
	req := &oidc.AuthorizeRequest{
		ClientID: "client-1",
		State:    "state-xyz",
	}

	// 1. Save
	err := storage.SavePARSession(ctx, uri, req, time.Minute)
	require.NoError(t, err)

	// 2. Get and Delete (Success)
	got, err := storage.GetAndDeletePARSession(ctx, uri)
	require.NoError(t, err)
	assert.Equal(t, "client-1", got.ClientID)

	// 3. Get again (Should fail - One time use)
	_, err = storage.GetAndDeletePARSession(ctx, uri)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "PAR session not found")
}

// ---------------------------------------------------------------------------
// ReplayCache (DPoP) Tests
// ---------------------------------------------------------------------------

func TestRedis_DPoP_Replay(t *testing.T) {
	_, storage := setupRedis(t)
	ctx := context.Background()
	jti := "unique-jti-123"

	// 1. First use
	isReplay, err := storage.CheckAndStore(ctx, jti, time.Minute)
	require.NoError(t, err)
	assert.False(t, isReplay, "First use should not be replay")

	// 2. Second use (Replay)
	isReplay, err = storage.CheckAndStore(ctx, jti, time.Minute)
	require.NoError(t, err)
	assert.True(t, isReplay, "Second use must be replay")
}

// ---------------------------------------------------------------------------
// Revocation & Rotation Tests
// ---------------------------------------------------------------------------

func TestRedis_Revocation(t *testing.T) {
	_, storage := setupRedis(t)
	ctx := context.Background()
	jti := "access-token-id"

	// Initial
	revoked, _ := storage.IsRevoked(ctx, jti)
	assert.False(t, revoked)

	// Revoke
	err := storage.Revoke(ctx, jti, time.Now().Add(time.Hour))
	require.NoError(t, err)

	// Check
	revoked, _ = storage.IsRevoked(ctx, jti)
	assert.True(t, revoked)
}

func TestRedis_TokenRotation_GracePeriod(t *testing.T) {
	s, storage := setupRedis(t)
	ctx := context.Background()
	tokenID := oidc.RefreshToken("raw").HashForDB()

	// Initial
	inGrace, _ := storage.IsInGracePeriod(ctx, tokenID)
	assert.False(t, inGrace)

	// Mark
	err := storage.MarkRefreshTokenAsRotating(ctx, tokenID, 10*time.Second)
	require.NoError(t, err)

	// Check
	inGrace, _ = storage.IsInGracePeriod(ctx, tokenID)
	assert.True(t, inGrace)

	// Expire
	s.FastForward(11 * time.Second)
	inGrace, _ = storage.IsInGracePeriod(ctx, tokenID)
	assert.False(t, inGrace)
}

// ---------------------------------------------------------------------------
// Distributed Lock Tests
// ---------------------------------------------------------------------------

func TestRedis_Lock(t *testing.T) {
	_, storage := setupRedis(t)
	ctx := context.Background()
	key := "my-lock"

	// 1. Acquire
	acquired, err := storage.Lock(ctx, key, time.Minute)
	require.NoError(t, err)
	assert.True(t, acquired)

	// 2. Acquire again (Fail)
	acquired, err = storage.Lock(ctx, key, time.Minute)
	require.NoError(t, err)
	assert.False(t, acquired)

	// 3. Unlock
	err = storage.Unlock(ctx, key)
	require.NoError(t, err)

	// 4. Acquire again (Success)
	acquired, err = storage.Lock(ctx, key, time.Minute)
	require.NoError(t, err)
	assert.True(t, acquired)
}

// ---------------------------------------------------------------------------
// KeyStorage Tests
// ---------------------------------------------------------------------------

func TestRedis_KeyStorage(t *testing.T) {
	_, storage := setupRedis(t)
	ctx := context.Background()

	// Create a JWK
	rawKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	key, _ := jwk.FromRaw(rawKey)
	key.Set(jwk.KeyIDKey, "key-1")

	// 1. Save
	err := storage.Save(ctx, key)
	require.NoError(t, err)

	// 2. Get
	got, err := storage.Get(ctx, "key-1")
	require.NoError(t, err)
	assert.Equal(t, "key-1", got.KeyID())

	// 3. List
	// Add another key
	key2, _ := jwk.FromRaw(rawKey)
	key2.Set(jwk.KeyIDKey, "key-2")
	storage.Save(ctx, key2)

	list, err := storage.List(ctx)
	require.NoError(t, err)
	assert.Len(t, list, 2)

	// 4. Signing Key ID
	err = storage.SaveSigningKeyID(ctx, "key-1")
	require.NoError(t, err)
	kid, err := storage.GetSigningKeyID(ctx)
	assert.Equal(t, "key-1", kid)

	// 5. Delete
	err = storage.Delete(ctx, "key-1")
	require.NoError(t, err)
	_, err = storage.Get(ctx, "key-1")
	assert.ErrorIs(t, err, oidc.ErrKeyNotFound)
}

// ---------------------------------------------------------------------------
// TokenCache Tests (Simple serialization check)
// ---------------------------------------------------------------------------

func TestRedis_TokenCache(t *testing.T) {
	_, storage := setupRedis(t)
	ctx := context.Background()

	tokenID := oidc.RefreshToken("raw").HashForDB()
	session := &oidc.RefreshTokenSession{
		ID:       tokenID,
		ClientID: oidc.BinaryUUID(uuid.New()),
		UserID:   oidc.BinaryUUID(uuid.New()),
		Scope:    "openid",
	}

	// Save
	err := storage.SaveRefreshToken(ctx, session, time.Minute)
	require.NoError(t, err)

	// Get
	got, err := storage.GetRefreshToken(ctx, tokenID)
	require.NoError(t, err)
	assert.Equal(t, session.UserID, got.UserID)

	// Invalidate
	err = storage.InvalidateRefreshToken(ctx, tokenID)
	require.NoError(t, err)

	_, err = storage.GetRefreshToken(ctx, tokenID)
	assert.ErrorIs(t, err, oidc.ErrTokenNotFound)
}
