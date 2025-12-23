package oidc_test

import (
	"context"
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/oy3o/oidc"
	"github.com/oy3o/oidc/cache"
	"github.com/oy3o/oidc/persist"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type clientFactory struct{}

func (f *clientFactory) New() oidc.RegisteredClient {
	return &oidc.ClientMetadata{}
}

func NewTestCache(t *testing.T) (oidc.Cache, *miniredis.Miniredis) {
	s := miniredis.RunT(t)

	rdb := redis.NewClient(&redis.Options{
		Addr: s.Addr(),
	})
	return cache.NewRedis(rdb, &clientFactory{}), s
}

// NewTestDB 获取全局的 Pool，并清空数据
func NewTestDB(t *testing.T) oidc.Persistence {
	if TestPool == nil {
		t.Fatal("Global test pool is not initialized. TestMain failed to run?")
	}

	// 每次测试前清空表，保证测试隔离性 (TRUNCATE 速度极快)
	// CASCADE 会自动处理外键依赖
	_, err := TestPool.Exec(context.Background(), `
		TRUNCATE users, profiles, credentials, oidc_clients, 
		oidc_auth_codes, oidc_device_codes, oidc_refresh_tokens, jwks 
		CASCADE
	`)
	require.NoError(t, err, "failed to clean database")

	hasher := &mockHasher{}
	return persist.NewPgx(TestPool, hasher)
}

func NewTestStorage(t *testing.T) (*oidc.TieredStorage, *miniredis.Miniredis) {
	rdb, s := NewTestCache(t)
	return oidc.NewTieredStorage(NewTestDB(t), rdb), s
}

func TestTieredStorage_ClientGetByID(t *testing.T) {
	cache, _ := NewTestCache(t)
	db := NewTestDB(t)
	storage := oidc.NewTieredStorage(db, cache)
	ctx := context.Background()

	clientID := oidc.BinaryUUID{0x01} // Simplified UUID
	clientMeta := &oidc.ClientMetadata{
		ID:                   clientID,
		RedirectURIs:         []string{"http://example.com"},
		IsConfidentialClient: true,
		Secret:               "hashed_secret",
	}

	// 1. Setup: Create client in DB only
	_, err := db.ClientCreate(ctx, clientMeta)
	assert.NoError(t, err)

	// 2. Test: ClientGetByID should hit DB and populate Cache
	client, err := storage.ClientGetByID(ctx, clientID)
	assert.NoError(t, err)
	assert.NotNil(t, client)
	assert.Equal(t, clientID, client.GetID())

	// Verify Cache is populated
	cachedClient, err := cache.ClientGetByID(ctx, clientID)
	// Note: MockStorage.ClientGetByID might return ErrClientNotFound if ClientCache didn't work as expected
	// (we implemented ClientCache in MockStorage to store in map)
	assert.NoError(t, err)
	assert.NotNil(t, cachedClient)
	assert.Equal(t, clientID, cachedClient.GetID())

	// 3. Test: ClientGetByID from Cache
	// Modify DB to ensure we are reading from Cache
	// (In a real mock, we could clear DB, but here we can just modify the cached object if it's a pointer,
	// but MockStorage stores pointers. Let's modify the cached object directly via cache interface if possible,
	// or modify DB and expect old value if cache is hit.)

	// Let's delete from DB and see if we can still get it (Cache Hit)
	err = db.ClientDeleteByID(ctx, clientID)
	assert.NoError(t, err)

	clientFromCache, err := storage.ClientGetByID(ctx, clientID)
	assert.NoError(t, err)
	assert.NotNil(t, clientFromCache)
	assert.Equal(t, clientID, clientFromCache.GetID())
}

func TestTieredStorage_ClientCreate(t *testing.T) {
	cache, _ := NewTestCache(t)
	db := NewTestDB(t)
	storage := oidc.NewTieredStorage(db, cache)
	ctx := context.Background()

	clientID := oidc.BinaryUUID{0x02}
	clientMeta := &oidc.ClientMetadata{
		ID: clientID,
	}

	// 1. Create Client
	_, err := storage.ClientCreate(ctx, clientMeta)
	assert.NoError(t, err)

	// 2. Verify DB
	dbClient, err := db.ClientGetByID(ctx, clientID)
	assert.NoError(t, err)
	assert.NotNil(t, dbClient)

	// 3. Verify Cache (Write-Through)
	cacheClient, err := cache.ClientGetByID(ctx, clientID)
	assert.NoError(t, err)
	assert.NotNil(t, cacheClient)
}

func TestTieredStorage_ClientDeleteByID(t *testing.T) {
	cache, _ := NewTestCache(t)
	db := NewTestDB(t)
	storage := oidc.NewTieredStorage(db, cache)
	ctx := context.Background()

	clientID := oidc.BinaryUUID{0x04}
	clientMeta := &oidc.ClientMetadata{ID: clientID}
	storage.ClientCreate(ctx, clientMeta)

	// JWKDelete
	err := storage.ClientDeleteByID(ctx, clientID)
	assert.NoError(t, err)

	// Verify DB deleted
	_, err = db.ClientGetByID(ctx, clientID)
	assert.Error(t, err)

	// Verify Cache deleted
	_, err = cache.ClientGetByID(ctx, clientID)
	assert.Error(t, err) // Should be not found
}

func TestTieredStorage_ClientUpdate(t *testing.T) {
	cache, _ := NewTestCache(t)
	db := NewTestDB(t)
	storage := oidc.NewTieredStorage(db, cache)
	ctx := context.Background()

	clientID := oidc.BinaryUUID{0x03}
	clientMeta := &oidc.ClientMetadata{ID: clientID, Scope: "scope1"}

	_, err := storage.ClientCreate(ctx, clientMeta)
	assert.NoError(t, err)

	// Update
	newMeta := &oidc.ClientMetadata{ID: clientID, Scope: "scope2"}
	_, err = storage.ClientUpdate(ctx, newMeta)
	assert.NoError(t, err)

	// Verify DB
	dbClient, _ := db.ClientGetByID(ctx, clientID)
	assert.Equal(t, "scope2", dbClient.GetScope())

	// Verify Cache
	cacheClient, _ := storage.ClientGetByID(ctx, clientID)
	assert.Equal(t, "scope2", cacheClient.GetScope())
}
