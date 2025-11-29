package oidc_test

import (
	"context"
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/oy3o/oidc"
	oidc_gorm "github.com/oy3o/oidc/gorm"
	oidc_redis "github.com/oy3o/oidc/redis"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

type clientFactory struct{}

func (f *clientFactory) New() oidc.RegisteredClient {
	return &oidc_gorm.ClientModel{}
}

func NewTestCache(t *testing.T) oidc.Cache {
	s := miniredis.RunT(t)

	rdb := redis.NewClient(&redis.Options{
		Addr: s.Addr(),
	})
	return oidc_redis.NewRedisStorage(rdb, &clientFactory{})
}

func NewTestDB() oidc.Persistence {
	db, _ := gorm.Open(sqlite.Open("file::memory:"), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})

	hasher := &mockHasher{}
	storage := oidc_gorm.NewGormStorage(db, hasher, true)
	db.AutoMigrate(
		&oidc_gorm.ClientModel{},
		&oidc_gorm.AuthCodeModel{},
		&oidc_gorm.RefreshTokenModel{},
		&oidc_gorm.BlacklistModel{},
		&oidc_gorm.DeviceCodeModel{},
		&oidc_gorm.UserModel{},
		&oidc_gorm.PARModel{},
		&oidc_gorm.KeyModel{},
		&oidc_gorm.LockModel{},
	)
	return storage
}

func NewTestStorage(t *testing.T) oidc.Storage {
	return oidc.NewTieredStorage(NewTestDB(), NewTestCache(t))
}

func TestTieredStorage_GetClient(t *testing.T) {
	cache := NewTestCache(t)
	db := NewTestDB()
	storage := oidc.NewTieredStorage(db, cache)
	ctx := context.Background()

	clientID := oidc.BinaryUUID{0x01} // Simplified UUID
	clientMeta := oidc.ClientMetadata{
		ID:             clientID,
		RedirectURIs:   []string{"http://example.com"},
		IsConfidential: true,
		Secret:         "hashed_secret",
	}

	// 1. Setup: Create client in DB only
	_, err := db.CreateClient(ctx, clientMeta)
	assert.NoError(t, err)

	// 2. Test: GetClient should hit DB and populate Cache
	client, err := storage.GetClient(ctx, clientID)
	assert.NoError(t, err)
	assert.NotNil(t, client)
	assert.Equal(t, clientID, client.GetID())

	// Verify Cache is populated
	cachedClient, err := cache.GetClient(ctx, clientID)
	// Note: MockStorage.GetClient might return ErrClientNotFound if SaveClient didn't work as expected
	// (we implemented SaveClient in MockStorage to store in map)
	assert.NoError(t, err)
	assert.NotNil(t, cachedClient)
	assert.Equal(t, clientID, cachedClient.GetID())

	// 3. Test: GetClient from Cache
	// Modify DB to ensure we are reading from Cache
	// (In a real mock, we could clear DB, but here we can just modify the cached object if it's a pointer,
	// but MockStorage stores pointers. Let's modify the cached object directly via cache interface if possible,
	// or modify DB and expect old value if cache is hit.)

	// Let's delete from DB and see if we can still get it (Cache Hit)
	err = db.DeleteClient(ctx, clientID)
	assert.NoError(t, err)

	clientFromCache, err := storage.GetClient(ctx, clientID)
	assert.NoError(t, err)
	assert.NotNil(t, clientFromCache)
	assert.Equal(t, clientID, clientFromCache.GetID())
}

func TestTieredStorage_CreateClient(t *testing.T) {
	cache := NewTestCache(t)
	db := NewTestDB()
	storage := oidc.NewTieredStorage(db, cache)
	ctx := context.Background()

	clientID := oidc.BinaryUUID{0x02}
	clientMeta := oidc.ClientMetadata{
		ID: clientID,
	}

	// 1. Create Client
	_, err := storage.CreateClient(ctx, clientMeta)
	assert.NoError(t, err)

	// 2. Verify DB
	dbClient, err := db.GetClient(ctx, clientID)
	assert.NoError(t, err)
	assert.NotNil(t, dbClient)

	// 3. Verify Cache (Write-Through)
	cacheClient, err := cache.GetClient(ctx, clientID)
	assert.NoError(t, err)
	assert.NotNil(t, cacheClient)
}

func TestTieredStorage_DeleteClient(t *testing.T) {
	cache := NewTestCache(t)
	db := NewTestDB()
	storage := oidc.NewTieredStorage(db, cache)
	ctx := context.Background()

	clientID := oidc.BinaryUUID{0x04}
	clientMeta := oidc.ClientMetadata{ID: clientID}
	storage.CreateClient(ctx, clientMeta)

	// Delete
	err := storage.DeleteClient(ctx, clientID)
	assert.NoError(t, err)

	// Verify DB deleted
	_, err = db.GetClient(ctx, clientID)
	assert.Error(t, err)

	// Verify Cache deleted
	_, err = cache.GetClient(ctx, clientID)
	assert.Error(t, err) // Should be not found
}

func TestTieredStorage_UpdateClient(t *testing.T) {
	cache := NewTestCache(t)
	db := NewTestDB()
	storage := oidc.NewTieredStorage(db, cache)
	ctx := context.Background()

	clientID := oidc.BinaryUUID{0x03}
	clientMeta := oidc.ClientMetadata{ID: clientID, Scope: "scope1"}

	_, err := storage.CreateClient(ctx, clientMeta)
	assert.NoError(t, err)

	// Update
	newMeta := oidc.ClientMetadata{ID: clientID, Scope: "scope2"}
	_, err = storage.UpdateClient(ctx, clientID, newMeta)
	assert.NoError(t, err)

	// Verify DB
	dbClient, _ := db.GetClient(ctx, clientID)
	assert.Equal(t, "scope2", dbClient.GetScope())

	// Verify Cache
	cacheClient, _ := storage.GetClient(ctx, clientID)
	assert.Equal(t, "scope2", cacheClient.GetScope())
}
