package oidc_test

import (
	"context"
	"testing"

	"github.com/oy3o/oidc"
	"github.com/stretchr/testify/assert"
)

func NewTestCache(t *testing.T) (oidc.Cache, *MockStorage) {
	s := NewMockStorage()
	return s, s
}

func NewTestDB(t *testing.T) oidc.Persistence {
	return NewMockStorage()
}

func NewTestStorage(t *testing.T) (*oidc.TieredStorage, *MockStorage) {
	c, mockC := NewTestCache(t)
	db := NewTestDB(t)
	return oidc.NewTieredStorage(db, c), mockC
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
	assert.NoError(t, err)
	assert.NotNil(t, cachedClient)
	assert.Equal(t, clientID, cachedClient.GetID())

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

	// Delete
	err := storage.ClientDeleteByID(ctx, clientID)
	assert.NoError(t, err)

	// Verify DB deleted
	_, err = db.ClientGetByID(ctx, clientID)
	assert.Error(t, err)

	// Verify Cache deleted
	_, err = cache.ClientGetByID(ctx, clientID)
	assert.Error(t, err)
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
