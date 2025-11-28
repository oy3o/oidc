package gorm_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"github.com/bytedance/sonic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/oy3o/oidc"
	oidcgorm "github.com/oy3o/oidc/gorm"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// -----------------------------------------------------------------------------
// Helpers & Setup
// -----------------------------------------------------------------------------

// mockHasher 用于测试的简单哈希器 (复用自 authorize_test.go)
type mockHasher struct{}

func (m *mockHasher) Hash(ctx context.Context, password []byte) ([]byte, error) {
	return []byte("hashed_" + string(password)), nil
}

func (m *mockHasher) Compare(ctx context.Context, hashedPassword []byte, password []byte) error {
	if string(hashedPassword) == "hashed_"+string(password) {
		return nil
	}
	return oidc.ErrInvalidGrant
}

func setupGormStorage(t *testing.T) (*oidcgorm.GormStorage, *gorm.DB) {
	// 使用内存数据库
	db, err := gorm.Open(sqlite.Open("file::memory:?cache=shared"), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	require.NoError(t, err)

	hasher := &mockHasher{}
	storage := oidcgorm.NewGormStorage(db, hasher, true)

	// Verify migration success to ensure tables exist
	err = db.AutoMigrate(
		&oidcgorm.ClientModel{},
		&oidcgorm.AuthCodeModel{},
		&oidcgorm.RefreshTokenModel{},
		&oidcgorm.BlacklistModel{},
		&oidcgorm.DeviceCodeModel{},
		&oidcgorm.UserModel{},
		&oidcgorm.PARModel{},
		&oidcgorm.KeyModel{},
		&oidcgorm.LockModel{},
	)
	require.NoError(t, err, "AutoMigrate failed")

	return storage, db
}

func newBinaryUUID() oidc.BinaryUUID {
	return oidc.BinaryUUID(uuid.New())
}

// -----------------------------------------------------------------------------
// ClientStorage Tests
// -----------------------------------------------------------------------------

func TestGormStorage_Client(t *testing.T) {
	s, _ := setupGormStorage(t)
	ctx := context.Background()

	clientID := newBinaryUUID()
	metadata := oidc.ClientMetadata{
		ID:                      clientID,
		OwnerID:                 newBinaryUUID(),
		Secret:                  "hashed_secret",
		RedirectURIs:            []string{"https://client.com/cb"},
		GrantTypes:              []string{"authorization_code"},
		Scope:                   "openid profile",
		Name:                    "Test Client",
		IsConfidential:          true,
		TokenEndpointAuthMethod: "client_secret_basic",
		CreatedAt:               time.Now(),
	}

	// 1. Create
	client, err := s.CreateClient(ctx, metadata)
	require.NoError(t, err)
	assert.Equal(t, clientID, client.GetID())
	assert.True(t, client.IsConfidential())
	assert.Equal(t, []string{"https://client.com/cb"}, client.GetRedirectURIs())

	// 2. Get
	got, err := s.GetClient(ctx, clientID)
	require.NoError(t, err)
	assert.Equal(t, "Test Client", got.(*oidcgorm.ClientModel).Name)

	// 3. Update
	metadata.Name = "Updated Client"
	metadata.RedirectURIs = []string{"https://new.com"}
	updated, err := s.UpdateClient(ctx, clientID, metadata)
	require.NoError(t, err)
	assert.Equal(t, "Updated Client", updated.(*oidcgorm.ClientModel).Name)
	assert.Equal(t, []string{"https://new.com"}, updated.GetRedirectURIs())

	// 4. Validate Secret (Logic inside Model/Storage interaction)
	// mockHasher expects "hashed_" + input
	err = got.ValidateSecret(ctx, &mockHasher{}, "secret")
	assert.NoError(t, err)

	// 5. Delete
	err = s.DeleteClient(ctx, clientID)
	require.NoError(t, err)

	_, err = s.GetClient(ctx, clientID)
	assert.ErrorIs(t, err, oidc.ErrClientNotFound)
}

// -----------------------------------------------------------------------------
// TokenStorage Tests
// -----------------------------------------------------------------------------

func TestGormStorage_RefreshToken(t *testing.T) {
	s, _ := setupGormStorage(t)
	ctx := context.Background()

	tokenID := oidc.RefreshToken("raw_token").HashForDB()
	session := &oidc.RefreshTokenSession{
		ID:        tokenID,
		ClientID:  newBinaryUUID(),
		UserID:    newBinaryUUID(),
		Scope:     "openid",
		ExpiresAt: time.Now().Add(24 * time.Hour),
	}

	// 1. Create
	err := s.CreateRefreshToken(ctx, session)
	require.NoError(t, err)

	// 2. Get
	got, err := s.GetRefreshToken(ctx, tokenID)
	require.NoError(t, err)
	assert.Equal(t, session.UserID, got.UserID)

	// 3. Rotate
	newTokenID := oidc.RefreshToken("new_token").HashForDB()
	newSession := &oidc.RefreshTokenSession{
		ID:        newTokenID,
		ClientID:  session.ClientID,
		UserID:    session.UserID,
		ExpiresAt: time.Now().Add(24 * time.Hour),
	}

	err = s.RotateRefreshToken(ctx, tokenID, newSession)
	require.NoError(t, err)

	// Old should be gone
	_, err = s.GetRefreshToken(ctx, tokenID)
	assert.ErrorIs(t, err, oidc.ErrTokenNotFound)

	// New should exist
	gotNew, err := s.GetRefreshToken(ctx, newTokenID)
	require.NoError(t, err)
	assert.Equal(t, newTokenID, gotNew.ID)

	// 4. Revoke
	err = s.RevokeRefreshToken(ctx, newTokenID)
	require.NoError(t, err)
	_, err = s.GetRefreshToken(ctx, newTokenID)
	assert.ErrorIs(t, err, oidc.ErrTokenNotFound)
}

func TestGormStorage_RevokeTokensForUser(t *testing.T) {
	s, _ := setupGormStorage(t)
	ctx := context.Background()
	userID := newBinaryUUID()

	// Create 2 tokens for user
	t1 := oidc.RefreshToken("t1").HashForDB()
	t2 := oidc.RefreshToken("t2").HashForDB()
	s.CreateRefreshToken(ctx, &oidc.RefreshTokenSession{ID: t1, UserID: userID, ExpiresAt: time.Now().Add(time.Hour)})
	s.CreateRefreshToken(ctx, &oidc.RefreshTokenSession{ID: t2, UserID: userID, ExpiresAt: time.Now().Add(time.Hour)})

	// Revoke
	err := s.RevokeTokensForUser(ctx, userID)
	require.NoError(t, err)

	_, err = s.GetRefreshToken(ctx, t1)
	assert.ErrorIs(t, err, oidc.ErrTokenNotFound)
	_, err = s.GetRefreshToken(ctx, t2)
	assert.ErrorIs(t, err, oidc.ErrTokenNotFound)
}

// -----------------------------------------------------------------------------
// KeyStorage Tests
// -----------------------------------------------------------------------------

func TestGormStorage_Key(t *testing.T) {
	s, _ := setupGormStorage(t)
	ctx := context.Background()

	// Create a real JWK
	rawKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	key, _ := jwk.FromRaw(rawKey)
	key.Set(jwk.KeyIDKey, "key-1")

	// 1. Save
	err := s.Save(ctx, key)
	require.NoError(t, err)

	// 2. Get
	got, err := s.Get(ctx, "key-1")
	require.NoError(t, err)
	assert.Equal(t, "key-1", got.KeyID())

	// 3. List
	list, err := s.List(ctx)
	require.NoError(t, err)
	assert.Len(t, list, 1)

	// 4. Signing Key ID
	err = s.SaveSigningKeyID(ctx, "key-1")
	require.NoError(t, err)

	kid, err := s.GetSigningKeyID(ctx)
	require.NoError(t, err)
	assert.Equal(t, "key-1", kid)

	// 5. Delete
	err = s.Delete(ctx, "key-1")
	require.NoError(t, err)
	_, err = s.Get(ctx, "key-1")
	assert.ErrorIs(t, err, oidc.ErrKeyNotFound)
}

// -----------------------------------------------------------------------------
// Type Mapping Tests (BinaryUUID & Hash256)
// -----------------------------------------------------------------------------

func TestGormTypes_JSON(t *testing.T) {
	// 验证 BinaryUUID 和 Hash256 的 JSON 序列化是否正确
	// (这对于前端展示和调试很重要，虽然存储是二进制，但 JSON 应该是字符串)

	// 1. BinaryUUID
	uid := newBinaryUUID()
	b, err := sonic.Marshal(uid)
	require.NoError(t, err)
	assert.Equal(t, `"`+uid.String()+`"`, string(b))

	var parsedUID oidc.BinaryUUID
	err = sonic.Unmarshal(b, &parsedUID)
	require.NoError(t, err)
	assert.Equal(t, uid, parsedUID)

	// 2. Hash256
	h := oidc.RefreshToken("foo").HashForDB()
	b, err = sonic.Marshal(h)
	require.NoError(t, err)
	// hex string length should be 64
	assert.Contains(t, string(b), `"`)
	assert.Len(t, string(b), 66) // " + 64 chars + "

	var parsedHash oidc.Hash256
	err = sonic.Unmarshal(b, &parsedHash)
	require.NoError(t, err)
	assert.Equal(t, h, parsedHash)
}
