package persist

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/oy3o/oidc"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
)

// 全局变量，整个测试套件生命周期内只初始化一次
var (
	testPool      *pgxpool.Pool
	testContainer *postgres.PostgresContainer
	poolOnce      sync.Once
)

// TestMain 控制测试的主入口，负责全局容器的启动和销毁
func TestMain(m *testing.M) {
	ctx := context.Background()

	// 1. 启动容器 (只启动一次)
	poolOnce.Do(func() {
		container, err := postgres.Run(
			ctx,
			"docker.io/postgres:18-alpine",
			postgres.WithInitScripts("./init.sql"),
			postgres.BasicWaitStrategies(),
		)
		if err != nil {
			fmt.Printf("failed to start container: %v\n", err)
			os.Exit(1)
		}
		testContainer = container

		// 2. 获取连接字符串
		connStr, err := container.ConnectionString(ctx, "sslmode=disable")
		if err != nil {
			fmt.Printf("failed to get connection string: %v\n", err)
			_ = container.Terminate(ctx)
			os.Exit(1)
		}

		// 3. 配置连接池
		dbConfig, err := pgxpool.ParseConfig(connStr)
		if err != nil {
			fmt.Printf("failed to parse config: %v\n", err)
			_ = container.Terminate(ctx)
			os.Exit(1)
		}
		dbConfig.MinConns = 1
		dbConfig.MaxConns = 10 // 稍微调大一点，避免测试并发不够

		pool, err := pgxpool.NewWithConfig(ctx, dbConfig)
		if err != nil {
			fmt.Printf("failed to create pool: %v\n", err)
			_ = container.Terminate(ctx)
			os.Exit(1)
		}
		testPool = pool

		// 等待数据库就绪
		if err := waitForDB(ctx, pool); err != nil {
			fmt.Printf("database not ready: %v\n", err)
			_ = container.Terminate(ctx)
			os.Exit(1)
		}
	})

	// 4. 运行所有测试
	code := m.Run()

	// 5. 清理资源
	testPool.Close()
	if err := testContainer.Terminate(ctx); err != nil {
		fmt.Printf("failed to terminate container: %v\n", err)
	}

	os.Exit(code)
}

// waitForDB 简单的重试逻辑
func waitForDB(ctx context.Context, pool *pgxpool.Pool) error {
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	timeout := time.After(5 * time.Second)

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timeout:
			return context.DeadlineExceeded
		case <-ticker.C:
			if err := pool.Ping(ctx); err == nil {
				return nil
			}
		}
	}
}

// NewTestDB 获取全局的 Pool，并清空数据
func NewTestDB(t *testing.T) oidc.Persistence {
	if testPool == nil {
		t.Fatal("Global test pool is not initialized. TestMain failed to run?")
	}

	// 每次测试前清空表，保证测试隔离性 (TRUNCATE 速度极快)
	// CASCADE 会自动处理外键依赖
	_, err := testPool.Exec(context.Background(), `
		TRUNCATE users, profiles, credentials, oidc_clients, 
		oidc_auth_codes, oidc_device_codes, oidc_refresh_tokens, jwks 
		CASCADE
	`)
	require.NoError(t, err, "failed to clean database")

	hasher := &mockHasher{}
	return NewPgx(testPool, hasher)
}

// mockHasher 用于测试的简单哈希器
type mockHasher struct{}

func (m *mockHasher) Hash(ctx context.Context, password []byte) ([]byte, error) {
	return password, nil // 测试时不进行实际哈希
}

func (m *mockHasher) Compare(ctx context.Context, hashedPassword []byte, password []byte) error {
	if string(hashedPassword) != string(password) {
		return oidc.ErrInvalidGrant
	}
	return nil
}

func TestUserLifecycle(t *testing.T) {
	p := NewTestDB(t)
	storage := p.(*PgxStorage)
	ctx := context.Background()

	// 1. Create User
	uid := oidc.BinaryUUID(uuid.New())
	user := &User{
		ID:     uid,
		Role:   RoleUser,
		Status: StatusActive,
	}
	creds := []*Credential{}
	profile := &Profile{
		UserID: uid,
		Name:   "Test User",
		Email:  strToPtr("test@example.com"),
	}

	err := storage.UserCreate(ctx, user, creds, profile)
	require.NoError(t, err)
	uid = user.ID

	// 2. Find User
	gotUser, err := storage.UserGetByID(ctx, uid)
	require.NoError(t, err)
	assert.Equal(t, user.ID, gotUser.ID)
	assert.Equal(t, user.Status, gotUser.Status)

	// 3. Find Profile
	gotProfile, err := storage.ProfileGetByUserID(ctx, uid)
	require.NoError(t, err)
	assert.Equal(t, "Test User", gotProfile.Name)
	assert.Equal(t, "test@example.com", *gotProfile.Email)

	// 4. Update User Status
	err = storage.UserUpdateStatus(ctx, uid, StatusSuspended)
	require.NoError(t, err)
	gotUser, err = storage.UserGetByID(ctx, uid)
	require.NoError(t, err)
	assert.Equal(t, StatusSuspended, gotUser.Status)

	// 5. Update Profile
	newEmail := "updated@example.com"
	gotProfile.Email = &newEmail
	err = storage.ProfileUpdate(ctx, gotProfile)
	require.NoError(t, err)
	gotProfile, err = storage.ProfileGetByUserID(ctx, uid)
	require.NoError(t, err)
	assert.Equal(t, newEmail, *gotProfile.Email)

	// 6. Delete User
	err = storage.UserDelete(ctx, uid)
	require.NoError(t, err)

	_, err = storage.UserGetByID(ctx, uid)
	assert.ErrorIs(t, err, ErrUserNotFound)
}

func TestCredentialLifecycle(t *testing.T) {
	p := NewTestDB(t)
	storage := p.(*PgxStorage)
	ctx := context.Background()

	// Create User first
	uid := oidc.BinaryUUID(uuid.New())
	user := &User{ID: uid, Role: RoleUser, Status: StatusActive}
	err := storage.UserCreate(ctx, user, nil, nil)
	require.NoError(t, err)
	uid = user.ID

	// 1. Create Credential
	cred := &Credential{
		UserID:     uid,
		Type:       CredentialTypePassword,
		Identifier: "testuser",
		Secret:     []byte("hashed_secret"),
		Verified:   true,
	}
	err = storage.CredentialCreate(ctx, cred)
	require.NoError(t, err)
	assert.NotZero(t, cred.ID)

	// 2. Find by Identifier
	gotCred, err := storage.CredentialGetByIdentifier(ctx, CredentialTypePassword, "testuser")
	require.NoError(t, err)
	assert.Equal(t, cred.UserID, gotCred.UserID)
	assert.Equal(t, cred.Secret, gotCred.Secret)

	// 3. Update Credential
	cred.Secret = []byte("new_secret")
	err = storage.CredentialUpdate(ctx, cred)
	require.NoError(t, err)
	gotCred, err = storage.CredentialGetByIdentifier(ctx, CredentialTypePassword, "testuser")
	require.NoError(t, err)
	assert.Equal(t, oidc.SecretBytes("new_secret"), gotCred.Secret)

	// 4. Delete Credential
	err = storage.CredentialDeleteByID(ctx, cred.ID)
	require.NoError(t, err)
	_, err = storage.CredentialGetByIdentifier(ctx, CredentialTypePassword, "testuser")
	assert.ErrorIs(t, err, ErrCredentialNotFound)
}

func TestClientLifecycle(t *testing.T) {
	p := NewTestDB(t)
	// ClientStorage methods are directly on Persistence interface
	ctx := context.Background()

	// 1. Create Client
	clientID := oidc.BinaryUUID(uuid.New())
	ownerID := oidc.BinaryUUID(uuid.New())
	metadata := &oidc.ClientMetadata{
		ID:                   clientID,
		OwnerID:              ownerID,
		Name:                 "Test Client",
		Secret:               "hashed_secret",
		RedirectURIs:         []string{"http://localhost/callback"},
		GrantTypes:           []string{"authorization_code"},
		Scope:                "openid profile",
		IsConfidentialClient: true,
	}

	created, err := p.ClientCreate(ctx, metadata)
	require.NoError(t, err)
	assert.Equal(t, clientID, created.GetID())

	// 2. Find Client
	gotClient, err := p.ClientGetByID(ctx, clientID)
	require.NoError(t, err)
	assert.Equal(t, "Test Client", gotClient.(*oidc.ClientMetadata).Name)

	// 3. List by Owner
	clients, err := p.ClientListByOwner(ctx, ownerID)
	require.NoError(t, err)
	assert.Len(t, clients, 1)

	// 4. Update Client
	metadata.Name = "Updated Client"
	updated, err := p.ClientUpdate(ctx, clientID, metadata)
	require.NoError(t, err)
	assert.Equal(t, "Updated Client", updated.(*oidc.ClientMetadata).Name)

	// 5. Delete Client
	err = p.ClientDeleteByID(ctx, clientID)
	require.NoError(t, err)
	_, err = p.ClientGetByID(ctx, clientID)
	assert.ErrorIs(t, err, oidc.ErrClientNotFound)
}

func TestJWKLifecycle(t *testing.T) {
	p := NewTestDB(t)
	ctx := context.Background()

	// 1. Save JWK
	rawKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	key, err := jwk.FromRaw(rawKey)
	require.NoError(t, err)

	err = key.Set(jwk.KeyIDKey, "test-kid")
	require.NoError(t, err)

	err = p.JWKSave(ctx, key)
	require.NoError(t, err)

	// 2. Get JWK
	gotKey, err := p.JWKGet(ctx, "test-kid")
	require.NoError(t, err)
	assert.Equal(t, key.KeyID(), gotKey.KeyID())

	// 3. List JWKs
	keys, err := p.JWKList(ctx)
	require.NoError(t, err)
	assert.NotEmpty(t, keys)

	// 4. Mark Signing
	err = p.JWKMarkSigning(ctx, "test-kid")
	require.NoError(t, err)
	kid, err := p.JWKGetSigning(ctx)
	require.NoError(t, err)
	assert.Equal(t, "test-kid", kid)

	// 5. Delete JWK
	err = p.JWKDelete(ctx, "test-kid")
	require.NoError(t, err)
	_, err = p.JWKGet(ctx, "test-kid")
	assert.ErrorIs(t, err, oidc.ErrKeyNotFound)
}

func TestRefreshTokenLifecycle(t *testing.T) {
	p := NewTestDB(t)
	ctx := context.Background()

	id := uuid.New()
	tokenID := make(oidc.Hash256, 32)
	copy(tokenID, id[:])

	session := &oidc.RefreshTokenSession{
		ID:        tokenID,
		ClientID:  oidc.BinaryUUID(uuid.New()),
		UserID:    oidc.BinaryUUID(uuid.New()),
		Scope:     "openid",
		ExpiresAt: time.Now().Add(1 * time.Hour),
	}

	err := p.RefreshTokenCreate(ctx, session)
	require.NoError(t, err)

	// 2. Get RefreshToken
	gotSession, err := p.RefreshTokenGet(ctx, tokenID)
	require.NoError(t, err)
	assert.Equal(t, session.ID, gotSession.ID)

	// 3. Rotate RefreshToken
	newId := uuid.New()
	newTokenID := make(oidc.Hash256, 32)
	copy(newTokenID, newId[:])

	newSession := *session
	newSession.ID = newTokenID

	err = p.RefreshTokenRotate(ctx, tokenID, &newSession, 0)
	require.NoError(t, err)

	_, err = p.RefreshTokenGet(ctx, tokenID) // Old should be gone
	assert.ErrorIs(t, err, oidc.ErrTokenNotFound)

	gotNewSession, err := p.RefreshTokenGet(ctx, newTokenID)
	require.NoError(t, err)
	assert.Equal(t, newTokenID, gotNewSession.ID)

	// 4. Revoke
	err = p.RefreshTokenRevoke(ctx, newTokenID)
	require.NoError(t, err)
	_, err = p.RefreshTokenGet(ctx, newTokenID)
	assert.ErrorIs(t, err, oidc.ErrTokenNotFound)
}
