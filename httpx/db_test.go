package httpx_test

import (
	"context"
	"fmt"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"

	"github.com/google/uuid"
	"github.com/oy3o/o11y"
	"github.com/oy3o/oidc"
	"github.com/oy3o/oidc/cache"
	"github.com/oy3o/oidc/persist"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
)

type clientFactory struct{}

func (f *clientFactory) New() oidc.RegisteredClient {
	return &oidc.ClientMetadata{}
}

// 全局变量，整个测试套件生命周期内只初始化一次
var (
	TestPool      *pgxpool.Pool
	TestContainer *postgres.PostgresContainer
	PoolOnce      sync.Once
)

// TestMain 控制测试的主入口，负责全局容器的启动和销毁
func TestMain(m *testing.M) {
	ctx := context.Background()
	cfg := o11y.Config{
		Enabled:     true,
		Service:     "oidc-httpx-test",
		Environment: "test",
		Log: o11y.LogConfig{
			Level:         "fatal", // 减少噪音
			EnableConsole: false,
		},
		Trace:  o11y.TraceConfig{Enabled: false, Exporter: "none"},
		Metric: o11y.MetricConfig{Enabled: false},
	}
	shutdown, _ := o11y.Init(cfg)

	// 1. 启动容器 (只启动一次)
	PoolOnce.Do(func() {
		container, err := postgres.Run(
			ctx,
			"docker.io/postgres:18-trixie",
			postgres.WithInitScripts("../persist/init.sql"),
			postgres.BasicWaitStrategies(),
		)
		if err != nil {
			fmt.Printf("failed to start container: %v\n", err)
			os.Exit(1)
		}
		TestContainer = container

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
		TestPool = pool

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
	TestPool.Close()
	if err := TestContainer.Terminate(ctx); err != nil {
		fmt.Printf("failed to terminate container: %v\n", err)
	}

	shutdown(context.Background())
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

// setupServer 创建一个完全配置的 OIDC Server 用于测试
func setupServer(t *testing.T) (*oidc.Server, oidc.Storage, oidc.RegisteredClient) {
	storage, _ := NewTestStorage(t)
	hasher := &mockHasher{}

	// 1. 初始化 Secret Manager
	sm := oidc.NewSecretManager()
	err := sm.AddKey("hmac-key-1", "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff")
	require.NoError(t, err)

	// 2. 创建 Server
	cfg := oidc.ServerConfig{
		Issuer:         "https://auth.example.com",
		Storage:        storage,
		Hasher:         hasher,
		SecretManager:  sm,
		AccessTokenTTL: 1 * time.Hour,
	}
	server, err := oidc.NewServer(cfg)
	require.NoError(t, err)

	// 3. 生成签名密钥 (必须步骤)
	_, err = server.KeyManager().Generate(context.Background(), oidc.KEY_RSA, true)
	require.NoError(t, err)

	// 4. 创建一个测试客户端
	clientID := oidc.BinaryUUID(uuid.New())
	clientMeta := &oidc.ClientMetadata{
		ID:                      clientID,
		RedirectURIs:            []string{"https://client.com/cb"},
		GrantTypes:              []string{"authorization_code", "client_credentials"},
		Scope:                   "openid profile",
		Name:                    "HTTPX Test Client",
		IsConfidentialClient:    true,
		Secret:                  "hashed_test_secret",
		TokenEndpointAuthMethod: "client_secret_basic",
	}
	client, err := storage.ClientCreate(context.Background(), clientMeta)
	require.NoError(t, err)

	return server, storage, client
}

// mockHasher 简单哈希实现
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
