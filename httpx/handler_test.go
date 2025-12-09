package httpx_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/bytedance/sonic"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"

	"github.com/google/uuid"
	"github.com/oy3o/o11y"
	"github.com/oy3o/oidc"
	"github.com/oy3o/oidc/cache"
	"github.com/oy3o/oidc/httpx"
	"github.com/oy3o/oidc/persist"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
)

type clientFactory struct{}

func (f *clientFactory) New() oidc.RegisteredClient {
	return &oidc.ClientMetadata{}
}

func NewTestCache(t *testing.T) oidc.Cache {
	s := miniredis.RunT(t)

	rdb := redis.NewClient(&redis.Options{
		Addr: s.Addr(),
	})
	return cache.NewRedis(rdb, &clientFactory{})
}

// 全局变量，整个测试套件生命周期内只初始化一次
var (
	testPool      *pgxpool.Pool
	testContainer *postgres.PostgresContainer
	poolOnce      sync.Once
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
	poolOnce.Do(func() {
		container, err := postgres.Run(
			ctx,
			"docker.io/postgres:18-alpine",
			postgres.WithInitScripts("../persist/init.sql"),
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
	return persist.NewPgx(testPool, hasher)
}

func NewTestStorage(t *testing.T) oidc.Storage {
	return oidc.NewTieredStorage(NewTestDB(t), NewTestCache(t))
}

// setupServer 创建一个完全配置的 OIDC Server 用于测试
func setupServer(t *testing.T) (*oidc.Server, oidc.Storage, oidc.RegisteredClient) {
	storage := NewTestStorage(t)
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

// -----------------------------------------------------------------------------
// Discovery & JWKS Tests (CORS Check)
// -----------------------------------------------------------------------------

func TestDiscoveryHandler(t *testing.T) {
	server, _, _ := setupServer(t)
	handler := httpx.DiscoveryHandler(server)

	req := httptest.NewRequest("GET", "/.well-known/openid-configuration", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "*", w.Header().Get("Access-Control-Allow-Origin"))

	var disco oidc.Discovery
	err := sonic.Unmarshal(w.Body.Bytes(), &disco)
	require.NoError(t, err)
	assert.Equal(t, "https://auth.example.com", disco.Issuer)
	assert.Equal(t, "https://auth.example.com/token", disco.TokenEndpoint)
}

func TestJWKSHandler(t *testing.T) {
	server, _, _ := setupServer(t)
	handler := httpx.JWKSHandler(server)

	req := httptest.NewRequest("GET", "/jwks.json", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	// 1. 验证状态码
	assert.Equal(t, http.StatusOK, w.Code)

	// 2. [关键] 验证 CORS 头
	assert.Equal(t, "*", w.Header().Get("Access-Control-Allow-Origin"))
	assert.Contains(t, w.Header().Get("Cache-Control"), "max-age")

	// 3. 验证 JWKS 结构
	var jwks oidc.JSONWebKeySet
	err := sonic.Unmarshal(w.Body.Bytes(), &jwks)
	require.NoError(t, err)
	assert.NotEmpty(t, jwks.Keys)
	assert.Equal(t, "RSA", jwks.Keys[0].Kty)
}

// -----------------------------------------------------------------------------
// Token Handler Tests (Error Unwrapping Check)
// -----------------------------------------------------------------------------

func TestTokenHandler_ErrorHandling(t *testing.T) {
	server, _, _ := setupServer(t)
	handler := httpx.TokenHandler(server)

	v := url.Values{}
	v.Set("grant_type", "unknown_grant")
	v.Set("client_id", "test-client") // 确保通过 Bind 校验，进入 Exchange 逻辑

	req := httptest.NewRequest("POST", "/token", strings.NewReader(v.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	var errResp oidc.Error
	sonic.Unmarshal(w.Body.Bytes(), &errResp)
	assert.Equal(t, "unsupported_grant_type", errResp.Code)
}

func TestTokenHandler_ClientCredentials(t *testing.T) {
	server, _, client := setupServer(t)
	handler := httpx.TokenHandler(server)

	v := url.Values{}
	v.Set("grant_type", "client_credentials")
	v.Set("client_id", client.GetID().String())
	v.Set("client_secret", "test_secret")
	v.Set("scope", "openid")

	req := httptest.NewRequest("POST", "/token", strings.NewReader(v.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	var tokenResp oidc.IssuerResponse
	sonic.Unmarshal(w.Body.Bytes(), &tokenResp)
	assert.NotEmpty(t, tokenResp.AccessToken)
	assert.Equal(t, "Bearer", tokenResp.TokenType)
}

// -----------------------------------------------------------------------------
// Middleware Tests (RFC 6750 Compliance Check)
// -----------------------------------------------------------------------------

func TestAuthenticationMiddleware_Compliance(t *testing.T) {
	server, _, client := setupServer(t)
	mw := httpx.AuthenticationMiddleware(server)

	protectedHandler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		claims, err := httpx.GetClaims(r.Context())
		require.NoError(t, err)
		assert.NotEmpty(t, claims.Subject)
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("success"))
	}))

	t.Run("Missing Header", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api", nil)
		w := httptest.NewRecorder()
		protectedHandler.ServeHTTP(w, req)

		// 1. 验证状态码 401
		assert.Equal(t, http.StatusUnauthorized, w.Code)

		// 2. [关键] 验证 WWW-Authenticate 头 (RFC 6750)
		authHeader := w.Header().Get("WWW-Authenticate")
		assert.Contains(t, authHeader, `Bearer error="invalid_request"`)
		assert.Contains(t, authHeader, "Missing or invalid authorization header")
	})

	t.Run("Invalid Token", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api", nil)
		req.Header.Set("Authorization", "Bearer invalid-token.xyz")
		w := httptest.NewRecorder()

		protectedHandler.ServeHTTP(w, req)

		// 1. 验证状态码 401
		assert.Equal(t, http.StatusUnauthorized, w.Code)

		// 2. [关键] 验证 WWW-Authenticate 头
		authHeader := w.Header().Get("WWW-Authenticate")
		assert.Contains(t, authHeader, `Bearer error="invalid_token"`) // code 应该是 invalid_token
	})

	t.Run("Valid Token", func(t *testing.T) {
		// 生成一个有效 Token
		ctx := context.Background()
		// 使用 Server.Exchange 而不是不存在的 ExchangeClientCredentials
		tokenResp, err := server.Exchange(ctx, &oidc.TokenRequest{
			GrantType:    "client_credentials",
			ClientID:     client.GetID().String(),
			ClientSecret: "test_secret",
			Scope:        "openid",
		})
		require.NoError(t, err)

		req := httptest.NewRequest("GET", "/api", nil)
		req.Header.Set("Authorization", "Bearer "+tokenResp.AccessToken)
		w := httptest.NewRecorder()

		protectedHandler.ServeHTTP(w, req)
		assert.Equal(t, http.StatusOK, w.Code)
	})
}

// -----------------------------------------------------------------------------
// UserInfo Handler Integration
// -----------------------------------------------------------------------------
func TestUserInfoHandler(t *testing.T) {
	server, storage, client := setupServer(t)
	mw := httpx.AuthenticationMiddleware(server)
	handler := mw(httpx.UserInfoHandler(server))
	ctx := context.Background()

	// 1. 准备用户数据
	// UserInfo 端点需要数据库里真的有这个用户
	userID := oidc.BinaryUUID(uuid.New())
	userName := "Test User"
	userEmail := "test@example.com"

	err := storage.UserCreateInfo(ctx, &oidc.UserInfo{
		Subject: userID.String(),
		Name:    &userName,
		Email:   &userEmail,
	})
	require.NoError(t, err)

	// 2. 手动签发一个属于该用户的 Token (模拟 Authorization Code Flow 的结果)
	// 我们不使用 client_credentials，而是直接调用 Issuer 生成用户 Token
	issueReq := &oidc.IssuerRequest{
		ClientID: client.GetID(),
		UserID:   userID, // 关键：sub 必须是 UserID
		Scopes:   "openid profile email",
		Audience: []string{client.GetID().String()},
	}

	// IssueOIDCTokens 会生成 ID Token, Access Token (sub=userID) 和 Refresh Token
	tokenResp, err := server.Issuer().IssueOIDCTokens(ctx, issueReq)
	require.NoError(t, err)

	// 3. 发起请求
	req := httptest.NewRequest("GET", "/userinfo", nil)
	req.Header.Set("Authorization", "Bearer "+tokenResp.AccessToken)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	// 4. 验证结果
	assert.Equal(t, http.StatusOK, w.Code)

	var info oidc.UserInfo
	sonic.Unmarshal(w.Body.Bytes(), &info)

	assert.Equal(t, userID.String(), info.Subject)
	assert.NotNil(t, info.Name)
	assert.Equal(t, "Test User", *info.Name)
	assert.NotNil(t, info.Email)
	assert.Equal(t, "test@example.com", *info.Email)
}

// -----------------------------------------------------------------------------
// Introspection Handler Tests
// -----------------------------------------------------------------------------

func TestIntrospectionHandler(t *testing.T) {
	server, _, client := setupServer(t)
	handler := httpx.IntrospectionHandler(server)

	// 1. 获取一个有效 Token
	tokenResp, err := server.Exchange(context.Background(), &oidc.TokenRequest{
		GrantType:    "client_credentials",
		ClientID:     client.GetID().String(),
		ClientSecret: "test_secret",
		Scope:        "openid",
	})
	require.NoError(t, err)

	// 2. 发起内省请求 (Basic Auth)
	v := url.Values{}
	v.Set("token", tokenResp.AccessToken)

	req := httptest.NewRequest("POST", "/introspect", strings.NewReader(v.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(client.GetID().String(), "test_secret")
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var intro oidc.IntrospectionResponse
	sonic.Unmarshal(w.Body.Bytes(), &intro)
	assert.True(t, intro.Active)
	assert.Equal(t, client.GetID().String(), intro.ClientID)
}
