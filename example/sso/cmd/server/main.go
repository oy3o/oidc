package main

import (
	"context"
	"net/http"
	"time"

	"github.com/rs/zerolog/log"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"

	"sso/internal/config"
	"sso/internal/handler"
	"sso/internal/infra/cache"
	"sso/internal/infra/db"

	"github.com/oy3o/appx"
	"github.com/oy3o/appx/security"
	"github.com/oy3o/httpx"
	"github.com/oy3o/o11y"
	"github.com/oy3o/oidc"
	"github.com/oy3o/oidc/hasher"
	oidc_httpx "github.com/oy3o/oidc/httpx"
	"github.com/oy3o/task"
)

func main() {
	// 1. 加载配置
	cfg, err := config.Load()
	if err != nil {
		panic("failed to load config: " + err.Error())
	}

	// 2. 初始化可观测性 (o11y)
	// Init 会初始化全局 Logger, Tracer, Meter
	shutdownO11y, err := o11y.Init(cfg.O11y)
	if err != nil {
		panic(err)
	}
	defer shutdownO11y(context.Background())

	// =========================================================================
	// [关键优化] httpx 与 o11y 的深度集成
	// =========================================================================

	// 1. 让 httpx 能获取到 TraceID，从而注入到 Response Header 和 Body 中
	httpx.GetTraceID = o11y.GetTraceID

	// 2. 配置 httpx 的全局错误钩子
	// 当 oidc 库或其他 handler 调用 httpx.Error() 时，自动记录带 TraceID 的结构化日志
	httpx.ErrorHook = func(ctx context.Context, err error) {
		// GetLoggerFromContext 会自动提取 TraceID
		logger := o11y.GetLoggerFromContext(ctx)

		// 记录错误堆栈和详细信息
		// 如果是业务错误(HttpError)，通常不需要 Error 级别，Info/Warn 即可
		// 但为了调试方便，这里统一用 Error
		logger.Error().Err(err).Msg("HTTP Request Error")
	}

	// =========================================================================

	// 3. 初始化基础设置
	gormDB, err := gorm.Open(postgres.Open(cfg.Database.DSN), &gorm.Config{})
	if err != nil {
		log.Fatal().Err(err).Msg("failed to connect to database")
	}

	redisStore, err := cache.NewCacheStorage(cfg.Redis.Addr, cfg.Redis.Password, cfg.Redis.DB)
	if err != nil {
		log.Fatal().Err(err).Msg("failed to connect to redis")
	}

	pwHasher := hasher.NewBcryptHasher(10)

	persistStore, err := db.NewStorage(gormDB, pwHasher)
	if err != nil {
		log.Fatal().Err(err).Msg("failed to init persistence storage")
	}

	storage := oidc.NewTieredStorage(persistStore, redisStore)

	// 4. 密钥管理
	sm := oidc.NewSecretManager()
	if err := sm.AddKey("key-1", "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"); err != nil {
		log.Fatal().Err(err).Msg("failed to add hmac key")
	}

	km := oidc.NewKeyManager(storage, 5*time.Minute)
	if _, _, err := km.GetSigningKey(context.Background()); err != nil {
		log.Info().Msg("generating initial signing key...")
		if _, err := km.Generate(context.Background(), oidc.KEY_RSA, true); err != nil {
			log.Fatal().Err(err).Msg("failed to generate signing key")
		}
	}

	rotator := oidc.NewKeyRotationScheduler(km, redisStore, oidc.KeyRotationConfig{
		RotationInterval: 24 * time.Hour,
		GracePeriod:      6 * time.Hour,
		KeyType:          oidc.KEY_RSA,
		EnableAutoRotate: true,
	})

	// 5. 创建 OIDC Server
	serverCfg := cfg.ToOIDCServerConfig(storage, pwHasher, sm)
	oidcServer, err := oidc.NewServer(serverCfg)
	if err != nil {
		log.Fatal().Err(err).Msg("failed to create oidc server")
	}

	// 6. 注册 HTTP 路由
	mux := http.NewServeMux()

	// [OIDC] 标准端点
	// oidc_httpx.*Handler 内部如果出错，会调用 httpx.Error，从而触发上面配置的 ErrorHook
	tokenHandler := oidc.DPoPOptionalMiddleware(redisStore)(oidc_httpx.TokenHandler(oidcServer))
	mux.Handle("POST /token", tokenHandler)
	mux.Handle("GET /jwks.json", oidc_httpx.JWKSHandler(oidcServer))
	mux.Handle("GET /.well-known/openid-configuration", oidc_httpx.DiscoveryHandler(oidcServer))

	userInfoHandler := oidc_httpx.AuthenticationMiddleware(oidcServer)(oidc_httpx.UserInfoHandler(oidcServer))
	mux.Handle("GET /userinfo", userInfoHandler)
	mux.Handle("POST /userinfo", userInfoHandler)

	// [UI] 登录页面
	loginH := handler.NewLoginHandler(oidcServer, persistStore, pwHasher)
	mux.HandleFunc("GET /authorize", loginH.ServeAuthorize)
	mux.HandleFunc("POST /login", loginH.HandleLogin)

	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})

	// 7. 使用 Appx 构建服务容器
	// Appx 会自动处理优雅关闭、信号监听
	app := appx.New(
		appx.WithLogger(&log.Logger),
		appx.WithConfig(cfg),
		appx.WithSecurityManager(security.New(&log.Logger)),
	)

	// 注册后台任务 (Key Rotation, GC)
	app.Add(appx.NewTaskService(task.NewRunner())) // Placeholder for generic tasks if needed
	// 手动启动 OIDC 后台 Worker (GC)
	// 在 Appx 中我们可以包装成一个 Service，或者利用 Hook
	app.Add(&oidcBackgroundService{server: oidcServer, rotator: rotator})

	// 创建 HTTP 服务
	// [关键] WithObservability(cfg.O11y) 会自动为所有请求注入 Tracing 中间件
	// 这确保了 context 中包含 TraceID，httpx.ErrorHook 才能取到它
	httpSvc := appx.NewHttpService("sso-server", cfg.Server.Addr, mux).
		WithObservability(cfg.O11y).
		WithReusePort().
		WithMaxConns(10000)

	app.Add(httpSvc)

	// 8. 运行
	if err := app.Run(); err != nil {
		log.Fatal().Err(err).Msg("Appx exited with error")
	}
}

// oidcBackgroundService 适配器，将 OIDC 后台任务适配为 Appx Service
type oidcBackgroundService struct {
	server  *oidc.Server
	rotator *oidc.KeyRotationScheduler
}

func (s *oidcBackgroundService) Name() string { return "oidc-workers" }
func (s *oidcBackgroundService) Start(ctx context.Context) error {
	s.server.StartBackgroundWorkers(ctx)
	return s.rotator.Start(ctx)
}

func (s *oidcBackgroundService) Stop(ctx context.Context) error {
	s.server.StopBackgroundWorkers()
	s.rotator.Stop()
	return nil
}
