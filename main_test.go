package oidc_test

import (
	"context"
	"fmt"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/oy3o/o11y"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
)

// 全局变量，整个测试套件生命周期内只初始化一次
var (
	TestPool      *pgxpool.Pool
	TestContainer *postgres.PostgresContainer
	PoolOnce      sync.Once
)

// TestMain 是测试的入口点。它负责初始化 o11y 基础设施，
// 以便其他测试文件中的 server.Exchange 等方法可以安全地调用 o11y.Run。
func TestMain(m *testing.M) {
	// 1. 配置 o11y 为测试模式
	// 我们启用它，但将 Exporter 设置为 "none"，并将日志级别调高，
	// 这样既防止了 panic，又保持了测试控制台的整洁。
	cfg := o11y.Config{
		Enabled:              true, // 必须启用，否则 Run 方法可能无法正常工作或直接跳过逻辑
		Service:              "oidc-test-suite",
		Version:              "0.0.0",
		Environment:          "test",
		InstrumentationScope: "github.com/oy3o/oidc",

		// 日志配置：只记录 Fatal 错误，或者是完全禁用控制台输出
		Log: o11y.LogConfig{
			Level:         "fatal",
			EnableConsole: false, // 禁用控制台输出，避免污染 go test 输出
			EnableFile:    false,
		},

		// 追踪配置：禁用导出
		Trace: o11y.TraceConfig{
			Enabled:  false, // 测试中通常不需要真实的 Trace
			Exporter: "none",
		},

		// 指标配置：禁用
		Metric: o11y.MetricConfig{
			Enabled: false,
		},
	}

	ctx := context.Background()
	PoolOnce.Do(func() {
		container, err := postgres.Run(
			ctx,
			"docker.io/postgres:18-trixie",
			postgres.WithInitScripts("./persist/init.sql"),
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

	// 2. 初始化全局单例
	shutdown, _ := o11y.Init(cfg)

	// 3. 运行所有测试
	code := m.Run()

	// 4. 清理资源
	TestPool.Close()
	if err := TestContainer.Terminate(ctx); err != nil {
		fmt.Printf("failed to terminate container: %v\n", err)
	}
	shutdown(context.Background())

	// 5. 退出
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
