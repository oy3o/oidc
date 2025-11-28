package oidc

import (
	"context"
	"os"
	"testing"

	"github.com/oy3o/o11y"
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

	// 2. 初始化全局单例
	shutdown, _ := o11y.Init(cfg)

	// 3. 运行所有测试
	code := m.Run()

	// 4. 清理资源
	shutdown(context.Background())

	// 5. 退出
	os.Exit(code)
}
