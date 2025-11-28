package oidc

import (
	"github.com/oy3o/o11y"
)

// RegisterMetrics 注册 OIDC 相关的 metrics 到 o11y registry
// 这个函数应该在初始化 OIDC Server 之后，启动服务之前调用
// 通常在 main.go 中调用一次即可
//
// 示例用法:
//
//	shutdown := o11y.Init(cfg.O11y)
//	defer shutdown(context.Background())
//	oidc.RegisterMetrics()  // 注册 OIDC 指标
func RegisterMetrics() {
	// OIDC 密钥轮换指标
	o11y.RegisterInt64Counter(
		"oidc.key_rotation.total",
		"Total number of key rotations performed",
		"{rotation}",
	)

	// OIDC JWKS 刷新指标 (可选，如果需要更详细的监控)
	// o11y.RegisterInt64Counter(
	// 	"oidc.jwks_refresh.total",
	// 	"Total number of JWKS refresh operations",
	// 	"{refresh}",
	// )
}
