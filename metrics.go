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
	o11y.RegisterInt64Counter("oidc.key.rotation.total", "Total number of cryptographic key rotations performed.", "{rotation}")
	o11y.RegisterInt64Counter("oidc.login.attempt.total", "Total count of login attempts. Differentiate outcomes via attributes (status=success|failure).", "{attempt}")
	o11y.RegisterInt64Counter("oidc.user.registration.total", "Total number of new user registrations.", "{user}")
	o11y.RegisterInt64Counter("oidc.code.sent.total", "Total number of verification codes (SMS/Email) sent.", "{event}")
	o11y.RegisterFloat64Histogram("oidc.login.duration", "Duration of the login process.", "s")
}
