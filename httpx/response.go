package httpx

import (
	"net/http"

	"github.com/bytedance/sonic"
)

// OidcResponse 是 OIDC 协议的标准化载体，实现了 httpx.Responder。
// 它负责处理 RFC 6749/7662 等规定的 HTTP 协议层细节。
type OidcResponse struct {
	Data    any               // 响应体 (通常是 struct)
	Status  int               // HTTP 状态码 (0 默认为 200)
	NoCache bool              // 强制禁止缓存 (RFC 6749 Section 5.1)
	Cors    bool              // 允许跨域 (Discovery / JWKS)
	Headers map[string]string // 其他自定义 Header
}

// WriteResponse 实现 httpx.Responder 接口
func (r OidcResponse) WriteResponse(w http.ResponseWriter, req *http.Request) {
	header := w.Header()

	// 1. Content-Type 总是 JSON
	header.Set("Content-Type", "application/json;charset=UTF-8")

	// 2. Cache Control
	if r.NoCache {
		header.Set("Cache-Control", "no-store")
		header.Set("Pragma", "no-cache")
	} else if r.Cors {
		// Public endpoints (JWKS, Discovery) 允许缓存
		header.Set("Cache-Control", "public, max-age=3600")
	}

	// 3. CORS (Cross-Origin Resource Sharing)
	if r.Cors {
		header.Set("Access-Control-Allow-Origin", "*")
		header.Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		header.Set("Access-Control-Allow-Headers", "Content-Type")
	}

	// 4. Custom Headers
	for k, v := range r.Headers {
		header.Set(k, v)
	}

	// 5. Status Code
	status := r.Status
	if status == 0 {
		status = http.StatusOK
	}
	w.WriteHeader(status)

	// 6. Body
	if r.Data != nil {
		// 使用 sonic 极速编码，错误交由 httpx 框架层监控
		_ = sonic.ConfigDefault.NewEncoder(w).Encode(r.Data)
	}
}
