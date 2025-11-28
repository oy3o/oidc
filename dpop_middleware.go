package oidc

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

// DPoPContext 是用于在 context 中传递 DPoP 验证结果的 key
type dpopContextKey struct{}

// DPoPClaims 存储 DPoP 验证后的信息
type DPoPClaims struct {
	JKT string // JWK Thumbprint，用于绑定到 Access Token
}

// DPoPMiddleware 创建一个中间件来验证 DPoP proof
// 如果验证成功，将 DPoPClaims 存入 context
// 如果验证失败，返回 401 错误
//
// 使用方式:
//
//	middleware := oidc.DPoPMiddleware(server, replayCache, true)
//	handler := middleware(yourHandler)
func DPoPMiddleware(cache ReplayCache, required bool) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()

			// 1. 检查 DPoP header
			dpopHeader := r.Header.Get("DPoP")
			if dpopHeader == "" {
				if required {
					// DPoP 是必需的但未提供
					http.Error(w, `{"error":"invalid_dpop_proof","error_description":"DPoP header is required"}`, http.StatusUnauthorized)
					return
				}
				// DPoP 是可选的，继续处理
				next.ServeHTTP(w, r)
				return
			}

			// 2. 构建完整的请求 URI (不含 query 和 fragment)
			httpURI := buildRequestURI(r)

			// 3. 验证 DPoP proof
			jkt, err := VerifyDPoPProof(ctx, r, w, cache, r.Method, httpURI)
			if err != nil {
				// DPoP 验证失败
				errMsg := fmt.Sprintf(`{"error":"invalid_dpop_proof","error_description":"%s"}`, err.Error())
				http.Error(w, errMsg, http.StatusUnauthorized)
				return
			}

			// 4. 将 DPoP claims 存入 context
			claims := &DPoPClaims{JKT: jkt}
			ctx = context.WithValue(ctx, dpopContextKey{}, claims)

			// 5. 继续处理请求
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// DPoPFromContext 从 context 中提取 DPoP 验证结果
// 返回 (claims, ok)，如果 ok == false 表示未使用 DPoP
func DPoPFromContext(ctx context.Context) (*DPoPClaims, bool) {
	claims, ok := ctx.Value(dpopContextKey{}).(*DPoPClaims)
	return claims, ok
}

// buildRequestURI 构建 HTTP 请求的完整 URI (不含 query 和 fragment)
// RFC 9449 Section 4.2: htu 必须是 scheme + host + path，不包含 query 和 fragment
func buildRequestURI(r *http.Request) string {
	scheme := "https"
	if r.TLS == nil {
		scheme = "http"
	}

	// 获取 Host (可能来自 Host header 或 URL)
	host := r.Host
	if host == "" {
		host = r.URL.Host
	}

	// 构建 URI
	u := &url.URL{
		Scheme: scheme,
		Host:   host,
		Path:   r.URL.Path,
	}

	return u.String()
}

// ExtractDPoPJKT 是一个辅助函数，用于从 context 中提取 JKT
// 如果不存在则返回空字符串
func ExtractDPoPJKT(ctx context.Context) string {
	if claims, ok := DPoPFromContext(ctx); ok {
		return claims.JKT
	}
	return ""
}

// DPoPOptionalMiddleware 创建一个可选的 DPoP 中间件
// 如果提供了 DPoP header 则验证，否则继续处理
func DPoPOptionalMiddleware(cache ReplayCache) func(http.Handler) http.Handler {
	return DPoPMiddleware(cache, false)
}

// DPoPRequiredMiddleware 创建一个必需的 DPoP 中间件
// 如果未提供 DPoP header 则返回 401 错误
func DPoPRequiredMiddleware(cache ReplayCache) func(http.Handler) http.Handler {
	return DPoPMiddleware(cache, true)
}

// DPoPProtectedEndpoints 返回需要 DPoP 保护的端点列表
// 通常包括：/token, /userinfo, /introspect
func DPoPProtectedEndpoints() []string {
	return []string{
		"/token",
		"/userinfo",
		"/introspect",
	}
}

// ShouldUseDPoP 检查请求路径是否应该使用 DPoP
func ShouldUseDPoP(path string) bool {
	for _, endpoint := range DPoPProtectedEndpoints() {
		if strings.HasSuffix(path, endpoint) {
			return true
		}
	}
	return false
}
