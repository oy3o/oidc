package httpx

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/oy3o/httpx"
	"github.com/oy3o/oidc"
)

// AuthenticationMiddleware 返回一个用于保护资源的中间件。
// 符合 RFC 6750: The OAuth 2.0 Authorization Framework: Bearer Token Usage
func AuthenticationMiddleware(s *oidc.Server) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()
			authHeader := r.Header.Get("Authorization")

			var tokenStr string
			var isDPoPScheme bool

			// 1. 提取 Token 并识别 Scheme
			if len(authHeader) > 7 && strings.EqualFold(authHeader[:7], "Bearer ") {
				tokenStr = authHeader[7:]
				isDPoPScheme = false
			} else if len(authHeader) > 5 && strings.EqualFold(authHeader[:5], "DPoP ") {
				tokenStr = authHeader[5:]
				isDPoPScheme = true
			} else {
				AuthError(w, "invalid_request", "Missing or invalid authorization header")
				return
			}

			// 2. 验证 Token (签名、过期、撤销)
			claims, err := s.VerifyAccessToken(ctx, tokenStr)
			if err != nil {
				// 区分过期错误和其他错误
				code := "invalid_token"
				if errors.Is(err, oidc.ErrTokenExpired) {
					code = "invalid_token" // RFC 6750 统一定义
				}
				AuthError(w, code, err.Error())
				return
			}

			// 3. DPoP 绑定检查
			tokenBoundJKT := ""
			if claims.Confirmation != nil {
				if jkt, ok := claims.Confirmation["jkt"].(string); ok {
					tokenBoundJKT = jkt
				}
			}

			if tokenBoundJKT != "" {
				if !isDPoPScheme {
					AuthError(w, "invalid_request", "Token is DPoP bound but used with Bearer scheme")
					return
				}

				currentJKT := oidc.ExtractDPoPJKT(ctx)
				if currentJKT == "" {
					// DPoP header 缺失或验证失败 (通常应由 DPoPMiddleware 处理)
					AuthError(w, "invalid_dpop_proof", "Missing DPoP proof")
					return
				}
				if currentJKT != tokenBoundJKT {
					AuthError(w, "invalid_dpop_proof", "DPoP proof mismatch")
					return
				}
			} else {
				// 非 DPoP Token 不能使用 DPoP Scheme
				if isDPoPScheme {
					AuthError(w, "invalid_request", "Bearer token used with DPoP scheme")
					return
				}
			}

			// 4. 注入 Identity
			ctx = context.WithValue(ctx, httpx.IdentityKey, claims)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// AuthError 写入符合 RFC 6750 的错误响应
func AuthError(w http.ResponseWriter, errorParam, desc string) {
	// 设置 WWW-Authenticate 头
	// 格式: Bearer error="invalid_token", error_description="..."
	w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Bearer error="%s", error_description="%s"`, errorParam, desc))

	// 这里复用 oidc.Error 格式返回 JSON body，方便前端调试，但 Head 也是必须的
	Error(w, oidc.NewError(errorParam, desc, http.StatusUnauthorized))
}

// GetClaims 从 Context 中安全提取 Claims
func GetClaims(ctx context.Context) (*oidc.AccessTokenClaims, error) {
	identity := httpx.GetIdentity(ctx)
	if identity == nil {
		return nil, errors.New("identity not found in context")
	}
	claims, ok := identity.(*oidc.AccessTokenClaims)
	if !ok {
		return nil, errors.New("identity type mismatch")
	}
	return claims, nil
}
