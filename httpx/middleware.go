package httpx

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	"github.com/oy3o/httpx"
	"github.com/oy3o/oidc"
)

// AuthenticationMiddleware 返回一个支持多路认证（Bearer/DPoP/Cookie）的中间件。
func AuthenticationMiddleware(s *oidc.Server, customStrategies ...httpx.AuthStrategy) func(http.Handler) http.Handler {
	// 1. 定义核心验证器 (Validator)
	// 这个函数纯粹负责：拿到 Token 字符串 -> 验证 -> 返回 Claims
	verifyAccessToken := func(ctx context.Context, tokenStr string) (any, error) {
		claims, err := s.VerifyAccessToken(ctx, tokenStr)
		if err != nil {
			return nil, err
		}
		// DPoP 绑定检查
		tokenBoundJKT := ""
		if claims.Confirmation != nil {
			if jkt, ok := claims.Confirmation["jkt"].(string); ok {
				tokenBoundJKT = jkt
			}
		}

		if tokenBoundJKT != "" {
			return nil, errors.New("Token is DPoP bound but used with Bearer scheme")
		}
		return claims, nil
	}

	verifyDPoP := func(ctx context.Context, tokenStr string) (any, error) {
		claims, err := s.VerifyAccessToken(ctx, tokenStr)
		if err != nil {
			return nil, err
		}
		// DPoP 绑定检查
		tokenBoundJKT := ""
		if claims.Confirmation != nil {
			if jkt, ok := claims.Confirmation["jkt"].(string); ok {
				tokenBoundJKT = jkt
			}
		}

		if tokenBoundJKT == "" {
			return nil, errors.New("Bearer token used with DPoP scheme")
		}

		currentJKT := oidc.ExtractDPoPJKT(ctx)
		if currentJKT == "" {
			return nil, errors.New("Missing DPoP proof")
		}

		if currentJKT != tokenBoundJKT {
			return nil, errors.New("DPoP proof mismatch")
		}

		return claims, nil
	}

	// 2. 组装策略链 (The Chain of Trust)
	// 优先级：Header (Bearer/DPoP) > Cookie > Query
	initStrategies := []httpx.AuthStrategy{
		httpx.FromHeader("Bearer", verifyAccessToken),
		httpx.FromHeader("DPoP", verifyDPoP),
	}

	// 构造最终切片：Core + Custom + Query
	// 预分配容量以优化性能
	strategies := make([]httpx.AuthStrategy, 0, len(initStrategies)+len(customStrategies)+1)
	strategies = append(strategies, initStrategies...)
	strategies = append(strategies, customStrategies...)
	strategies = append(strategies, httpx.FromQuery("access_token", verifyAccessToken))

	chain := httpx.AuthChain(strategies...)

	// 3. 返回标准中间件
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			httpx.Auth(chain)(httpx.AuthRequired(func(w http.ResponseWriter, r *http.Request) {
				// 3. 包装 Challenge (The Ultimatum)
				// 如果整条链都跑完了还没找到凭证，返回标准的 Bearer Challenge
				// 写入符合 RFC 6750 的错误响应
				// 设置 WWW-Authenticate 头
				// 格式: Bearer error="invalid_token", error_description="..."
				w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Bearer error="%s", error_description="%s"`, "invalid_token", httpx.GetAuthError(r.Context()).Error()))
				// 这里复用 oidc.Error 格式返回 JSON body，方便前端调试，但 Head 也是必须的
				Error(w, r, oidc.NewError("invalid_token", httpx.GetAuthError(r.Context()).Error(), http.StatusUnauthorized))
			})(next)).ServeHTTP(w, r)
		})
	}
}

// GetClaims 从 Context 中安全提取 Claims
func GetClaims(ctx context.Context) (*oidc.AccessTokenClaims, error) {
	identity := httpx.GetIdentity(ctx)
	if identity == nil {
		return nil, ErrIdentityNotFound
	}
	claims, ok := identity.(*oidc.AccessTokenClaims)
	if !ok {
		return nil, ErrIdentityTypeMismatch
	}
	return claims, nil
}
