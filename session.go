package oidc

import (
	"context"
	"fmt"
	"net/url"

	"github.com/rs/zerolog/log"
)

// EndSessionRequest RP-Initiated Logout Request
type EndSessionRequest struct {
	IDTokenHint           string
	PostLogoutRedirectURI string
	State                 string
	// AccessToken 当前有效的 Access Token (可选)
	// 如果提供，将被加入黑名单以实现即时登出
	AccessToken string
}

// EndSession 处理用户登出请求
func EndSession(ctx context.Context, storage Storage, verifier TokenVerifier, req *EndSessionRequest) (string, error) {
	// 1. 验证 ID Token Hint (如果提供)
	// 这有助于确定是哪个用户/客户端发起的登出
	var clientID BinaryUUID
	var userID BinaryUUID

	if req.IDTokenHint != "" {
		// 这里我们只需要解析，不需要严格验证过期（因为是登出）
		// 但为了安全，还是验证签名
		claims, err := verifier.ParseAccessToken(ctx, req.IDTokenHint)
		if err != nil {
			// 如果 ID Token 无效，我们可能无法安全重定向
			// 但通常还是继续处理登出
			// return "", fmt.Errorf("invalid id_token_hint: %w", err)
		} else {
			// 解析成功，获取上下文
			if id, err := ParseUUID(claims.AuthorizedParty); err == nil {
				clientID = id
			}
			if id, err := ParseUUID(claims.Subject); err == nil {
				userID = id
			}
		}
	}

	// 2. 执行登出逻辑
	// 2.1 撤销该用户的所有 Refresh Tokens
	if userID != (BinaryUUID{}) {
		if _, err := storage.RevokeTokensForUser(ctx, userID); err != nil {
			return "", fmt.Errorf("failed to revoke user tokens: %w", err)
		}
	}

	// 2.2 撤销当前 Access Token (JTI 黑名单)
	// 这是修复"伪登出"漏洞的关键：即使 RT 被撤销，AT 在过期前仍可使用
	// 通过将 JTI 加入黑名单，确保 AT 立即失效
	if req.AccessToken != "" {
		claims, err := verifier.ParseAccessToken(ctx, req.AccessToken)
		if err == nil && claims.ID != "" {
			// 将 JTI 加入黑名单，直到 Token 过期
			// 注意：即使解析失败也继续登出流程，不阻塞用户登出
			if err := storage.Revoke(ctx, claims.ID, claims.ExpiresAt.Time); err != nil {
				// 记录日志，但不阻塞登出
				log.Warn().Err(err).Str("jti", claims.ID).Msg("Failed to revoke access token during logout")
			}
		}
	}

	// 3. 验证 Post Logout Redirect URI
	// 必须与 Client 注册的 URI 匹配
	redirectURL := ""
	if req.PostLogoutRedirectURI != "" && clientID != (BinaryUUID{}) {
		client, err := storage.GetClient(ctx, clientID)
		if err == nil {
			// 这里应该检查 PostLogoutRedirectURIs，但接口里只有 GetRedirectURIs
			// 简化处理：检查是否在 RedirectURIs 中
			// 实际 OIDC 规范要求单独注册 post_logout_redirect_uris
			for _, uri := range client.GetRedirectURIs() {
				if uri == req.PostLogoutRedirectURI {
					redirectURL = req.PostLogoutRedirectURI
					break
				}
			}
		}
	}

	// 4. 构建返回 URL
	if redirectURL != "" {
		if req.State != "" {
			u, _ := url.Parse(redirectURL)
			q := u.Query()
			q.Set("state", req.State)
			u.RawQuery = q.Encode()
			redirectURL = u.String()
		}
		return redirectURL, nil
	}

	return "", nil
}
