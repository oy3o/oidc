package oidc

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
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
func EndSession(ctx context.Context, storage Storage, server interface {
	ParseAccessToken(ctx context.Context, tokenStr string) (*AccessTokenClaims, error)
	KeyManager() *KeyManager
	Config() *ServerConfig
}, req *EndSessionRequest) (string, error) {
	// 1. 验证 ID Token Hint (如果提供)
	// 这有助于确定是哪个用户/客户端发起的登出
	var clientID BinaryUUID
	var userID BinaryUUID

	if req.IDTokenHint != "" {
		// 这里我们只需要解析，不需要严格验证过期（因为是登出）
		// 但为了安全，还是验证签名
		claims, err := server.ParseAccessToken(ctx, req.IDTokenHint)
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

	// 2. 准备 Back-Channel Logout 广播
	// 在撤销令牌之前，我们需要知道用户当前有哪些活动的会话/客户端
	// 并且提取出对应的 Session ID
	var sessionsToLogout []*RefreshTokenSession
	if userID != (BinaryUUID{}) {
		if sessions, err := storage.RefreshTokenListByUser(ctx, userID); err == nil {
			sessionsToLogout = sessions
		}
	}

	// 3. 执行登出逻辑
	// 3.1 撤销该用户的所有 Refresh Tokens
	if userID != (BinaryUUID{}) {
		if _, err := storage.RefreshTokenRevokeUser(ctx, userID); err != nil {
			return "", fmt.Errorf("failed to revoke user tokens: %w", err)
		}
	}

	// 3.2 撤销当前 Access Token (JTI 黑名单)
	// 这是修复"伪登出"漏洞的关键：即使 RT 被撤销，AT 在过期前仍可使用
	// 通过将 JTI 加入黑名单，确保 AT 立即失效
	if req.AccessToken != "" {
		claims, err := server.ParseAccessToken(ctx, req.AccessToken)
		if err == nil && claims.ID != "" {
			// 将 JTI 加入黑名单，直到 Token 过期
			// 注意：即使解析失败也继续登出流程，不阻塞用户登出
			if err := storage.AccessTokenRevoke(ctx, claims.ID, claims.ExpiresAt.Time); err != nil {
				// 记录日志，但不阻塞登出
				log.Warn().Err(err).Str("jti", claims.ID).Msg("Failed to revoke access token during logout")
			}
		}
	}

	// 4. 验证 Post Logout Redirect URI
	// 必须与 Client 注册的 URI 匹配
	redirectURL := ""
	if req.PostLogoutRedirectURI != "" && clientID != (BinaryUUID{}) {
		client, err := storage.ClientGetByID(ctx, clientID)
		if err == nil {
			// 检查是否在 LogoutRedirectURIs 中
			for _, uri := range client.GetLogoutRedirectURIs() {
				if uri == req.PostLogoutRedirectURI {
					redirectURL = req.PostLogoutRedirectURI
					break
				}
			}
		}
	}

	// 5. 触发 Back-Channel Logout (异步)
	if len(sessionsToLogout) > 0 {
		go broadcastBackchannelLogout(ctx, storage, server, sessionsToLogout)
	}

	// 6. 构建返回 URL
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

// broadcastBackchannelLogout 向受影响的客户端广播注销令牌
func broadcastBackchannelLogout(ctx context.Context, storage Storage, issuer interface {
	KeyManager() *KeyManager
	Config() *ServerConfig
}, sessions []*RefreshTokenSession) {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
	defer cancel()

	var wg sync.WaitGroup

	// 避免对同一个 client 发送多次请求
	visitedClients := make(map[BinaryUUID]bool)

	for _, session := range sessions {
		if visitedClients[session.ClientID] {
			continue
		}
		visitedClients[session.ClientID] = true

		client, err := storage.ClientGetByID(ctx, session.ClientID)
		if err != nil {
			continue
		}

		logoutURI := client.GetBackchannelLogoutURI()
		if logoutURI == "" {
			continue
		}

		// 检查是否需要 Session ID
		if client.GetBackchannelLogoutSessionRequired() && session.SessionID == "" {
			continue
		}

		// 构建 Logout Token
		kid, privateKey, err := issuer.KeyManager().GetSigningKey(ctx)
		if err != nil {
			continue
		}

		method := GetSigningMethod(privateKey)
		if method == nil {
			continue
		}

		claims := &LogoutTokenClaims{
			RegisteredClaims: jwt.RegisteredClaims{
				Issuer:   issuer.Config().Issuer,
				Subject:  session.UserID.String(),
				Audience: jwt.ClaimStrings{client.GetID().String()},
				IssuedAt: jwt.NewNumericDate(time.Now()),
				ID:       uuid.New().String(), // JTI
			},
			Events: map[string]interface{}{
				"http://schemas.openid.net/event/backchannel-logout": map[string]interface{}{},
			},
		}

		if session.SessionID != "" {
			claims.SessionID = session.SessionID
		}

		token := jwt.NewWithClaims(method, claims)
		token.Header["kid"] = kid
		signedToken, err := token.SignedString(privateKey)
		if err != nil {
			continue
		}

		wg.Add(1)
		// 发送 HTTP POST 请求
		go func(ctx context.Context, uri string, logoutToken string) {
			defer wg.Done()
			_, err := sendLogoutRequest(ctx, uri, logoutToken)
			if err != nil {
				log.Warn().Err(err).Str("uri", uri).Msg("Failed to send back-channel logout request")
			}
		}(ctx, logoutURI, signedToken)
	}

	wg.Wait()
}

func sendLogoutRequest(ctx context.Context, uri string, logoutToken string) (*http.Response, error) {
	data := url.Values{}
	data.Set("logout_token", logoutToken)

	req, err := http.NewRequestWithContext(ctx, "POST", uri, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	client := &http.Client{Timeout: 5 * time.Second}
	return client.Do(req)
}
