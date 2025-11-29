package oidc

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"
)

// AuthorizeRequest 封装授权端点的请求参数
type AuthorizeRequest struct {
	// 必需参数
	ClientID     string `form:"client_id" json:"client_id"`
	RedirectURI  string `form:"redirect_uri" json:"redirect_uri"`
	ResponseType string `form:"response_type" json:"response_type"` // 目前仅支持 "code"

	// 可选参数
	Scope               string `form:"scope" json:"scope"`
	State               string `form:"state" json:"state"`
	Nonce               string `form:"nonce" json:"nonce"`
	CodeChallenge       string `form:"code_challenge" json:"code_challenge"`
	CodeChallengeMethod string `form:"code_challenge_method" json:"code_challenge_method"`

	// PAR (RFC 9126): 推送授权请求 URI
	// 如果存在，忽略其他参数，从 PARStorage 加载完整请求
	RequestURI string `form:"request_uri" json:"request_uri"`

	// DPoP (RFC 9449): JWK Thumbprint from DPoP proof
	// 由 HTTP Handler 验证 DPoP Proof 后提取并传入
	// 将被绑定到 Auth Code，在 Token Exchange 时验证
	DPoPJKT string `form:"-" json:"-"`

	// 上下文数据 (由调用者在用户登录/确认后填充)
	UserID   string    `form:"-" json:"-"`
	AuthTime time.Time `form:"-" json:"-"`
	// FinalScope 允许调用者在业务层修改最终授予的 Scope (例如移除用户无权的 scope)
	// 如果为空，将默认使用请求的 Scope
	FinalScope string `form:"-" json:"-"`
}

// RequestAuthorize 校验授权请求的基本参数。
// 这一步通常在显示登录页面或授权同意页面之前调用。
// 如果返回 error，调用者应直接向用户显示错误页，而不是重定向（因为 RedirectURI 可能尚未验证）。
//
// PAR 支持 (RFC 9126):
// - 如果 req.RequestURI 存在，从 PARStorage 加载完整请求参数
// - request_uri 只能使用一次
func RequestAuthorize(ctx context.Context, storage Storage, req *AuthorizeRequest) (RegisteredClient, error) {
	// [PAR] 如果提供了 request_uri，从 PARStorage 加载参数
	// 注意：这里需要 PARStorage，但为了保持向后兼容，我们使用类型断言
	if req.RequestURI != "" {
		// 加载 PAR 会话 (原子删除)
		parReq, err := LoadPARSession(ctx, storage, req.RequestURI)
		if err != nil {
			return nil, fmt.Errorf("%w: invalid or expired request_uri", ErrInvalidRequest)
		}

		// 使用 PAR 中的参数替换当前请求
		// 保留 UserID, AuthTime, FinalScope (由后续流程设置)
		userID := req.UserID
		authTime := req.AuthTime
		finalScope := req.FinalScope

		*req = *parReq
		req.UserID = userID
		req.AuthTime = authTime
		req.FinalScope = finalScope
	}

	clientID, err := uuid.Parse(req.ClientID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid client_id", ErrInvalidRequest)
	}
	// 1. 验证 Client ID
	client, err := storage.GetClient(ctx, BinaryUUID(clientID))
	// [安全] 即使客户端未找到，我们也不立即返回，而是继续后续验证，以防止客户端ID枚举攻击。
	if err != nil && !errors.Is(err, ErrClientNotFound) {
		return nil, err
	}

	// 2. 验证 Redirect URI
	// 安全性关键：必须进行精确字符串匹配，防止绕过
	if !isValidURI(client, req.RedirectURI) {
		return nil, fmt.Errorf("%w: mismatch redirect_uri", ErrInvalidRequest)
	}

	// 3. 验证 Response Type
	if req.ResponseType != "code" {
		return nil, fmt.Errorf("%w: unsupported response_type", ErrUnsupportedGrantType)
	}

	// 4. 验证 Grant Type 支持
	// 虽然这是授权端点，但客户端必须被允许使用 authorization_code 流程
	if !slices.Contains(client.GetGrantTypes(), "authorization_code") {
		return nil, fmt.Errorf("%w: client not authorized for authorization_code flow", ErrUnauthorizedClient)
	}

	// 5. 验证 Scope
	// 检查请求的 Scope 是否都在 Client 注册的允许范围内
	if err := ValidateScopes(client.GetScope(), req.Scope); err != nil {
		return nil, err
	}

	// 6. OIDC 特定检查
	if strings.Contains(req.Scope, "openid") && req.Nonce == "" {
		return nil, fmt.Errorf("%w: nonce is required for OpenID requests", ErrInvalidRequest)
	}

	// 7. PKCE 检查
	// 在旧的标准（RFC 7636）中，机密客户端（Confidential Client）不需要强制使用 PKCE。
	// 但在最新的安全最佳实践（OAuth 2.0 Security BCP）和即将到来的 OAuth 2.1 标准中，强烈建议甚至强制所有类型的客户端（包括机密客户端）都使用 PKCE。
	if req.CodeChallengeMethod == "" {
		req.CodeChallengeMethod = CodeChallengeMethodS256
	}
	if req.CodeChallenge == "" {
		return nil, fmt.Errorf("%w: code_challenge is required", ErrInvalidRequest)
	}

	return client, nil
}

// ResponseAuthorized 在用户通过身份验证并同意授权后调用。
// 它生成 Authorization Code，保存到存储层，并返回包含 code 和 state 的重定向 URL。
func ResponseAuthorized(ctx context.Context, storage AuthCodeStorage, req *AuthorizeRequest, codeTTL time.Duration) (string, error) {
	// 0. 前置检查
	if req.UserID == "" {
		return "", ErrUserIDRequired
	}

	clientID, err := uuid.Parse(req.ClientID)
	if err != nil {
		return "", fmt.Errorf("%w: invalid client_id", ErrInvalidRequest)
	}

	userID, err := uuid.Parse(req.UserID)
	if err != nil {
		return "", fmt.Errorf("%w: invalid user_id", ErrInvalidRequest)
	}

	if req.CodeChallengeMethod == "" {
		req.CodeChallengeMethod = CodeChallengeMethodS256
	}

	// 1. 确定最终 Scope
	// 如果调用者设置了 FinalScope（例如基于用户角色过滤后），则使用它，否则使用请求的 Scope
	finalScope := req.Scope
	if req.FinalScope != "" {
		finalScope = req.FinalScope
	}

	// 2. 生成 Authorization Code (32字节随机字符串)
	code, err := RandomString(32)
	if err != nil {
		return "", fmt.Errorf("failed to generate code: %w", err)
	}

	// 3. 构造 Session 对象
	session := &AuthCodeSession{
		Code:                code,
		ClientID:            BinaryUUID(clientID),
		UserID:              BinaryUUID(userID),
		AuthTime:            req.AuthTime,
		ExpiresAt:           time.Now().Add(codeTTL),
		RedirectURI:         req.RedirectURI,
		Scope:               finalScope,
		Nonce:               req.Nonce,
		CodeChallenge:       req.CodeChallenge,
		CodeChallengeMethod: req.CodeChallengeMethod,
		DPoPJKT:             req.DPoPJKT, // DPoP 绑定
	}

	// 4. 持久化存储
	if err := storage.SaveAuthCode(ctx, session); err != nil {
		return "", fmt.Errorf("failed to save auth code: %w", err)
	}

	// 5. 构建重定向 URL
	redirectURL, err := BuildRedirectURL(req.RedirectURI, code, req.State)
	if err != nil {
		return "", fmt.Errorf("failed to build redirect url: %w", err)
	}

	return redirectURL, nil
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// ValidateScopes 检查 requestedScope 是否是 allowedScope 的子集
// 支持通配符匹配:
// - "scope:*" 匹配 "scope:read", "scope:write"
// - "scope:read:*" 匹配 "scope:read:user"
// - "*" 匹配所有
func ValidateScopes(allowedScopeStr, requestedScopeStr string) error {
	if requestedScopeStr == "" {
		return nil
	}

	allowed := strings.Fields(allowedScopeStr)
	requested := strings.Fields(requestedScopeStr)

	for _, req := range requested {
		if !isScopeAllowed(req, allowed) {
			return fmt.Errorf("%w: scope '%s' is not allowed for this client", ErrInvalidScope, req)
		}
	}
	return nil
}

// isScopeAllowed 检查单个 scope 是否在允许列表中
func isScopeAllowed(req string, allowed []string) bool {
	for _, allow := range allowed {
		if allow == req {
			return true
		}
		// 通配符处理
		if strings.HasSuffix(allow, "*") {
			prefix := strings.TrimSuffix(allow, "*")
			if strings.HasPrefix(req, prefix) {
				return true
			}
		}
	}
	return false
}

// BuildRedirectURL 拼接 URL 参数
func BuildRedirectURL(baseURI, code, state string) (string, error) {
	u, err := url.Parse(baseURI)
	if err != nil {
		return "", err
	}
	q := u.Query()
	q.Set("code", code)
	if state != "" {
		q.Set("state", state)
	}
	u.RawQuery = q.Encode()
	return u.String(), nil
}

// isValidURI 验证 Redirect URI 是否在 Client 的注册范围内
func isValidURI(client RegisteredClient, redirectURI string) bool {
	if client == nil {
		return false
	}
	for _, registeredURI := range client.GetRedirectURIs() {
		if registeredURI == redirectURI {
			return true
		}
	}
	return false
}
