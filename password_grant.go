//go:build test

package oidc

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"time"
)

// PasswordGrant 处理密码授权流程，仅用于负载测试等情景。
// RFC 6749 Section 4.3: Resource Owner Password Credentials Grant
// 注意：此流程不推荐用于生产环境，因为它违背了 OAuth 2.0 的核心设计原则。
func PasswordGrant(ctx context.Context, storage Storage, hasher Hasher, issuer *Issuer, req *TokenRequest) (*IssuerResponse, error) {
	// 1. 认证客户端, 对于密码授权，客户端必须是机密的
	if req.ClientSecret == "" {
		return nil, fmt.Errorf("%w: client_secret is required", ErrInvalidRequest)
	}

	client, err := AuthenticateClient(ctx, storage, req.ClientID, req.ClientSecret, hasher)
	if err != nil {
		return nil, err
	}

	// 2. 验证 Grant Type 支持
	// 虽然这是测试端点，但客户端必须被允许使用 password 流程
	if !slices.Contains(client.GetGrantTypes(), "password") {
		return nil, fmt.Errorf("%w: client not authorized for password flow", ErrUnauthorizedClient)
	}

	// 3. 认证用户
	if req.Username == "" || req.Password == "" {
		return nil, fmt.Errorf("%w: username and password are required", ErrInvalidRequest)
	}

	userID, err := storage.AuthenticateByPassword(ctx, req.Username, req.Password)
	if err != nil {
		// 统一错误响应，防止用户枚举攻击
		return nil, fmt.Errorf("%w: invalid username or password", ErrInvalidGrant)
	}

	// 4. 验证和计算 Scope
	// Password Grant 允许客户端请求自定义 scope，但必须在客户端允许范围内
	requestedScopes := strings.Fields(req.Scope)
	clientScopes := strings.Fields(client.GetScope())

	// 计算交集：只保留客户端允许的 scope
	var grantedScopes []string
	for _, reqScope := range requestedScopes {
		if slices.Contains(clientScopes, reqScope) {
			grantedScopes = append(grantedScopes, reqScope)
		}
	}

	// 如果没有请求 scope，使用客户端的默认 scope
	if len(requestedScopes) == 0 {
		grantedScopes = clientScopes
	}

	finalScope := strings.Join(grantedScopes, " ")

	// 5. 构建 Issuer Request
	issueReq := &IssuerRequest{
		ClientID: client.GetID(),
		UserID:   userID,
		Scopes:   finalScope,
		// AuthTime 设置为当前时间，因为用户刚刚完成认证
		AuthTime: time.Now(),
	}

	// 6. 判断是否需要签发 ID Token
	// 只有当 scope 包含 "openid" 时才签发 ID Token (OIDC 标准要求)
	if slices.Contains(grantedScopes, "openid") {
		// 签发 OIDC Token 套件
		return issuer.IssueOIDCTokens(ctx, issueReq)
	}

	// 7. 签发纯 OAuth2 Token
	return issuer.IssueOAuthTokens(ctx, issueReq)
}
