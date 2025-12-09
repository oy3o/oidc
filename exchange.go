package oidc

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"
)

// TokenRequest 封装了 /token 端点的标准参数
// 对应 RFC 6749 Section 4.1.3 & 6
type TokenRequest struct {
	GrantType    string `form:"grant_type" json:"grant_type"`
	ClientID     string `form:"client_id" json:"client_id"`
	ClientSecret string `form:"client_secret" json:"client_secret"`
	RedirectURI  string `form:"redirect_uri" json:"redirect_uri"`

	// authorization_code 参数
	Code         string `form:"code" json:"code"`
	CodeVerifier string `form:"code_verifier" json:"code_verifier"` // PKCE

	// device_code 参数
	DeviceCode string `form:"device_code" json:"device_code"`

	// refresh_token 参数
	RefreshToken string `form:"refresh_token" json:"refresh_token"`

	// client_credentials 参数 (可选扩展)
	Scope string `form:"scope" json:"scope"`

	// password 参数 (可选扩展, 仅用于测试)
	Username string `form:"username" json:"username"`
	Password string `form:"password" json:"password"`

	// DPoP (RFC 9449): JWK Thumbprint from DPoP proof
	// 如果请求包含 DPoP header，验证后提取的 JKT
	DPoPJKT string `form:"-" json:"-"` // 不从 body 绑定
}

// AuthenticateClient 验证客户端身份
func AuthenticateClient(ctx context.Context, storage ClientStorage, clientIDStr, clientSecret string, hasher Hasher) (RegisteredClient, error) {
	if clientIDStr == "" {
		return nil, fmt.Errorf("%w: client_id is required", ErrInvalidRequest)
	}

	clientID, err := ParseUUID(clientIDStr)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid client_id", ErrInvalidRequest)
	}

	client, err := storage.ClientFindByID(ctx, clientID)
	if err != nil {
		if errors.Is(err, ErrClientNotFound) {
			return nil, fmt.Errorf("%w: invalid client", ErrInvalidClient)
		}
		return nil, err
	}

	// 验证 Secret (仅针对机密客户端)
	if client.IsConfidential() {
		if clientSecret == "" {
			return nil, fmt.Errorf("%w: invalid client", ErrInvalidClient)
		}
		if err := client.ValidateSecret(ctx, hasher, clientSecret); err != nil {
			return nil, fmt.Errorf("%w: invalid client", ErrInvalidClient)
		}
	}

	return client, nil
}

// ExchangeCode 用于处理 authorization_code 流程
func ExchangeCode(ctx context.Context, storage Storage, hasher Hasher, issuer *Issuer, req *TokenRequest) (*IssuerResponse, error) {
	// 1. 查找并消耗授权码
	// 注意：AuthCodeConsume 必须是一个原子操作或事务，确保 Code 只能被使用一次
	session, err := storage.AuthCodeConsume(ctx, req.Code)
	if err != nil {
		if errors.Is(err, ErrCodeNotFound) {
			return nil, fmt.Errorf("%w: invalid or expired code", ErrInvalidGrant)
		}
		return nil, err
	}

	// 2. 绑定检查 (Binding Checks)
	// 确保请求 Token 的 Client 就是当初申请 Code 的 Client
	// 除非同时确认了 Code 和 Client 都正确, 否则返回相同的错误以防止探测攻击。
	clientID, err := ParseUUID(req.ClientID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid client_id", ErrInvalidRequest)
	}
	if session.ClientID != clientID {
		return nil, fmt.Errorf("%w: invalid or expired code", ErrInvalidGrant)
	}

	// 确保 RedirectURI 与申请 Code 时的一致
	// RFC 6749 Section 4.1.3 要求：
	// - 如果授权请求中包含 redirect_uri，则此参数也必须提供且值必须完全相同
	// - 如果授权请求中未包含 redirect_uri（且客户端只注册了一个 URI），则此参数可以省略
	if req.RedirectURI != "" && session.RedirectURI != req.RedirectURI {
		return nil, fmt.Errorf("%w: redirect_uri mismatch", ErrInvalidGrant)
	}

	// DPoP 绑定验证 (RFC 9449)
	// 如果 Auth Code 绑定了 DPoP Key，则必须使用相同的 Key 进行 Exchange
	// 这防止了 Code Injection 攻击：攻击者截获 Code 后无法用自己的 DPoP Key 换取 Token
	if session.DPoPJKT != "" {
		if session.DPoPJKT != req.DPoPJKT {
			return nil, fmt.Errorf("%w: DPoP key mismatch", ErrInvalidGrant)
		}
	}

	// 3. PKCE 验证 (RFC 7636)
	// Only verify if CodeChallenge was present in the authorization request
	if session.CodeChallenge != "" {
		if err := VerifyPKCE(session.CodeChallenge, session.CodeChallengeMethod, req.CodeVerifier); err != nil {
			return nil, fmt.Errorf("%w: pkce verification failed", ErrInvalidGrant)
		}
	}

	// 4. Client 认证
	client, err := AuthenticateClient(ctx, storage, req.ClientID, req.ClientSecret, hasher)
	if err != nil {
		return nil, fmt.Errorf("%w: client authentication failed", ErrInvalidClient)
	}
	// 验证 Grant Type 支持
	// 虽然这是授权端点，但客户端必须被允许使用 authorization_code 流程
	if !slices.Contains(client.GetGrantTypes(), "authorization_code") {
		return nil, fmt.Errorf("%w: client not authorized for authorization_code flow", ErrUnauthorizedClient)
	}

	// 5. 准备 Issuer 请求
	profile := &UserInfo{}
	if strings.Contains(session.Scope, "openid") {
		profile, err = storage.UserGetInfoByID(ctx, session.UserID, strings.Fields(session.Scope))
		if err != nil {
			return nil, fmt.Errorf("failed to get user info: %w", err)
		}
	}

	issueReq := &IssuerRequest{
		ClientID: clientID,
		UserID:   session.UserID,
		Scopes:   session.Scope,
		Audience: []string{clientID.String()}, // 默认 Audience 是 ClientID
		Nonce:    session.Nonce,               // ID Token 需要
		Code:     Code(req.Code),              // 用于计算 c_hash
		AuthTime: session.AuthTime,
		DPoPJKT:  session.DPoPJKT,

		// 可以在此注入用户信息 (Profile)，如果 Issuer 需要放入 ID Token
		Name:                profile.Name,
		PreferredUsername:   profile.PreferredUsername,
		Picture:             profile.Picture,
		Email:               profile.Email,
		EmailVerified:       profile.EmailVerified,
		PhoneNumber:         profile.PhoneNumber,
		PhoneNumberVerified: profile.PhoneNumberVerified,
	}

	// 6. 根据是否携带 openid 生成 Tokens
	// IssueOIDCTokens 会处理 at_hash, c_hash 等计算
	var resp *IssuerResponse
	if strings.Contains(issueReq.Scopes, "openid") {
		resp, err = issuer.IssueOIDCTokens(ctx, issueReq)
		if err != nil {
			return nil, fmt.Errorf("failed to issue tokens: %w", err)
		}
	} else {
		resp, err = issuer.IssueOAuthTokens(ctx, issueReq)
		if err != nil {
			return nil, fmt.Errorf("failed to issue tokens: %w", err)
		}
	}

	// 7. 持久化 Refresh Token
	// Issuer 生成了 RT 字符串，我们需要计算哈希并存入 Storage
	rtSession := &RefreshTokenSession{
		ID:        RefreshToken(resp.RefreshToken).HashForDB(),
		ClientID:  clientID,
		UserID:    session.UserID,
		Scope:     session.Scope,
		AuthTime:  session.AuthTime,
		Nonce:     session.Nonce, // 保留 Nonce 上下文
		ExpiresAt: time.Now().Add(issuer.cfg.RefreshTokenTTL),
		ACR:       session.ACR,
		AMR:       session.AMR,
	}

	if err := storage.RefreshTokenCreate(ctx, rtSession); err != nil {
		return nil, fmt.Errorf("failed to store refresh token: %w", err)
	}

	return resp, nil
}

// RefreshTokens 用于处理 refresh_token 流程
func RefreshTokens(ctx context.Context, storage Storage, secretManager *SecretManager, hasher Hasher, issuer *Issuer, req *TokenRequest) (*IssuerResponse, error) {
	// 1. 参数检查
	if req.RefreshToken == "" {
		return nil, fmt.Errorf("%w: refresh_token is required", ErrInvalidRequest)
	}

	// 确认 Refresh Token 的有效性
	if err := ValidateStructuredRefreshToken(ctx, secretManager, RefreshToken(req.RefreshToken)); err != nil {
		return nil, err
	}

	clientID, err := ParseUUID(req.ClientID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid client_id", ErrInvalidRequest)
	}

	// 2. 计算哈希并查找旧 Token
	rtHash := RefreshToken(req.RefreshToken).HashForDB()
	oldSession, err := storage.RefreshTokenGet(ctx, rtHash)
	if err != nil {
		if errors.Is(err, ErrTokenNotFound) {
			// 安全警报：如果使用了未知的 RT，可能是令牌被盗并已被轮换。
			// 高级实现应在此处触发 "Reuse Detection" 逻辑，撤销该用户的所有令牌。
			return nil, fmt.Errorf("%w: invalid refresh token", ErrInvalidGrant)
		}
		return nil, err
	}

	// 3. 验证归属权
	if oldSession.ClientID != clientID {
		return nil, fmt.Errorf("%w: client mismatch", ErrInvalidClient)
	}

	// 4. Client 认证
	client, err := AuthenticateClient(ctx, storage, req.ClientID, req.ClientSecret, hasher)
	if err != nil {
		return nil, fmt.Errorf("%w: client authentication failed", ErrInvalidClient)
	}

	// 5. 验证 Grant Type 支持
	// 虽然这是授权端点，但客户端必须被允许使用 refresh_token
	if !slices.Contains(client.GetGrantTypes(), "refresh_token") {
		return nil, fmt.Errorf("%w: client not authorized for refresh_token flow", ErrUnauthorizedClient)
	}

	// 6. 生成新 Token (Issuer 逻辑)
	// 注意：OIDC 规范建议刷新时 ID Token 不包含 nonce，除非能验证 nonce 连续性。
	// 这里使用 RefreshOIDCTokens 方法。

	// 处理 Scope 缩减 (Downscoping)
	finalScope := oldSession.Scope
	if req.Scope != "" {
		// 验证请求的 Scope 是否是原 Scope 的子集
		if err := ValidateScopes(oldSession.Scope, req.Scope); err != nil {
			return nil, err
		}
		finalScope = req.Scope
	}

	issueReq := &IssuerRequest{
		ClientID: clientID,
		UserID:   oldSession.UserID,
		Scopes:   finalScope,
		Audience: []string{clientID.String()},
		AuthTime: oldSession.AuthTime,
		// 对于 Refresh Token，通常不强制要求 DPoP 绑定，或者沿用旧的 JKT
		// 如果需要 DPoP Rotate，这里需要处理 req.DPoPJKT
		// 目前假设 Access Token 继承 Refresh Token 的属性，或者根据请求重新绑定
		DPoPJKT: req.DPoPJKT,
	}

	resp, err := issuer.RefreshOIDCTokens(ctx, issueReq)
	if err != nil {
		return nil, fmt.Errorf("failed to refresh tokens: %w", err)
	}

	// 7. 令牌轮换 (Token Rotation)
	// 构建新 Session
	newSession := &RefreshTokenSession{
		ID:        RefreshToken(resp.RefreshToken).HashForDB(),
		ClientID:  clientID,
		UserID:    oldSession.UserID,
		Scope:     finalScope,
		AuthTime:  oldSession.AuthTime,
		Nonce:     oldSession.Nonce,
		ExpiresAt: time.Now().Add(issuer.cfg.RefreshTokenTTL),
		ACR:       oldSession.ACR,
		AMR:       oldSession.AMR,
	}

	// 执行原子轮换：删除旧的，保存新的
	if err := storage.RefreshTokenRotate(ctx, rtHash, newSession); err != nil {
		return nil, fmt.Errorf("failed to rotate refresh token: %w", err)
	}

	return resp, nil
}

// ExchangeClientCredentials 处理 client_credentials 流程 (M2M)
func ExchangeClientCredentials(ctx context.Context, storage ClientStorage, hasher Hasher, issuer *Issuer, req *TokenRequest) (*IssuerResponse, error) {
	// 1. Client 认证
	// 此模式下 Client 必须存在且必须验证 Secret (本质就是 Confidential Client)
	if req.ClientSecret == "" {
		return nil, fmt.Errorf("%w: client_secret is required", ErrInvalidClient)
	}

	client, err := AuthenticateClient(ctx, storage, req.ClientID, req.ClientSecret, hasher)
	if err != nil {
		return nil, err // AuthenticateClient 已经包装了具体的错误
	}

	// 2. 验证 Grant Type 支持
	if !slices.Contains(client.GetGrantTypes(), "client_credentials") {
		return nil, fmt.Errorf("%w: client not authorized for client_credentials flow", ErrUnauthorizedClient)
	}

	// 3. 确定 Scope
	// 如果请求未指定 Scope，则默认使用 Client 注册的所有 Scope
	// 如果指定了，必须是注册 Scope 的子集
	finalScope := req.Scope
	if finalScope == "" {
		finalScope = client.GetScope()
	} else {
		if err := ValidateScopes(client.GetScope(), req.Scope); err != nil {
			return nil, err
		}
	}

	// 4. 准备 Issuer 请求
	// 注意：在 Client Credentials 模式下，Subject (sub) 通常就是 Client ID
	issueReq := &IssuerRequest{
		ClientID: client.GetID(),
		UserID:   client.GetID(), // sub = client_id
		Scopes:   finalScope,
		Audience: []string{client.GetID().String()}, // 或者是配置的 Resource Server ID
		AuthTime: time.Now(),
		DPoPJKT:  req.DPoPJKT, // 支持 DPoP for M2M
	}

	// 5. 签发 Token (无 Refresh Token, 无 ID Token)
	return issuer.IssueClientCredentialsToken(ctx, issueReq)
}
