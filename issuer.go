package oidc

import (
	"context"
	"fmt"
	"net/url"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// IssuerConfig 配置签发的默认参数
type IssuerConfig struct {
	Issuer        string
	SecretManager *SecretManager

	// 默认 TTL (兜底策略)
	AccessTokenTTL  time.Duration
	IDTokenTTL      time.Duration
	RefreshTokenTTL time.Duration
}

// Issuer 负责生成符合 OIDC/OAuth2 标准的 Token
type Issuer struct {
	issuer        string
	keyManager    *KeyManager
	cfg           IssuerConfig // 保存配置以获取默认 TTL
	secretManager *SecretManager
}

// NewIssuer 创建一个新的 Token 发行者
func NewIssuer(cfg IssuerConfig, keyManager *KeyManager) (*Issuer, error) {
	// 1. 基础配置检查
	if cfg.Issuer == "" {
		return nil, ErrIssuerEmpty
	}
	if _, err := url.ParseRequestURI(cfg.Issuer); err != nil {
		return nil, ErrInvalidIssuerURL
	}
	if cfg.AccessTokenTTL <= 0 || cfg.IDTokenTTL <= 0 {
		return nil, ErrInvalidTTL
	}
	if keyManager == nil {
		return nil, ErrKeyManagerNil
	}
	if cfg.SecretManager == nil {
		return nil, ErrSecretManagerNil
	}

	return &Issuer{
		issuer:        cfg.Issuer,
		keyManager:    keyManager,
		cfg:           cfg,
		secretManager: cfg.SecretManager,
	}, nil
}

func (i *Issuer) Issuer() string {
	return i.issuer
}

func (i *Issuer) SecretManager() *SecretManager {
	return i.secretManager
}

// IssuerRequest 包含生成 Token 所需的上下文信息
type IssuerRequest struct {
	ClientID BinaryUUID
	UserID   BinaryUUID // Subject (sub)
	Scopes   string     // Space delimited scopes
	Audience []string   // Resource Server URIs

	Nonce    string    // 仅用于 Implicit/AuthCode Flow 的 Issue 阶段
	Code     Code      // 关联的 Authorization Code (如果适用，用于计算 c_hash)
	AuthTime time.Time // 用户完成认证的时间

	// --- TTL 覆盖策略 ---
	// 如果设置了以下字段（大于0），则使用该时间；否则使用 Config 中的默认时间。
	AccessTokenDuration  time.Duration
	RefreshTokenDuration time.Duration
	IDTokenDuration      time.Duration

	// --- User Profile ---
	Name                *string
	PreferredUsername   *string
	Picture             *string
	Email               *string
	EmailVerified       *bool
	PhoneNumber         *string
	PhoneNumberVerified *bool

	// DPoP (RFC 9449): JWK Thumbprint from DPoP proof
	// 如果不为空，将在 Access Token 中添加 cnf.jkt claim
	DPoPJKT string
}

// IssuerResponse OAuth2 /oauth/token 响应结构
type IssuerResponse struct {
	TokenType    string `json:"token_type"` // Bearer
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token,omitempty"`
	IDToken      string `json:"id_token,omitempty"` // 仅在 OIDC 流程中存在
	ExpiresIn    int64  `json:"expires_in"`
	Scope        string `json:"scope,omitempty"`
}

// ---------------------------------------------------------------------------
// Public Methods (Flows)
// ---------------------------------------------------------------------------

func (g *Issuer) IssueOAuthTokens(ctx context.Context, req *IssuerRequest) (*IssuerResponse, error) {
	// 1. 计算 AccessToken TTL
	atTTL := g.getAccessTokenTTL(req)

	// 2. 生成 Access Token
	at, err := g.accessToken(ctx, req, atTTL)
	if err != nil {
		return nil, err
	}

	// 3. 生成 Refresh Token
	rt, err := g.refreshToken(ctx, req.UserID)
	if err != nil {
		return nil, err
	}

	return &IssuerResponse{
		TokenType:    "Bearer",
		AccessToken:  string(at),
		RefreshToken: string(rt),
		ExpiresIn:    int64(atTTL.Seconds()), // 返回实际使用的过期时间
		Scope:        req.Scopes,
	}, nil
}

// RefreshOAuthTokens 刷新 OAuth2 Token
// 注意：调用者负责验证旧 Refresh Token 的合法性，并将旧 Token 关联的信息填入 req
func (g *Issuer) RefreshOAuthTokens(ctx context.Context, req *IssuerRequest) (*IssuerResponse, error) {
	// Refresh 逻辑通常与 Issue 相同，生成新的 AT 和 RT
	// 某些策略可能通过 req 控制是否轮换 RT，这里默认轮换
	return g.IssueOAuthTokens(ctx, req)
}

// IssueOIDCTokens 生成 OIDC 套件 (ID Token + Access Token + Refresh Token)
func (g *Issuer) IssueOIDCTokens(ctx context.Context, req *IssuerRequest) (*IssuerResponse, error) {
	atTTL := g.getAccessTokenTTL(req)

	// 1. Access Token
	at, err := g.accessToken(ctx, req, atTTL)
	if err != nil {
		return nil, err
	}

	// 2. ID Token (包含 Nonce)
	// 注意：ID Token 的 TTL 也可以在 request 中覆盖
	idTTL := g.getIDTokenTTL(req)
	idt, err := g.idToken(ctx, req, at, true, idTTL)
	if err != nil {
		return nil, err
	}

	// 3. Refresh Token
	rt, err := g.refreshToken(ctx, req.UserID)
	if err != nil {
		return nil, err
	}

	return &IssuerResponse{
		TokenType:    "Bearer",
		AccessToken:  string(at),
		RefreshToken: string(rt),
		IDToken:      string(idt),
		ExpiresIn:    int64(atTTL.Seconds()),
		Scope:        req.Scopes,
	}, nil
}

// RefreshOIDCTokens 刷新 OIDC Token
// 区别：ID Token 在刷新时不应包含 Nonce (OIDC Core 1.0 Section 12.1)
func (g *Issuer) RefreshOIDCTokens(ctx context.Context, req *IssuerRequest) (*IssuerResponse, error) {
	atTTL := g.getAccessTokenTTL(req)

	at, err := g.accessToken(ctx, req, atTTL)
	if err != nil {
		return nil, err
	}

	// 刷新时 ID Token 不包含 Nonce
	idTTL := g.getIDTokenTTL(req)
	idt, err := g.idToken(ctx, req, at, false, idTTL)
	if err != nil {
		return nil, err
	}

	rt, err := g.refreshToken(ctx, req.UserID)
	if err != nil {
		return nil, err
	}

	return &IssuerResponse{
		TokenType:    "Bearer",
		AccessToken:  string(at),
		RefreshToken: string(rt),
		IDToken:      string(idt),
		ExpiresIn:    int64(atTTL.Seconds()),
		Scope:        req.Scopes,
	}, nil
}

// IssueClientCredentialsToken 专门用于客户端凭证模式
// 只生成 Access Token，不生成 Refresh Token，不生成 ID Token
func (g *Issuer) IssueClientCredentialsToken(ctx context.Context, req *IssuerRequest) (*IssuerResponse, error) {
	// 1. 计算 AccessToken TTL
	atTTL := g.getAccessTokenTTL(req)

	// 2. 生成 Access Token
	at, err := g.accessToken(ctx, req, atTTL)
	if err != nil {
		return nil, err
	}

	// client_credentials 通常不返回 refresh_token
	return &IssuerResponse{
		TokenType:   "Bearer",
		AccessToken: string(at),
		ExpiresIn:   int64(atTTL.Seconds()),
		Scope:       req.Scopes,
	}, nil
}

// IssuePasswordResetAccessToken 生成密码修改 AccessToken
func (g *Issuer) IssuePasswordResetAccessToken(ctx context.Context, req *IssuerRequest) (*IssuerResponse, error) {
	req.Scopes = "user:password:reset"
	at, err := g.accessToken(ctx, req, g.getAccessTokenTTL(req))
	if err != nil {
		return nil, err
	}
	return &IssuerResponse{
		TokenType:   "Bearer",
		AccessToken: string(at),
		ExpiresIn:   int64(g.getAccessTokenTTL(req).Seconds()),
		Scope:       req.Scopes,
	}, nil
}

// ---------------------------------------------------------------------------
// Internal Methods (Builders)
// ---------------------------------------------------------------------------

// 获取 AccessToken 有效期：优先 Request，其次 Config
func (g *Issuer) getAccessTokenTTL(req *IssuerRequest) time.Duration {
	if req.AccessTokenDuration > 0 {
		return req.AccessTokenDuration
	}
	return g.cfg.AccessTokenTTL
}

// 获取 IDToken 有效期
func (g *Issuer) getIDTokenTTL(req *IssuerRequest) time.Duration {
	if req.IDTokenDuration > 0 {
		return req.IDTokenDuration
	}
	return g.cfg.IDTokenTTL
}

// accessToken 构建并签名 Access Token
func (iss *Issuer) accessToken(ctx context.Context, req *IssuerRequest, ttl time.Duration) (AccessToken, error) {
	now := time.Now()
	exp := now.Add(ttl)

	// 生成JTI
	uuidV7, err := uuid.NewV7()
	if err != nil {
		return "", ErrFailedToGenerateUUID
	}

	claims := &AccessTokenClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    iss.issuer,
			Subject:   req.UserID.String(),
			Audience:  req.Audience,
			ExpiresAt: jwt.NewNumericDate(exp),
			IssuedAt:  jwt.NewNumericDate(now),
			ID:        uuidV7.String(), // JTI 用于撤销时定位
		},
		Scope:           req.Scopes,
		AuthorizedParty: req.ClientID.String(),
	}

	// [DPoP] 如果提供了 JKT，添加 cnf claim
	// RFC 9449 Section 6: cnf = {"jkt": "<thumbprint>"}
	if req.DPoPJKT != "" {
		claims.Confirmation = map[string]interface{}{
			"jkt": req.DPoPJKT,
		}
	}

	// 获取签名密钥
	kid, key, err := iss.keyManager.GetSigningKey(ctx)
	if err != nil {
		return "", fmt.Errorf("failed to get signing key: %w", err)
	}

	// 确定签名方法
	method := GetSigningMethod(key)
	if method == nil {
		return "", ErrUnsupportedSigningKeyType
	}

	// 签名
	token := jwt.NewWithClaims(method, claims)
	token.Header["kid"] = kid

	signedStr, err := token.SignedString(key)
	if err != nil {
		return "", fmt.Errorf("failed to sign access token: %w", err)
	}

	return AccessToken(signedStr), nil
}

// idToken 构建并签名 ID Token
// includeNonce: Issue 流程为 true, Refresh 流程为 false
func (g *Issuer) idToken(ctx context.Context, req *IssuerRequest, at AccessToken, includeNonce bool, ttl time.Duration) (IDToken, error) {
	now := time.Now()
	uuidV7, err := uuid.NewV7()
	if err != nil {
		return "", ErrFailedToGenerateUUID
	}

	// 获取当前签名密钥
	kid, key, err := g.keyManager.GetSigningKey(ctx)
	if err != nil {
		return "", fmt.Errorf("failed to get signing key: %w", err)
	}

	// 确定签名方法
	method := GetSigningMethod(key)
	if method == nil {
		return "", ErrUnsupportedSigningKeyType
	}

	// OIDC 规范核心逻辑：计算 at_hash
	atHash, err := at.Hash(method)
	if err != nil {
		return "", err
	}

	var cHash string
	if req.Code != "" {
		cHash, err = req.Code.Hash(method)
		if err != nil {
			return "", err
		}
	}

	claims := IDTokenClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        uuidV7.String(),
			Issuer:    g.issuer,
			Subject:   req.UserID.String(),
			Audience:  jwt.ClaimStrings{req.ClientID.String()},
			ExpiresAt: jwt.NewNumericDate(now.Add(ttl)),
			IssuedAt:  jwt.NewNumericDate(now),
		},
		AuthTime:        req.AuthTime.Unix(),
		AtHash:          atHash,
		CHash:           cHash,
		AuthorizedParty: req.ClientID.String(),

		Name:                req.Name,
		PreferredUsername:   req.PreferredUsername,
		Picture:             req.Picture,
		Email:               req.Email,
		EmailVerified:       req.EmailVerified,
		PhoneNumber:         req.PhoneNumber,
		PhoneNumberVerified: req.PhoneNumberVerified,
	}

	if includeNonce {
		claims.Nonce = req.Nonce
	}

	token := jwt.NewWithClaims(method, &claims)
	token.Header["kid"] = kid

	signedStr, err := token.SignedString(key)
	if err != nil {
		return "", fmt.Errorf("failed to sign id token: %w", err)
	}
	return IDToken(signedStr), nil
}

// refreshToken 生成一个高熵随机字符串 (Opaque Token)
func (g *Issuer) refreshToken(ctx context.Context, userid BinaryUUID) (RefreshToken, error) {
	return IssueStructuredRefreshToken(ctx, g.secretManager, userid.String(), g.cfg.RefreshTokenTTL)
}
