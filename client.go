package oidc

import (
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// ClientConfig 客户端配置
type ClientConfig struct {
	Issuer       string
	ClientID     string
	ClientSecret string
	RedirectURI  string
	Scopes       []string
}

// Client 是 OIDC Relying Party (RP) 的全功能实现
type Client struct {
	cfg        ClientConfig
	httpClient *http.Client
	discovery  *Discovery

	// DPoP 签名密钥 (可选)
	dpopKey Key

	// ID Token 验证器
	verifier *ClientVerifier
}

// NewClient 创建一个新的 OIDC 客户端
// 它会自动从 Issuer 获取 Discovery 文档，并初始化 ID Token 验证器
func NewClient(ctx context.Context, cfg ClientConfig, httpClient *http.Client) (*Client, error) {
	if httpClient == nil {
		httpClient = http.DefaultClient
	}

	// 1. 自动发现配置
	discovery, err := Discover(ctx, cfg.Issuer, httpClient)
	if err != nil {
		return nil, fmt.Errorf("oidc: failed to discover issuer: %w", err)
	}

	// 2. 初始化远程 JWKS 加载器 (用于验证 ID Token)
	jwks := NewRemoteKeySet(ctx, discovery.JWKSURI, httpClient)

	// 3. 初始化验证器
	verifier := NewClientVerifier(cfg.Issuer, cfg.ClientID, jwks)

	return &Client{
		cfg:        cfg,
		httpClient: httpClient,
		discovery:  discovery,
		verifier:   verifier,
	}, nil
}

// AuthCodeOption 允许自定义请求参数
type AuthCodeOption func(url.Values)

func WithNonce(nonce string) AuthCodeOption {
	return func(v url.Values) {
		v.Set("nonce", nonce)
	}
}

func WithPKCE(codeChallenge, codeChallengeMethod string) AuthCodeOption {
	return func(v url.Values) {
		v.Set("code_challenge", codeChallenge)
		v.Set("code_challenge_method", codeChallengeMethod)
	}
}

// WithDPoP 启用 DPoP 支持
// 传入客户端的私钥 (建议使用 ECDSA P-256)，后续请求将自动附带 DPoP Proof
func (c *Client) WithDPoP(key Key) *Client {
	c.dpopKey = key
	return c
}

// GeneratePKCE 生成 PKCE 的 Verifier 和 Challenge
func (c *Client) GeneratePKCE() (verifier, challenge string, err error) {
	verifier, err = GeneratePKCEVerifier()
	if err != nil {
		return "", "", err
	}
	challenge, err = ComputePKCEChallenge(CodeChallengeMethodS256, verifier)
	return verifier, challenge, err
}

// ---------------------------------------------------------------------------
// Authorization Code Flow & PAR
// ---------------------------------------------------------------------------

// AuthCodeURL 生成标准授权跳转链接
func (c *Client) AuthCodeURL(state string, opts ...AuthCodeOption) string {
	return c.buildAuthorizeURL(state, opts...)
}

// PushAuthorize 执行 PAR (RFC 9126)，推送参数并返回带有 request_uri 的授权链接
func (c *Client) PushAuthorize(ctx context.Context, state string, opts ...AuthCodeOption) (authURL string, requestURI string, err error) {
	endpoint := c.discovery.PushedAuthorizationRequestEndpoint
	if endpoint == "" {
		return "", "", fmt.Errorf("oidc: server does not support PAR")
	}

	// 1. 准备参数
	v := c.baseAuthParams(state)
	for _, opt := range opts {
		opt(v)
	}

	// 2. 发送 PAR 请求 (需要客户端认证)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(v.Encode()))
	if err != nil {
		return "", "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	c.authenticateClient(req, v)

	// 处理 DPoP (如果启用)
	if err := c.applyDPoP(req); err != nil {
		return "", "", err
	}

	// 3. 执行请求
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		return "", "", c.parseError(resp.Body)
	}

	var parResp struct {
		RequestURI string `json:"request_uri"`
		ExpiresIn  int    `json:"expires_in"`
	}
	if err := DecodeJSON(resp.Body, &parResp); err != nil {
		return "", "", err
	}

	// 4. 构造最终跳转 URL
	u, _ := url.Parse(c.discovery.AuthorizationEndpoint)
	q := u.Query()
	q.Set("client_id", c.cfg.ClientID)
	q.Set("request_uri", parResp.RequestURI)
	u.RawQuery = q.Encode()

	return u.String(), parResp.RequestURI, nil
}

// ---------------------------------------------------------------------------
// Token Exchange
// ---------------------------------------------------------------------------

// Token 响应结构，包含 ID Token 解析后的 Claims
type Token struct {
	AccessToken   string         `json:"access_token"`
	TokenType     string         `json:"token_type"`
	RefreshToken  string         `json:"refresh_token,omitempty"`
	ExpiresIn     int            `json:"expires_in"`
	IDToken       string         `json:"id_token,omitempty"`
	Scope         string         `json:"scope,omitempty"`
	Expiry        time.Time      `json:"-"`
	IDTokenClaims *IDTokenClaims `json:"-"` // 解析并验证后的 ID Token
}

// ExchangeAuthorizationCode 使用授权码换取 Token
func (c *Client) ExchangeAuthorizationCode(ctx context.Context, code, codeVerifier string) (*Token, error) {
	v := url.Values{}
	v.Set("grant_type", "authorization_code")
	v.Set("code", code)
	if c.cfg.RedirectURI != "" {
		v.Set("redirect_uri", c.cfg.RedirectURI)
	}
	if codeVerifier != "" {
		v.Set("code_verifier", codeVerifier)
	}

	return c.doTokenRequest(ctx, v)
}

// ExchangeRefreshToken 刷新 Token
func (c *Client) ExchangeRefreshToken(ctx context.Context, refreshToken string) (*Token, error) {
	v := url.Values{}
	v.Set("grant_type", "refresh_token")
	v.Set("refresh_token", refreshToken)
	return c.doTokenRequest(ctx, v)
}

// ExchangeClientCredentials 客户端凭证模式 (M2M)
func (c *Client) ExchangeClientCredentials(ctx context.Context, scope ...string) (*Token, error) {
	v := url.Values{}
	v.Set("grant_type", "client_credentials")
	reqScope := strings.Join(c.cfg.Scopes, " ")
	if len(scope) > 0 {
		reqScope = strings.Join(scope, " ")
	}
	if reqScope != "" {
		v.Set("scope", reqScope)
	}
	return c.doTokenRequest(ctx, v)
}

// ---------------------------------------------------------------------------
// Device Flow
// ---------------------------------------------------------------------------

// RequestDeviceAuthorization 发起设备授权请求
func (c *Client) RequestDeviceAuthorization(ctx context.Context) (*DeviceAuthorizationResponse, error) {
	endpoint := c.discovery.DeviceAuthorizationEndpoint
	if endpoint == "" {
		return nil, fmt.Errorf("oidc: server does not support device flow")
	}

	v := url.Values{}
	v.Set("client_id", c.cfg.ClientID)
	if len(c.cfg.Scopes) > 0 {
		v.Set("scope", strings.Join(c.cfg.Scopes, " "))
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(v.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	// 注意：设备流通常是公共客户端，但也支持机密客户端认证
	if c.cfg.ClientSecret != "" {
		c.authenticateClient(req, v)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, c.parseError(resp.Body)
	}

	var devResp DeviceAuthorizationResponse
	if err := DecodeJSON(resp.Body, &devResp); err != nil {
		return nil, err
	}
	return &devResp, nil
}

// PollDeviceToken 轮询设备 Token
// 该方法会阻塞直到获取 Token、过期或发生错误
func (c *Client) PollDeviceToken(ctx context.Context, deviceCode string, interval int) (*Token, error) {
	if interval < 1 {
		interval = 5
	}
	ticker := time.NewTicker(time.Duration(interval) * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-ticker.C:
			v := url.Values{}
			v.Set("grant_type", "urn:ietf:params:oauth:grant-type:device_code")
			v.Set("device_code", deviceCode)
			v.Set("client_id", c.cfg.ClientID)

			// 这里直接调底层的请求，因为 doTokenRequest 会自动处理错误解析
			token, err := c.doTokenRequest(ctx, v)
			if err == nil {
				return token, nil
			}

			// 检查特定错误
			oidcErr, ok := err.(*Error)
			if !ok {
				// 非协议错误，直接返回
				return nil, err
			}

			switch oidcErr.Code {
			case "authorization_pending":
				// 继续等待
				continue
			case "slow_down":
				// 减慢轮询
				ticker.Reset(time.Duration(interval+5) * time.Second)
				continue
			case "access_denied", "expired_token":
				return nil, err
			default:
				return nil, err
			}
		}
	}
}

// ---------------------------------------------------------------------------
// Other Endpoints
// ---------------------------------------------------------------------------

// UserInfo 获取用户信息
func (c *Client) UserInfo(ctx context.Context, accessToken string) (*UserInfo, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.discovery.UserInfoEndpoint, nil)
	if err != nil {
		return nil, err
	}

	// 如果使用了 DPoP，Authentication 头格式为 "DPoP <token>"
	if c.dpopKey != nil {
		req.Header.Set("Authorization", "DPoP "+accessToken)
		if err := c.applyDPoP(req); err != nil {
			return nil, err
		}
	} else {
		req.Header.Set("Authorization", "Bearer "+accessToken)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, c.parseError(resp.Body)
	}

	var userInfo UserInfo
	if err := DecodeJSON(resp.Body, &userInfo); err != nil {
		return nil, fmt.Errorf("oidc: failed to decode userinfo: %w", err)
	}

	return &userInfo, nil
}

// Revoke 撤销 Token (Access Token 或 Refresh Token)
func (c *Client) Revoke(ctx context.Context, token string, hint string) error {
	endpoint := c.discovery.RevocationEndpoint
	if endpoint == "" {
		return fmt.Errorf("oidc: server does not support revocation")
	}

	v := url.Values{}
	v.Set("token", token)
	if hint != "" {
		v.Set("token_type_hint", hint)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(v.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	c.authenticateClient(req, v)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return c.parseError(resp.Body)
	}
	return nil
}

// Introspect 检查 Token 状态
func (c *Client) Introspect(ctx context.Context, token string) (*IntrospectionResponse, error) {
	endpoint := c.discovery.IntrospectionEndpoint
	if endpoint == "" {
		return nil, fmt.Errorf("oidc: server does not support introspection")
	}

	v := url.Values{}
	v.Set("token", token)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(v.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	c.authenticateClient(req, v)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, c.parseError(resp.Body)
	}

	var intro IntrospectionResponse
	if err := DecodeJSON(resp.Body, &intro); err != nil {
		return nil, err
	}
	return &intro, nil
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func (c *Client) baseAuthParams(state string) url.Values {
	v := url.Values{}
	v.Set("response_type", "code")
	v.Set("client_id", c.cfg.ClientID)
	if c.cfg.RedirectURI != "" {
		v.Set("redirect_uri", c.cfg.RedirectURI)
	}
	if len(c.cfg.Scopes) > 0 {
		v.Set("scope", strings.Join(c.cfg.Scopes, " "))
	}
	if state != "" {
		v.Set("state", state)
	}
	return v
}

func (c *Client) buildAuthorizeURL(state string, opts ...AuthCodeOption) string {
	u, _ := url.Parse(c.discovery.AuthorizationEndpoint)
	q := c.baseAuthParams(state)
	for _, opt := range opts {
		opt(q)
	}
	u.RawQuery = q.Encode()
	return u.String()
}

func (c *Client) doTokenRequest(ctx context.Context, v url.Values) (*Token, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.discovery.TokenEndpoint, strings.NewReader(v.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	// 客户端认证
	c.authenticateClient(req, v)

	// DPoP 处理
	if err := c.applyDPoP(req); err != nil {
		return nil, err
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, c.parseError(resp.Body)
	}

	var token Token
	if err := DecodeJSON(resp.Body, &token); err != nil {
		return nil, fmt.Errorf("oidc: failed to decode token response: %w", err)
	}

	if token.ExpiresIn > 0 {
		token.Expiry = time.Now().Add(time.Duration(token.ExpiresIn) * time.Second)
	}

	// 自动验证 ID Token
	if token.IDToken != "" && c.verifier != nil {
		claims, err := c.verifier.Verify(ctx, token.IDToken)
		if err != nil {
			return nil, fmt.Errorf("oidc: id_token verification failed: %w", err)
		}
		// 校验 nonce
		nonce := v.Get("nonce")
		if nonce != "" && claims.Nonce != nonce {
			return nil, fmt.Errorf("oidc: nonce mismatch")
		}
		token.IDTokenClaims = claims
	}

	return &token, nil
}

func (c *Client) authenticateClient(req *http.Request, v url.Values) {
	// 优先使用 Basic Auth 如果有 Secret
	if c.cfg.ClientSecret != "" {
		req.SetBasicAuth(c.cfg.ClientID, c.cfg.ClientSecret)
	} else {
		// Public Client 只能把 ClientID 放在 Body 里
		// 如果 Basic Auth 已经设置了，ClientCredential 模式下有些服务也要求 Body 带 ID
		if v.Get("client_id") == "" {
			// 由于 Body 已经做成 Reader 了，这里只能追加参数是比较麻烦的
			// 所以在构造 Values 时尽量保证完整，或者这里只处理 Header
			// 大部分 OIDC 实现允许 Basic Auth
		}
	}
}

func (c *Client) parseError(r io.Reader) error {
	var errResp Error
	if err := DecodeJSON(r, &errResp); err != nil {
		return fmt.Errorf("oidc: request failed with unparseable error")
	}
	return &errResp
}

// applyDPoP 生成并添加 DPoP Header
func (c *Client) applyDPoP(req *http.Request) error {
	if c.dpopKey == nil {
		return nil
	}

	// 确定 jwk
	pubKey := c.dpopKey.Public()

	// 转换为 JWK
	// 注意：DPoP 要求 JWK 不包含 kid, alg 等，只包含 key 参数
	// PublicKeyToJWK 生成了完整的结构，我们需要转成 map 并剔除多余字段
	// 这里直接复用生成逻辑，但在 Header 中只放必要的
	jwkObj, err := PublicKeyToJWK(pubKey, "", "")
	if err != nil {
		return err
	}

	// 手动构建 map 以完全控制字段
	jwkMap := make(map[string]interface{})
	jwkMap["kty"] = jwkObj.Kty
	jwkMap["crv"] = jwkObj.Crv
	jwkMap["x"] = jwkObj.X
	jwkMap["y"] = jwkObj.Y
	jwkMap["n"] = jwkObj.N
	jwkMap["e"] = jwkObj.E

	// 构建 Claims
	now := time.Now()
	jti := uuid.New().String()

	// RFC 9449: htu 不包含 query 和 fragment
	htu := BuildRequestURI(req)

	claims := jwt.MapClaims{
		"htm": req.Method,
		"htu": htu,
		"iat": now.Unix(),
		"jti": jti,
	}

	// 签名
	var method jwt.SigningMethod
	switch c.dpopKey.(type) {
	case *ecdsa.PrivateKey:
		method = jwt.SigningMethodES256
	case *rsa.PrivateKey:
		method = jwt.SigningMethodRS256
	}

	token := jwt.NewWithClaims(method, claims)
	token.Header["typ"] = "dpop+jwt"
	token.Header["jwk"] = jwkMap

	proof, err := token.SignedString(c.dpopKey)
	if err != nil {
		return fmt.Errorf("oidc: failed to sign dpop proof: %w", err)
	}

	req.Header.Set("DPoP", proof)
	return nil
}
