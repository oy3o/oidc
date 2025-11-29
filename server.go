package oidc

import (
	"context"
	"fmt"
	"slices"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/oy3o/o11y"
	"go.opentelemetry.io/otel/attribute"
	"golang.org/x/sync/singleflight"
)

// ServerConfig 用于初始化 OIDC Server 的配置
type ServerConfig struct {
	// Issuer 是服务的唯一标识符 (URL)，例如 "https://auth.example.com"
	Issuer string

	// Storage 是数据持久层接口实现
	Storage Storage

	// Hasher 是密码哈希器
	Hasher Hasher

	// SecretManager 用于管理 Refresh Token 签名的对称密钥 (HMAC)
	// 如果为 nil，NewServer 会初始化一个默认的 MemoryKeyProvider，但该 Provider 初始无密钥，
	// 需要通过 server.SecretManager() 获取实例后添加密钥，或者在 Config 中直接传入配置好的实例。
	SecretManager *SecretManager

	// 令牌有效期配置 (若为 0，NewServer 会设置默认值)
	CodeTTL         time.Duration // 默认 5 分钟
	AccessTokenTTL  time.Duration // 默认 1 小时
	RefreshTokenTTL time.Duration // 默认 30 天
	IDTokenTTL      time.Duration // 默认 1 小时

	// SupportedSigningAlgs 支持的签名算法 (默认为 RS256, ES256)
	SupportedSigningAlgs []string

	// EnableGC 是否启用垃圾回收 Worker (默认为 true)
	EnableGC bool

	// GCInterval GC 执行间隔 (默认 1 小时)
	GCInterval time.Duration
}

// Server 是 OIDC 协议的核心控制器。
// 它是一个 Facade (门面)，组合了 Authorizer, Issuer, TokenHandler 等组件。
// 调用者应通过 NewServer 创建实例，并将其挂载到 HTTP 路由上。
type Server struct {
	cfg ServerConfig

	// 核心组件
	storage       Storage
	keyManager    *KeyManager
	secretManager *SecretManager
	issuer        *Issuer
	hasher        Hasher
	gcWorker      *GCWorker // 垃圾回收 Worker
}

// NewServer 初始化一个新的 OIDC 服务。
// 注意：初始化后，必须：
// 1. 调用 server.KeyManager().Add(...) 添加至少一个签名密钥 (RSA/EC)
// 2. 调用 server.SecretManager().AddKey(...) 添加至少一个 HMAC 密钥 (用于 Refresh Token)
// 3. 调用 server.ValidateKeys() 验证密钥配置
// 4. 启动 HTTP 服务
func NewServer(cfg ServerConfig) (*Server, error) {
	// 1. 基础校验
	if cfg.Issuer == "" {
		return nil, fmt.Errorf("oidc: issuer url is required")
	}
	if cfg.Storage == nil {
		return nil, fmt.Errorf("oidc: storage implementation is required")
	}
	if cfg.Hasher == nil {
		return nil, fmt.Errorf("oidc: hasher implementation is required")
	}

	// 2. 设置默认 TTL
	if cfg.CodeTTL == 0 {
		cfg.CodeTTL = 5 * time.Minute
	}
	if cfg.AccessTokenTTL == 0 {
		cfg.AccessTokenTTL = 1 * time.Hour
	}
	if cfg.RefreshTokenTTL == 0 {
		cfg.RefreshTokenTTL = 24 * 30 * time.Hour
	}
	if cfg.IDTokenTTL == 0 {
		cfg.IDTokenTTL = 1 * time.Hour
	}
	if len(cfg.SupportedSigningAlgs) == 0 {
		cfg.SupportedSigningAlgs = DefaultSupportedSigningAlgs
	}

	// 3. 初始化基础组件
	km := NewKeyManager(cfg.Storage, 0)

	sm := cfg.SecretManager
	if sm == nil {
		sm = NewSecretManager()
	}

	// 4. 初始化 Issuer
	issuerCfg := IssuerConfig{
		Issuer:          cfg.Issuer,
		AccessTokenTTL:  cfg.AccessTokenTTL,
		RefreshTokenTTL: cfg.RefreshTokenTTL,
		IDTokenTTL:      cfg.IDTokenTTL,
		SecretManager:   sm, // 传递 SecretManager
	}
	issuer, err := NewIssuer(issuerCfg, km)
	if err != nil {
		return nil, fmt.Errorf("oidc: failed to create issuer: %w", err)
	}

	s := &Server{
		cfg:           cfg,
		storage:       cfg.Storage,
		hasher:        cfg.Hasher,
		keyManager:    km,
		secretManager: sm,
		issuer:        issuer,
	}

	// 5. 初始化 GC Worker (如果启用)
	if cfg.EnableGC {
		gcInterval := cfg.GCInterval
		if gcInterval == 0 {
			gcInterval = time.Hour // 默认 1 小时
		}
		s.gcWorker = NewGCWorker(cfg.Storage, gcInterval)
	}

	return s, nil
}

// ---------------------------------------------------------------------------
// Component Accessors (Getters)
// ---------------------------------------------------------------------------

func (s *Server) Config() *ServerConfig {
	return &s.cfg
}

// Issuer 返回 Issuer，用于生成 Token。
func (s *Server) Issuer() *Issuer {
	return s.issuer
}

// KeyManager 返回密钥管理器，用于添加、删除密钥或导出 JWKS。
func (s *Server) KeyManager() *KeyManager {
	return s.keyManager
}

// SecretManager 返回 HMAC 密钥管理器，用于 Refresh Token 的签名管理。
func (s *Server) SecretManager() *SecretManager {
	return s.secretManager
}

// ValidateKeys 检查密钥管理器是否至少配置了一个签名密钥。
// 应在启动 HTTP 服务前调用，以尽早发现配置错误。
//
// 返回 ErrNoSigningKey 如果未配置任何签名密钥。
func (s *Server) ValidateKeys(ctx context.Context) error {
	// 验证非对称密钥 (Access Token / ID Token)
	if _, _, err := s.keyManager.GetSigningKey(ctx); err != nil {
		return fmt.Errorf("signing key check failed: %w", err)
	}

	// 验证对称密钥 (Refresh Token)
	if key, _ := s.secretManager.GetSigningKey(ctx); len(key) == 0 {
		return fmt.Errorf("hmac key check failed: no active key for refresh tokens")
	}

	return nil
}

// --
// Special Methods (可能需要管理员权限, 管理客户端等)
// --

// RegisterClient 处理动态客户端注册
func (s *Server) RegisterClient(ctx context.Context, req *ClientRegistrationRequest) (*ClientRegistrationResponse, error) {
	return RegisterClient(ctx, s.storage, s.hasher, req)
}

// UnregisterClient 处理动态客户端注销
func (s *Server) UnregisterClient(ctx context.Context, clientIDStr string) error {
	return UnregisterClient(ctx, s.storage, clientIDStr)
}

// UpdateClient 处理动态客户端更新
func (s *Server) UpdateClient(ctx context.Context, req *ClientUpdateRequest) (*ClientRegistrationResponse, error) {
	return UpdateClient(ctx, s.storage, req)
}

// ListClient 列出所有客户端
func (s *Server) ListClient(ctx context.Context, query ListQuery) ([]RegisteredClient, error) {
	return ListClient(ctx, s.storage, query)
}

// ---------------------------------------------------------------------------
// Public Methods (直接对外暴露业务能力，内部调用独立函数)
// ---------------------------------------------------------------------------

// RequestAuthorize 校验授权请求
func (s *Server) RequestAuthorize(ctx context.Context, req *AuthorizeRequest) (client RegisteredClient, err error) {
	err = o11y.Run(ctx, "oidc.RequestAuthorize", func(ctx context.Context, state o11y.State) error {
		state.SetAttributes(attribute.String("client_id", req.ClientID))
		state.SetAttributes(attribute.String("response_type", req.ResponseType))
		client, err = RequestAuthorize(ctx, s.storage, req)
		return err
	})
	return
}

// ResponseAuthorized 用户同意后生成重定向URL
func (s *Server) ResponseAuthorized(ctx context.Context, req *AuthorizeRequest) (redirectURL string, err error) {
	err = o11y.Run(ctx, "oidc.ResponseAuthorized", func(ctx context.Context, state o11y.State) error {
		state.SetAttributes(attribute.String("client_id", req.ClientID))
		state.SetAttributes(attribute.String("user_id", req.UserID))
		redirectURL, err = ResponseAuthorized(ctx, s.storage, req, s.cfg.CodeTTL)
		return err
	})
	return
}

// DeviceAuthorization 处理设备授权请求
func (s *Server) DeviceAuthorization(ctx context.Context, req *DeviceAuthorizationRequest) (*DeviceAuthorizationResponse, error) {
	return DeviceAuthorization(ctx, s.storage, s.cfg.Issuer, req)
}

// EndSession 处理用户登出
func (s *Server) EndSession(ctx context.Context, req *EndSessionRequest) (string, error) {
	return EndSession(ctx, s.storage, s, req)
}

// PushedAuthorization 处理推送授权请求 (PAR - RFC 9126)
func (s *Server) PushedAuthorization(ctx context.Context, req *PARRequest) (*PARResponse, error) {
	return PushedAuthorization(ctx, s.storage, s.hasher, req)
}

// Exchange 处理 Token 交换
func (s *Server) Exchange(ctx context.Context, req *TokenRequest) (resp *IssuerResponse, err error) {
	err = o11y.Run(ctx, "oidc.Exchange", func(ctx context.Context, state o11y.State) error {
		state.SetAttributes(attribute.String("grant_type", req.GrantType))

		if req.DPoPJKT == "" {
			req.DPoPJKT = ExtractDPoPJKT(ctx)
		}

		switch req.GrantType {
		case GrantTypeAuthorizationCode:
			resp, err = ExchangeCode(ctx, s.storage, s.hasher, s.issuer, req)
		case GrantTypeRefreshToken:
			resp, err = RefreshTokens(ctx, s.storage, s.secretManager, s.hasher, s.issuer, req)
		case GrantTypeDeviceCode:
			resp, err = DeviceTokenExchange(ctx, s.storage, s.issuer, req)
		case GrantTypeClientCredentials:
			resp, err = ExchangeClientCredentials(ctx, s.storage, s.hasher, s.issuer, req)
		case GrantTypePassword: // 仅供压力测试使用, 环境会返回错误
			resp, err = PasswordGrant(ctx, s.storage, s.hasher, s.issuer, req)
		default:
			err = ErrUnsupportedGrantType
		}
		return err
	})
	return
}

// RevokeToken 处理 Token 撤销
func (s *Server) RevokeToken(ctx context.Context, req *RevocationRequest) error {
	return o11y.Run(ctx, "oidc.RevokeToken", func(ctx context.Context, state o11y.State) error {
		return RevokeToken(ctx, s.storage, s.secretManager, s.hasher, s, req)
	})
}

// GetUserInfo 获取用户信息
func (s *Server) GetUserInfo(ctx context.Context, claims *AccessTokenClaims) (*UserInfo, error) {
	// Server 自身作为 Verifier 传入
	return GetUserInfo(ctx, s.storage, s, claims)
}

// Introspect 验证 Token 状态
func (s *Server) Introspect(ctx context.Context, tokenStr, clientIDStr, clientSecret string) (*IntrospectionResponse, error) {
	return Introspect(ctx, s.storage, s, tokenStr, clientIDStr, clientSecret, s.hasher)
}

// ---------------------------------------------------------------------------
// Discovery Endpoint
// ---------------------------------------------------------------------------

// Discovery 返回符合 OIDC Discovery 标准的元数据结构。
// 调用者应将其序列化为 JSON 并通过 /.well-known/openid-configuration 暴露。
func (s *Server) Discovery() *Discovery {
	return &Discovery{
		Issuer:                             s.cfg.Issuer,
		AuthorizationEndpoint:              s.cfg.Issuer + "/authorize",
		TokenEndpoint:                      s.cfg.Issuer + "/token",
		JWKSURI:                            s.cfg.Issuer + "/jwks.json",
		UserInfoEndpoint:                   s.cfg.Issuer + "/userinfo",
		RevocationEndpoint:                 s.cfg.Issuer + "/revoke",
		IntrospectionEndpoint:              s.cfg.Issuer + "/introspect",
		DeviceAuthorizationEndpoint:        s.cfg.Issuer + "/device/authorize",
		EndSessionEndpoint:                 s.cfg.Issuer + "/endsession",
		RegistrationEndpoint:               s.cfg.Issuer + "/register",
		PushedAuthorizationRequestEndpoint: s.cfg.Issuer + "/par", // RFC 9126

		// 动态能力标识
		ScopesSupported:        []string{ScopeOpenID, ScopeProfile, ScopeEmail, ScopePhone, ScopeOfflineAccess},
		ResponseTypesSupported: []string{ResponseTypeCode}, // 目前仅实现了 Code Flow
		GrantTypesSupported:    []string{GrantTypeAuthorizationCode, GrantTypeRefreshToken, GrantTypeClientCredentials},
		SubjectTypesSupported:  []string{SubjectTypePublic},

		// 算法支持 (取决于 KeyManager 支持的类型，这里列出常见的)
		IDTokenSigningAlgValuesSupported: s.cfg.SupportedSigningAlgs,

		// Client 认证方式
		TokenEndpointAuthMethodsSupported: []string{AuthMethodClientSecretBasic, AuthMethodClientSecretPost},

		// Claims
		ClaimsSupported: []string{
			"iss", "sub", "aud", "exp", "iat", "auth_time",
			"name", "email", "email_verified", "picture",
		},

		// PKCE
		CodeChallengeMethodsSupported: []string{CodeChallengeMethodS256, CodeChallengeMethodPlain},
	}
}

// ---------------------------------------------------------------------------
// Interface Implementations
// ---------------------------------------------------------------------------

// SingleFlight 合并并发请求, 防止同一个 Token 在极短时间内发起数万次攻击
var verifierGroup singleflight.Group

// VerifyAccessToken 用于验证 Bearer Token 的有效性。
// 此实现不校验 Audience，因为 UserInfo 端点信任本 Issuer 签发的任何包含 openid scope 的 Token。
func (s *Server) VerifyAccessToken(ctx context.Context, tokenStr string) (*AccessTokenClaims, error) {
	val, err, _ := verifierGroup.Do(tokenStr, func() (any, error) {
		var claims *AccessTokenClaims
		// 我们把 o11y 放在 Do 里面，意味着只有“执行者”会产生详细的 Trace 和 Log
		// 这对防 DDoS 是好事，减少了日志系统压力
		err := o11y.Run(ctx, "oidc.VerifyAccessToken", func(ctx context.Context, state o11y.State) error {
			var err error
			// 1. 解析并验证签名、Issuer
			claims, err = s.ParseAccessToken(ctx, tokenStr)
			if err != nil {
				return err
			}

			state.SetAttributes(attribute.String("user_id", claims.Subject))
			state.SetAttributes(attribute.String("client_id", claims.AuthorizedParty))

			// 2. 验证撤销状态 (Revocation List)
			// 如果 Access Token 有 JTI，检查是否被撤销
			if claims.ID != "" {
				isRevoked, err := s.storage.IsRevoked(ctx, claims.ID)
				if err != nil {
					return fmt.Errorf("failed to check revocation: %w", err)
				}
				if isRevoked {
					return ErrTokenRevoked
				}
			}
			return nil
		})
		// 将结果返回给 singleflight
		return claims, err
	})

	if err != nil {
		return nil, err
	}

	// 类型断言：将 interface{} 还原为具体的类型
	return val.(*AccessTokenClaims), nil
}

// SingleFlight 合并并发请求, 防止同一个 Token 在极短时间内发起数万次攻击
var validateGroup singleflight.Group

// ParseAccessToken 解析并验证 Token 签名和 Issuer，但不检查撤销状态。
func (s *Server) ParseAccessToken(ctx context.Context, tokenStr string) (*AccessTokenClaims, error) {
	val, err, _ := validateGroup.Do(tokenStr, func() (any, error) {
		// 1. 定义 KeyFunc 查找公钥
		keyFunc := func(token *jwt.Token) (interface{}, error) {
			// 强制校验签名算法类型，防止 "none" 算法攻击
			if !slices.Contains(s.cfg.SupportedSigningAlgs, token.Method.Alg()) {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}

			kid, _ := token.Header["kid"].(string)
			// 使用 KeyManager 查找公钥
			return s.keyManager.GetKey(ctx, kid)
		}

		// 2. 解析 Token
		var claims AccessTokenClaims
		token, err := jwt.ParseWithClaims(tokenStr, &claims, keyFunc)
		if err != nil {
			// jwt.ParseWithClaims 已经处理了过期时间(exp)的校验
			return nil, fmt.Errorf("%w: %w", ErrInvalidGrant, err)
		}

		if !token.Valid {
			return nil, fmt.Errorf("%w: token is invalid", ErrInvalidGrant)
		}

		// 3. 验证 Issuer
		if claims.Issuer != s.cfg.Issuer {
			return nil, fmt.Errorf("%w: issuer mismatch (expected %s, got %s)", ErrInvalidIssuer, s.cfg.Issuer, claims.Issuer)
		}

		return &claims, nil
	})
	if err != nil {
		return nil, err
	}

	return val.(*AccessTokenClaims), nil
}
