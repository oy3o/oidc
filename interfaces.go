package oidc

import (
	"context"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwk"
)

// ---------------------------------------------------------------------------
// Client Interfaces
// ---------------------------------------------------------------------------

// RegisteredClient 定义了 OIDC 协议流程中所需的客户端视图。
type RegisteredClient interface {
	// GetID 返回客户端 ID
	GetID() BinaryUUID

	// GetRedirectURIs 返回注册的回调地址列表
	GetRedirectURIs() []string

	// GetGrantTypes 返回允许的授权类型 (e.g., "authorization_code", "refresh_token")
	GetGrantTypes() []string

	// GetScope 返回客户端注册的允许 Scopes 字符串 (空格分隔)
	// OIDC Core 逻辑会用此与请求的 Scope 取交集
	GetScope() string

	// IsConfidential 返回是否为机密客户端 (Confidential vs Public)
	IsConfidential() bool

	// ValidateSecret 验证输入的明文密钥。
	// 对于 Public Client，此方法应直接返回 nil。
	// 对于 Confidential Client，实现层应处理哈希比对 (如 bcrypt/argon2)。
	ValidateSecret(ctx context.Context, hasher Hasher, secret string) error
}

// ClientMetadata 包含客户端注册信息
type ClientMetadata struct {
	ID                      BinaryUUID
	OwnerID                 BinaryUUID
	Secret                  String // 存储哈希后的 Secret。对于机密客户端，在调用 CreateClient 之前必须先通过 Hasher.Hash() 哈希
	RedirectURIs            []string
	GrantTypes              []string
	Scope                   string
	Name                    string
	LogoURI                 string
	TokenEndpointAuthMethod string
	IsConfidential          bool
	CreatedAt               time.Time
}

// ClientStorage 定义了获取客户端信息的接口。
type ClientStorage interface {
	// GetClient 根据 ID 获取客户端详情。
	// 如果未找到，应返回 ErrClientNotFound。
	GetClient(ctx context.Context, clientID BinaryUUID) (RegisteredClient, error)

	// CreateClient 注册新客户端
	// 注意：metadata.Secret 必须已经通过 Hasher.Hash() 哈希处理
	CreateClient(ctx context.Context, metadata ClientMetadata) (RegisteredClient, error)

	// UpdateClient 更新客户端元数据
	UpdateClient(ctx context.Context, clientID BinaryUUID, metadata ClientMetadata) (RegisteredClient, error)

	// DeleteClient 删除客户端
	DeleteClient(ctx context.Context, clientID BinaryUUID) error

	// ListClientsByOwner 根据所有者查询客户端 (可选)
	ListClientsByOwner(ctx context.Context, ownerID BinaryUUID) ([]RegisteredClient, error)

	// ListClients 列出所有客户端
	ListClients(ctx context.Context, query ListQuery) ([]RegisteredClient, error)
}

// ClientCache 定义了客户端信息的缓存接口。
type ClientCache interface {
	// GetClient 从缓存获取客户端
	GetClient(ctx context.Context, clientID BinaryUUID) (RegisteredClient, error)

	// SaveClient 将客户端存入缓存
	SaveClient(ctx context.Context, client RegisteredClient, ttl time.Duration) error

	// InvalidateClient 从缓存中移除客户端
	InvalidateClient(ctx context.Context, clientID BinaryUUID) error
}

// Hasher 定义了密码哈希和验证的接口。
type Hasher interface {
	// Hash 对给定的明文密码进行哈希处理。
	// 返回哈希后的字节切片或错误。
	Hash(ctx context.Context, password []byte) ([]byte, error)

	// Compare 将明文密码与已有的哈希值进行比较。
	// 如果匹配，则返回nil；否则返回错误。
	Compare(ctx context.Context, hashedPassword []byte, password []byte) error
}

// ReplayCache 定义了防重放攻击的缓存接口。
// 用于 DPoP (RFC 9449) 的 JTI (JWT ID) 去重。
type ReplayCache interface {
	// CheckAndStore 原子性地检查 JTI 是否已使用，若未使用则存储。
	// 返回 true 表示 JTI 已存在 (重放攻击)，false 表示首次使用。
	// ttl 参数指定 JTI 在缓存中的有效期。
	CheckAndStore(ctx context.Context, jti string, ttl time.Duration) (bool, error)
}

// PARStorage 管理推送授权请求 (Pushed Authorization Requests) 会话
// RFC 9126: OAuth 2.0 Pushed Authorization Requests
type PARStorage interface {
	// SavePARSession 保存 PAR 会话
	// requestURI: 格式为 "urn:ietf:params:oauth:request_uri:<唯一标识>"
	// req: 完整的授权请求参数
	// ttl: 会话有效期，RFC 建议 60 秒
	SavePARSession(ctx context.Context, requestURI string, req *AuthorizeRequest, ttl time.Duration) error

	// GetAndDeletePARSession 获取并删除 PAR 会话（原子操作）
	// PAR request_uri 只能使用一次
	GetAndDeletePARSession(ctx context.Context, requestURI string) (*AuthorizeRequest, error)
}

// ---------------------------------------------------------------------------
// Authorization Code Interfaces
// ---------------------------------------------------------------------------

// AuthCodeSession 包含授权码关联的所有上下文信息。
// 这些信息需要在 Exchange 阶段被恢复。
type AuthCodeSession struct {
	Code      string
	ClientID  BinaryUUID
	UserID    BinaryUUID
	AuthTime  time.Time
	ExpiresAt time.Time

	// (可选) 认证上下文引用和方法
	ACR string   // Authentication Context Class Reference
	AMR []string // Authentication Methods References

	// 原始请求参数，用于二次校验
	RedirectURI string
	Scope       string
	Nonce       string

	// PKCE (RFC 7636) 必须字段
	CodeChallenge       string
	CodeChallengeMethod string

	// DPoP (RFC 9449): JWK Thumbprint 绑定
	// 如果授权请求包含 DPoP Proof，将 jkt 绑定到 Auth Code
	// 在 Token Exchange 时验证，防止 Code Injection 攻击
	DPoPJKT string
}

type AuthCodeStorage interface {
	// SaveAuthCode 存储生成的授权码及其上下文。
	SaveAuthCode(ctx context.Context, session *AuthCodeSession) error

	// LoadAndConsumeAuthCode 查找并标记为已使用（防止重放）。
	// 这是一个原子操作：读取的同时必须确保下次读取失败或标记为已消耗。
	// 如果未找到或已过期/已消耗，应返回 ErrCodeNotFound。
	LoadAndConsumeAuthCode(ctx context.Context, code string) (*AuthCodeSession, error)
}

// ---------------------------------------------------------------------------
// Device Flow Interfaces (RFC 8628)
// ---------------------------------------------------------------------------

type DeviceCodeSession struct {
	DeviceCode      string
	UserCode        string
	ClientID        BinaryUUID
	Scope           string
	ExpiresAt       time.Time
	LastPolled      time.Time
	Status          string // "pending", "allowed", "denied"
	UserID          BinaryUUID
	AuthorizedScope string
}

type DeviceCodeStorage interface {
	// SaveDeviceCode 存储设备码和用户码
	SaveDeviceCode(ctx context.Context, session *DeviceCodeSession) error

	// GetDeviceCodeSession 根据设备码获取会话
	GetDeviceCodeSession(ctx context.Context, deviceCode string) (*DeviceCodeSession, error)

	// GetDeviceCodeSessionByUserCode 根据用户码获取会话 (用于用户授权页面)
	GetDeviceCodeSessionByUserCode(ctx context.Context, userCode string) (*DeviceCodeSession, error)

	// UpdateDeviceCodeSession 更新会话状态 (例如用户同意后)
	UpdateDeviceCodeSession(ctx context.Context, deviceCode string, session *DeviceCodeSession) error
}

// ---------------------------------------------------------------------------
// Token Interfaces
// ---------------------------------------------------------------------------

// RefreshTokenSession 包含刷新令牌关联的上下文信息。
type RefreshTokenSession struct {
	ID        Hash256
	ClientID  BinaryUUID
	UserID    BinaryUUID
	Scope     string
	AuthTime  time.Time
	ExpiresAt time.Time

	// 用于 OIDC 刷新的上下文
	Nonce string
	ACR   string
	AMR   []string
}

// TokenStorage 负责持久化刷新令牌 (Long-lived tokens)。
type TokenStorage interface {
	// CreateRefreshToken 存储新的刷新令牌。
	CreateRefreshToken(ctx context.Context, session *RefreshTokenSession) error

	// GetRefreshToken 根据令牌 ID (或哈希) 查找。
	// 如果未找到或过期，应返回 ErrTokenNotFound。
	GetRefreshToken(ctx context.Context, tokenID Hash256) (*RefreshTokenSession, error)

	// RotateRefreshToken 令牌轮换：删除旧的，保存新的。
	// 强烈建议在事务中执行：如果保存新令牌失败，旧令牌也不应被删除（或者整个操作回滚）。
	RotateRefreshToken(ctx context.Context, oldTokenID Hash256, newSession *RefreshTokenSession) error

	// RevokeRefreshToken 撤销指定的刷新令牌。
	RevokeRefreshToken(ctx context.Context, tokenID Hash256) error

	// RevokeTokensForUser 撤销指定用户的所有令牌 (例如用户登出或修改密码时)。
	RevokeTokensForUser(ctx context.Context, userID BinaryUUID) error
}

// TokenCache 定义了 Refresh Token 的缓存接口
type TokenCache interface {
	// GetRefreshToken 从缓存获取
	GetRefreshToken(ctx context.Context, tokenID Hash256) (*RefreshTokenSession, error)

	// SaveRefreshToken 存入缓存
	SaveRefreshToken(ctx context.Context, session *RefreshTokenSession, ttl time.Duration) error

	// InvalidateRefreshToken 从缓存移除
	InvalidateRefreshToken(ctx context.Context, tokenID Hash256) error
}

// TokenRotationStorage 负责快速检测刷新令牌的轮换状态。
type TokenRotationStorage interface {
	// MarkRefreshTokenAsRotating 标记旧 Token 进入宽限期
	// 在宽限期内，旧 Token 仍可刷新（但仅一次）
	// gracePeriod: 宽限期时长，建议 30 秒
	//
	// RFC 6749 说明：在网络不稳定环境中，客户端可能并发发送多个刷新请求
	// 宽限期允许客户端在短时间内使用旧 Token 重试，避免合法请求失败
	MarkRefreshTokenAsRotating(ctx context.Context, tokenID Hash256, gracePeriod time.Duration) error

	// IsInGracePeriod 检查 Token 是否在宽限期内
	// 返回 true 表示可以允许一次重试刷新
	IsInGracePeriod(ctx context.Context, tokenID Hash256) (bool, error)
}

// RevocationStorage 用于管理 Access Token 的黑名单 (Revocation List)。
// Access Token 通常是无状态 JWT，一旦签发无法修改，撤销只能通过黑名单 (JTI) 实现。
type RevocationStorage interface {
	// Revoke 将 JTI (JWT ID) 加入黑名单，直到 expiration 时间。
	Revoke(ctx context.Context, jti string, expiration time.Time) error

	// IsRevoked 检查 JTI 是否在黑名单中。
	IsRevoked(ctx context.Context, jti string) (bool, error)
}

// ---------------------------------------------------------------------------
// KeyStorage Interfaces
// ---------------------------------------------------------------------------

// KeyStorage 定义了私钥的持久化存储接口
// 必须支持分布式环境下的并发访问
type KeyStorage interface {
	// Save 存储一个 JWK (包含私钥)
	// 如果 key 已存在，应该覆盖或返回错误（取决于实现，通常是覆盖）
	Save(ctx context.Context, key jwk.Key) error

	// Get 获取指定 kid 的 JWK
	Get(ctx context.Context, kid string) (jwk.Key, error)

	// List 获取所有存储的 JWK
	List(ctx context.Context) ([]jwk.Key, error)

	// Delete 删除指定 kid 的 JWK
	Delete(ctx context.Context, kid string) error

	// SaveSigningKeyID 存储当前签名密钥 ID
	SaveSigningKeyID(ctx context.Context, kid string) error

	// GetSigningKeyID 获取当前签名密钥 ID
	GetSigningKeyID(ctx context.Context) (string, error)
}

// DistributedLock 定义了分布式锁接口
// 用于密钥轮换等需要互斥的操作
type DistributedLock interface {
	// Lock 尝试获取锁
	// ttl: 锁的自动过期时间
	// 返回: true 如果获取成功, false 如果已被占用
	Lock(ctx context.Context, key string, ttl time.Duration) (bool, error)

	// Unlock 释放锁
	Unlock(ctx context.Context, key string) error
}

// ---------------------------------------------------------------------------
// User Info Interfaces
// ---------------------------------------------------------------------------

// UserInfoGetter 用于从业务系统获取用户信息，以填充 ID Token 或响应 UserInfo 端点。
type UserInfoGetter interface {
	// GetUserInfo 根据 UserID 和请求的 Scopes 返回用户信息。
	// scope 参数允许实现层根据权限过滤返回字段 (例如：没有 'email' scope 就不查邮箱)。
	GetUserInfo(ctx context.Context, userID BinaryUUID, scopes []string) (*UserInfo, error)
}

// ---------------------------------------------------------------------------
// User Authentication Interfaces (仅用于测试流程，如 Password Grant)
// ---------------------------------------------------------------------------

// UserAuthenticator 定义用户认证接口。
// 此接口仅用于特殊场景（如负载测试的 Password Grant 流程），不应在生产环境的标准 OIDC 流程中使用。
type UserAuthenticator interface {
	// GetUser 根据用户名和密码进行认证。
	// 成功时返回用户 ID，失败时应返回 ErrUserNotFound。
	// 注意：此方法应实现速率限制和防暴力破解机制。
	GetUser(ctx context.Context, username, password string) (BinaryUUID, error)
}

// ---------------------------------------------------------------------------
// Storage Composition
// ---------------------------------------------------------------------------

// Persistence 负责长久存储的数据
// 建议实现：GORM (PostgreSQL)
type Persistence interface {
	ClientStorage
	KeyStorage     // JWK (基础设施)
	TokenStorage   // Refresh Token (长效)
	UserInfoGetter // 用户数据
	UserAuthenticator

	// Cleanup 清理过期的数据 (Garbage Collection)
	// 此方法应删除已过期的 RefreshToken, AuthCode, DeviceCode 等临时数据
	// 建议由后台 Worker 定期调用（例如每小时一次）
	// 返回被清理的记录数和错误
	Cleanup(ctx context.Context) (deleted int64, err error)
}

// Cache 负责临时、高频、需要自动过期的数据
// 建议实现：Redis
type Cache interface {
	AuthCodeStorage      // 极短 TTL
	DeviceCodeStorage    // 短 TTL
	DistributedLock      // 分布式锁
	PARStorage           // 极短 TTL
	ReplayCache          // DPoP JTI 防重放
	RevocationStorage    // Access Token 黑名单 (高频读取)
	TokenRotationStorage // 快速检测被轮转的 Refresh Token

	// 用于多级缓存, “缓存穿透”和“回写”的逻辑
	KeyStorage // JWK (基础设施)
	ClientCache
	TokenCache
}

// Storage 是一个聚合接口，方便在 Server 初始化时传递。
type Storage interface {
	Persistence
	Cache
}
