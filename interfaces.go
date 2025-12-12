package oidc

import (
	"context"
	"time"

	"github.com/bytedance/sonic"
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

	// 提供给Redis一个序列化和反序列化的方法
	Serialize() (string, error)
	Deserialize(string) error
}

// ClientFactory 定义了创建客户端的接口。
type ClientFactory interface {
	New() RegisteredClient
}

// ClientMetadata 客户端注册信息
// 对应 OAuth 2.0 Dynamic Client Registration Protocol
type ClientMetadata struct {
	// ID: 主键，使用 UUID
	ID BinaryUUID `db:"id"`

	// OwnerID: 用于查询“我创建的应用”，需要索引
	OwnerID BinaryUUID `db:"owner_id"`

	// Secret: 客户端密钥，经过哈希，预留足够长度
	Secret SecretString `db:"secret"`

	// Name: 应用名称
	Name string `db:"name"`

	// 数组类型处理：
	RedirectURIs StringSlice `db:"redirect_uris"`
	GrantTypes   StringSlice `db:"grant_types"`

	// Scope: 空格分隔的字符串，或者也可以用 type:text
	Scope string `db:"scope"`

	LogoURI                 string `db:"logo_uri"`
	TokenEndpointAuthMethod string `db:"token_endpoint_auth_method"`

	// IsConfidentialClient: 区分公开/机密客户端
	IsConfidentialClient bool `db:"is_confidential_client"`

	CreatedAt time.Time `db:"created_at"`
	UpdatedAt time.Time `db:"updated_at"`
}

func (ClientMetadata) TableName() string            { return "oidc_clients" }
func (c *ClientMetadata) GetID() BinaryUUID         { return c.ID }
func (c *ClientMetadata) GetRedirectURIs() []string { return c.RedirectURIs }
func (c *ClientMetadata) GetGrantTypes() []string   { return c.GrantTypes }
func (c *ClientMetadata) GetScope() string          { return c.Scope }
func (c *ClientMetadata) IsConfidential() bool      { return c.IsConfidentialClient }
func (c *ClientMetadata) Serialize() (string, error) {
	// 1. 定义一个别名。Aux 拥有 ClientMetadata 的所有字段，
	// 但不会继承 ClientMetadata 及其字段类型（SecretString）绑定的方法。
	type Aux ClientMetadata

	// 2. 创建一个影子结构体
	aux := &struct {
		// 强制将 SecretString 转换为 string，绕过脱敏逻辑
		Secret string `json:"secret"`
		*Aux
	}{
		Secret: string(c.Secret),
		Aux:    (*Aux)(c),
	}

	b, err := sonic.ConfigDefault.Marshal(aux)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func (c *ClientMetadata) Deserialize(data string) error {
	type Alias ClientMetadata

	// 同样使用影子结构体来接收数据
	aux := &struct {
		Secret string `json:"secret"`
		*Alias
	}{
		Alias: (*Alias)(c),
	}

	if err := sonic.ConfigDefault.Unmarshal([]byte(data), &aux); err != nil {
		return err
	}

	// 还原回 SecretString 类型
	c.Secret = SecretString(aux.Secret)
	return nil
}

// ValidateSecret 需要 hasher 协助，这里只提供数据，逻辑在 Server 层或 Storage 方法中
// 为了满足接口，我们在 Storage 实现中处理，这里仅作占位
func (c *ClientMetadata) ValidateSecret(ctx context.Context, hasher Hasher, secret string) error {
	// 如果是 Public Client，无需验证
	if !c.IsConfidentialClient {
		return nil
	}
	if hasher == nil {
		return ErrHasherNotConfigured
	}
	return hasher.Compare(ctx, []byte(c.Secret), []byte(secret))
}

// ClientStorage 定义了获取客户端信息的接口。
type ClientStorage interface {
	// ClientGetByID 根据 ID 获取客户端详情。
	// 如果未找到，应返回 ErrClientNotFound。
	ClientGetByID(ctx context.Context, clientID BinaryUUID) (RegisteredClient, error)

	// ClientCreate 注册新客户端
	// 注意：metadata.Secret 必须已经通过 Hasher.Hash() 哈希处理
	ClientCreate(ctx context.Context, metadata *ClientMetadata) (RegisteredClient, error)

	// ClientUpdate 更新客户端元数据
	ClientUpdate(ctx context.Context, clientID BinaryUUID, metadata *ClientMetadata) (RegisteredClient, error)

	// ClientDeleteByID 删除客户端
	ClientDeleteByID(ctx context.Context, clientID BinaryUUID) error

	// ClientListByOwner 根据所有者查询客户端 (可选)
	ClientListByOwner(ctx context.Context, ownerID BinaryUUID) ([]RegisteredClient, error)

	// ClientListAll 列出所有客户端
	ClientListAll(ctx context.Context, query ListQuery) ([]RegisteredClient, error)
}

// ClientCache 定义了客户端信息的缓存接口。
type ClientCache interface {
	// ClientGetByID 从缓存获取客户端
	ClientGetByID(ctx context.Context, clientID BinaryUUID) (RegisteredClient, error)

	// ClientSave 将客户端存入缓存
	ClientSave(ctx context.Context, client RegisteredClient, ttl time.Duration) error

	// ClientInvalidate 从缓存中移除客户端
	ClientInvalidate(ctx context.Context, clientID BinaryUUID) error
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
	// PARSessionSave 保存 PAR 会话
	// requestURI: 格式为 "urn:ietf:params:oauth:request_uri:<唯一标识>"
	// req: 完整的授权请求参数
	// ttl: 会话有效期，RFC 建议 60 秒
	PARSessionSave(ctx context.Context, requestURI string, req *AuthorizeRequest, ttl time.Duration) error

	// PARSessionConsume 获取并删除 PAR 会话（原子操作）
	// PAR request_uri 只能使用一次
	PARSessionConsume(ctx context.Context, requestURI string) (*AuthorizeRequest, error)
}

// ---------------------------------------------------------------------------
// Authorization Code Interfaces
// ---------------------------------------------------------------------------

// AuthCodeSession 授权码会话 (临时数据), 这些信息需要在 Exchange 阶段被恢复。
// 存活时间极短 (通常 < 10分钟)，读写极高
type AuthCodeSession struct {
	// Code: 授权码本身作为主键，必须是唯一的
	Code string `db:"code"`

	// 关联索引：Token Exchange 时需验证 ClientID，且包含 UserID
	ClientID BinaryUUID `db:"client_id"`
	UserID   BinaryUUID `db:"user_id"`

	AuthTime time.Time
	// ExpiresAt: 必须加索引，用于定期清理过期数据 (GC)
	ExpiresAt time.Time `db:"expires_at"`

	// ACR/AMR: 认证上下文 (可选)
	ACR string   `db:"acr"`
	AMR []string `db:"amr"`

	// 原始请求参数校验
	RedirectURI string `db:"redirect_uri"`
	Scope       string `db:"scope"`
	Nonce       string `db:"nonce"`

	// PKCE (RFC 7636): 必须字段
	CodeChallenge       string `db:"code_challenge"`
	CodeChallengeMethod string `db:"code_challenge_method"`

	// DPoP JKT (RFC 9449): 绑定指纹，防止 Code 窃取
	DPoPJKT string `db:"d_pop_jkt"`
}

func (AuthCodeSession) TableName() string { return "oidc_auth_codes" }

type AuthCodeStorage interface {
	// AuthCodeSave 存储生成的授权码及其上下文。
	AuthCodeSave(ctx context.Context, session *AuthCodeSession) error

	// AuthCodeConsume 查找并标记为已使用（防止重放）。
	// 这是一个原子操作：读取的同时必须确保下次读取失败或标记为已消耗。
	// 如果未找到或已过期/已消耗，应返回 ErrCodeNotFound。
	AuthCodeConsume(ctx context.Context, code string) (*AuthCodeSession, error)
}

// ---------------------------------------------------------------------------
// Device Flow Interfaces (RFC 8628)
// ---------------------------------------------------------------------------

// DeviceCodeSession 设备流会话 (RFC 8628)
type DeviceCodeSession struct {
	// DeviceCode: 设备换取 Token 的凭证，主键
	DeviceCode string `db:"device_code"`

	// UserCode: 用户在浏览器输入的短码，必须唯一且有索引
	UserCode string `db:"user_code"`

	ClientID BinaryUUID `db:"client_id"`
	UserID   BinaryUUID `db:"user_id"` // 初始为空，用户授权后填充

	Scope      string    `db:"scope"`
	ExpiresAt  time.Time `db:"expires_at"` // 用于清理
	LastPolled time.Time // 用于频率限制 (Rate Limiting)检查

	// Status: pending, allowed, denied
	Status string `db:"status"`

	AuthTime        time.Time
	AuthorizedScope string `db:"authorized_scope"` // 用户实际同意的 Scope
}

func (DeviceCodeSession) TableName() string { return "oidc_device_codes" }

type DeviceCodeStorage interface {
	// DeviceCodeSave 存储设备码和用户码
	DeviceCodeSave(ctx context.Context, session *DeviceCodeSession) error

	// DeviceCodeGet 根据设备码获取会话
	DeviceCodeGet(ctx context.Context, deviceCode string) (*DeviceCodeSession, error)

	// DeviceCodeGetByUserCode 根据用户码获取会话 (用于用户授权页面)
	DeviceCodeGetByUserCode(ctx context.Context, userCode string) (*DeviceCodeSession, error)

	// DeviceCodeUpdate 更新会话状态 (例如用户同意后)
	DeviceCodeUpdate(ctx context.Context, deviceCode string, session *DeviceCodeSession) error

	// DeviceCodeDelete 删除设备码会话及其关联索引
	DeviceCodeDelete(ctx context.Context, deviceCode string) error
}

// ---------------------------------------------------------------------------
// Token Interfaces
// ---------------------------------------------------------------------------

// RefreshTokenSession 包含刷新令牌关联的上下文信息。
type RefreshTokenSession struct {
	// ID 默认为主键，无需标签
	// GORM 默认将 Hash256 映射为对应类型（需实现 Scanner/Valuer）
	ID Hash256

	// 默认映射为 client_id，但在 db 标签中指定 index
	ClientID BinaryUUID `db:"client_id"`

	// 默认映射为 user_id，指定 index
	UserID BinaryUUID `db:"user_id"`

	// 指定数据库类型为 text
	Scope string `db:"scope"`

	// 默认映射 auth_time
	AuthTime time.Time

	// 默认映射 expires_at，指定 index
	ExpiresAt time.Time `db:"expires_at"`

	// 上下文信息
	Nonce string      // 默认 varchar
	ACR   string      // 默认 varchar
	AMR   StringSlice `db:"amr"`
}

func (RefreshTokenSession) TableName() string { return "oidc_refresh_tokens" }

// TokenStorage 负责持久化刷新令牌 (Long-lived tokens)。
type TokenStorage interface {
	// RefreshTokenCreate 存储新的刷新令牌。
	RefreshTokenCreate(ctx context.Context, session *RefreshTokenSession) error

	// RefreshTokenGet 根据令牌 ID (或哈希) 查找。
	// 如果未找到或过期，应返回 ErrTokenNotFound。
	RefreshTokenGet(ctx context.Context, tokenID Hash256) (*RefreshTokenSession, error)

	// RefreshTokenRotate 令牌轮换：删除旧的，保存新的。
	// 强烈建议在事务中执行：如果保存新令牌失败，旧令牌也不应被删除（或者整个操作回滚）。
	RefreshTokenRotate(ctx context.Context, oldTokenID Hash256, newSession *RefreshTokenSession, gracePeriod time.Duration) error

	// RefreshTokenRevoke 撤销指定的刷新令牌。
	RefreshTokenRevoke(ctx context.Context, tokenID Hash256) error

	// RefreshTokenRevokeUser 撤销指定用户的所有令牌 (例如用户登出或修改密码时)。
	RefreshTokenRevokeUser(ctx context.Context, userID BinaryUUID) ([]Hash256, error)

	// RefreshTokenListByUser 列出指定用户的所有活跃令牌。
	RefreshTokenListByUser(ctx context.Context, userID BinaryUUID) ([]*RefreshTokenSession, error)
}

// TokenCache 定义了 Refresh Token 的缓存接口
type TokenCache interface {
	// RefreshTokenGet 从缓存获取
	RefreshTokenGet(ctx context.Context, tokenID Hash256) (*RefreshTokenSession, error)

	// RefreshTokenSave 存入缓存
	RefreshTokenSave(ctx context.Context, session *RefreshTokenSession, ttl time.Duration) error

	// RefreshTokenRotate 令牌轮换：删除旧的，保存新的。如果保存新令牌失败，旧令牌也不应被删除（或者整个操作回滚）。
	RefreshTokenRotate(ctx context.Context, oldTokenID Hash256, newSession *RefreshTokenSession, gracePeriod time.Duration) error

	// RefreshTokenInvalidate 从缓存移除
	RefreshTokenInvalidate(ctx context.Context, tokenID Hash256) error

	// RefreshTokensInvalidate 批量从缓存移除
	RefreshTokensInvalidate(ctx context.Context, tokenIDs []Hash256) error
}

// RevocationStorage 用于管理 Access Token 的黑名单 (Revocation JWKList)。
// Access Token 通常是无状态 JWT，一旦签发无法修改，撤销只能通过黑名单 (JTI) 实现。
type RevocationStorage interface {
	// AccessTokenRevoke 将 JTI (JWT ID) 加入黑名单，直到 expiration 时间。
	AccessTokenRevoke(ctx context.Context, jti string, expiration time.Time) error

	// AccessTokenIsRevoked 检查 JTI 是否在黑名单中。
	AccessTokenIsRevoked(ctx context.Context, jti string) (bool, error)
}

// ---------------------------------------------------------------------------
// KeyStorage Interfaces
// ---------------------------------------------------------------------------

// KeyStorage 定义了私钥的持久化存储接口
// 必须支持分布式环境下的并发访问
type KeyStorage interface {
	// JWKSave 存储一个 JWK (包含私钥)
	// 如果 key 已存在，应该覆盖或返回错误（取决于实现，通常是覆盖）
	JWKSave(ctx context.Context, key jwk.Key) error

	// JWKGet 获取指定 kid 的 JWK
	JWKGet(ctx context.Context, kid string) (jwk.Key, error)

	// JWKList 获取所有存储的 JWK
	JWKList(ctx context.Context) ([]jwk.Key, error)

	// JWKDelete 删除指定 kid 的 JWK
	JWKDelete(ctx context.Context, kid string) error

	// JWKMarkSigning 存储当前签名密钥 ID
	JWKMarkSigning(ctx context.Context, kid string) error

	// JWKGetSigning 获取当前签名密钥 ID
	JWKGetSigning(ctx context.Context) (string, error)
}

// JWK 存储轮转的加密密钥
type JWK struct {
	// KID: Key ID，主键
	KID string `db:"kid"`

	// JWK: 包含私钥的大段 JSON 文本，使用 text 类型
	JWK SecretString `db:"jwk"`

	CreatedAt time.Time `db:"created_at"`
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
	// 测试中需要添加可查询的用户信息
	UserCreateInfo(ctx context.Context, userInfo *UserInfo) error
	// UserGetInfoByID 根据 UserID 和请求的 Scopes 返回用户信息。
	// scope 参数允许实现层根据权限过滤返回字段 (例如：没有 'email' scope 就不查邮箱)。
	UserGetInfoByID(ctx context.Context, userID BinaryUUID, scopes []string) (*UserInfo, error)
}

// ---------------------------------------------------------------------------
// User Authentication Interfaces (仅用于测试流程，如 Password Grant)
// ---------------------------------------------------------------------------

// UserAuthenticator 定义用户认证接口。
// 此接口仅用于特殊场景（如负载测试的 Password Grant 流程），不应在生产环境的标准 OIDC 流程中使用。
type UserAuthenticator interface {
	// AuthenticateByPassword 根据用户名和密码进行认证。
	// 成功时返回用户 ID，失败时应返回 ErrUserNotFound。
	// 注意：此方法应实现速率限制和防暴力破解机制。
	AuthenticateByPassword(ctx context.Context, username, password string) (BinaryUUID, string, error)
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
	Close()
}

// Cache 负责临时、高频、需要自动过期的数据
// 建议实现：Redis
type Cache interface {
	AuthCodeStorage   // 极短 TTL
	DeviceCodeStorage // 短 TTL
	DistributedLock   // 分布式锁
	PARStorage        // 极短 TTL
	ReplayCache       // DPoP JTI 防重放
	RevocationStorage // Access Token 黑名单 (高频读取)

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
