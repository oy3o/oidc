package cache

import (
	"context"
	"fmt"
	"time"

	"github.com/bytedance/sonic"

	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/oy3o/oidc"
	"github.com/redis/go-redis/v9"
)

const (
	// Key Prefixes
	prefixAuthCode     = "oidc:code:"
	prefixRefreshToken = "oidc:rt:"
	prefixDeviceCode   = "oidc:device:"
	prefixUserCode     = "oidc:usercode:"
	prefixRevocation   = "oidc:revoked:"
	prefixDPoPJTI      = "oidc:dpop:jti:"   // DPoP JTI 防重放
	prefixPAR          = "oidc:par:"        // PAR request_uri 会话
	prefixKey          = "oidc:keys:"       // JWK 存储
	prefixLock         = "oidc:lock:"       // 分布式锁
	prefixSigningKey   = "oidc:signing_key" // 当前签名密钥 ID
)

// RedisStorage 实现了 oidc 包所需的多个存储接口
type RedisStorage struct {
	client  *redis.Client
	factory oidc.ClientFactory
}

var _ oidc.Cache = (*RedisStorage)(nil)

func NewRedis(client *redis.Client, factory oidc.ClientFactory) *RedisStorage {
	return &RedisStorage{
		client:  client,
		factory: factory,
	}
}

// ---------------------------------------------------------------------------
// AuthCodeStorage 实现
// ---------------------------------------------------------------------------

// AuthCodeSave 存储生成的授权码
func (r *RedisStorage) AuthCodeSave(ctx context.Context, session *oidc.AuthCodeSession) error {
	data, err := sonic.Marshal(session)
	if err != nil {
		return fmt.Errorf("failed to marshal auth code session: %w", err)
	}

	key := prefixAuthCode + session.Code
	// 计算剩余有效期
	ttl := time.Until(session.ExpiresAt)
	if ttl <= 0 {
		return ErrAuthCodeExpired
	}

	return r.client.Set(ctx, key, data, ttl).Err()
}

// AuthCodeConsume 原子性地获取并删除授权码（一次性使用）
func (r *RedisStorage) AuthCodeConsume(ctx context.Context, code string) (*oidc.AuthCodeSession, error) {
	key := prefixAuthCode + code

	// 使用 Lua 脚本保证 JWKGet 和 Del 的原子性
	// 脚本逻辑：获取值，如果存在则删除，返回获取到的值
	script := redis.NewScript(`
		local val = redis.call("GET", KEYS[1])
		if val then
			redis.call("DEL", KEYS[1])
		end
		return val
	`)

	result, err := script.Run(ctx, r.client, []string{key}).Result()

	// 优先检查系统错误，防止被 nil result 掩盖
	if err != nil && err != redis.Nil {
		return nil, fmt.Errorf("redis error: %w", err)
	}

	// Redis 返回 Nil 或 result 为 nil 表示 Key 不存在
	if err == redis.Nil || result == nil {
		return nil, oidc.ErrCodeNotFound
	}

	valStr, ok := result.(string)
	if !ok {
		return nil, ErrInvalidDataType
	}

	var session oidc.AuthCodeSession
	if err := sonic.Unmarshal([]byte(valStr), &session); err != nil {
		return nil, fmt.Errorf("failed to unmarshal session: %w", err)
	}

	return &session, nil
}

// ---------------------------------------------------------------------------
// DeviceCodeStorage 实现
// ---------------------------------------------------------------------------

// DeviceCodeSave 存储设备码 session
func (r *RedisStorage) DeviceCodeSave(ctx context.Context, session *oidc.DeviceCodeSession) error {
	data, err := sonic.Marshal(session)
	if err != nil {
		return err
	}
	ttl := time.Until(session.ExpiresAt)
	if ttl <= 0 {
		return ErrDeviceCodeExpired
	}

	// 需要存两份索引：一份通过 DeviceCode 查，一份通过 UserCode 查
	pipe := r.client.Pipeline()
	pipe.Set(ctx, prefixDeviceCode+session.DeviceCode, data, ttl)
	pipe.Set(ctx, prefixUserCode+session.UserCode, session.DeviceCode, ttl) // UserCode -> DeviceCode 映射

	_, err = pipe.Exec(ctx)
	return err
}

// DeviceCodeGet 获取会话
func (r *RedisStorage) DeviceCodeGet(ctx context.Context, deviceCode string) (*oidc.DeviceCodeSession, error) {
	val, err := r.client.Get(ctx, prefixDeviceCode+deviceCode).Result()
	if err == redis.Nil {
		return nil, oidc.ErrTokenNotFound // 或者专门的 ErrDeviceCodeNotFound
	}
	if err != nil {
		return nil, err
	}

	var session oidc.DeviceCodeSession
	if err := sonic.Unmarshal([]byte(val), &session); err != nil {
		return nil, err
	}
	return &session, nil
}

// DeviceCodeGetByUserCode 通过 UserCode 查找
func (r *RedisStorage) DeviceCodeGetByUserCode(ctx context.Context, userCode string) (*oidc.DeviceCodeSession, error) {
	// 1. 先查映射
	deviceCode, err := r.client.Get(ctx, prefixUserCode+userCode).Result()
	if err == redis.Nil {
		return nil, oidc.ErrTokenNotFound
	}
	if err != nil {
		return nil, err
	}

	// 2. 再查 Session
	return r.DeviceCodeGet(ctx, deviceCode)
}

// DeviceCodeUpdate 更新状态 (例如改为 Allowed，并绑定用户)
func (r *RedisStorage) DeviceCodeUpdate(ctx context.Context, deviceCode string, session *oidc.DeviceCodeSession) error {
	// 复用 JWKSave 逻辑覆盖即可，因为 Redis Set 是覆盖操作
	// 注意：UserCode 的映射不需要变

	// 为了数据一致性，通常只更新 DeviceCode 对应的 Key
	data, err := sonic.Marshal(session)
	if err != nil {
		return err
	}

	// 保持原有的 TTL (或者更新？通常 RFC 要求过期时间是固定的)
	// 这里使用 KEEPTTL (Redis 6.0+)
	return r.client.SetArgs(ctx, prefixDeviceCode+deviceCode, data, redis.SetArgs{
		KeepTTL: true,
	}).Err()
}

// DeviceCodeDelete 删除设备码会话
func (r *RedisStorage) DeviceCodeDelete(ctx context.Context, deviceCode string) error {
	// 1. 先获取 Session 以拿到 UserCode (为了删除索引)
	// 如果 Session 已经过期或不存在，JWKGet 会报错，我们忽略错误直接返回即可
	session, err := r.DeviceCodeGet(ctx, deviceCode)
	if err != nil {
		return nil // 已经不存在了，视为成功
	}

	// 2. 使用 Pipeline 原子删除两个 Key
	pipe := r.client.Pipeline()
	pipe.Del(ctx, prefixDeviceCode+deviceCode)
	pipe.Del(ctx, prefixUserCode+session.UserCode)
	_, err = pipe.Exec(ctx)
	return err
}

// ---------------------------------------------------------------------------
// DistributedLock Implementation
// ---------------------------------------------------------------------------

// Lock 获取分布式锁
func (r *RedisStorage) Lock(ctx context.Context, key string, ttl time.Duration) (bool, error) {
	redisKey := prefixLock + key
	return r.client.SetNX(ctx, redisKey, "locked", ttl).Result()
}

// Unlock 释放分布式锁
func (r *RedisStorage) Unlock(ctx context.Context, key string) error {
	redisKey := prefixLock + key
	return r.client.Del(ctx, redisKey).Err()
}

// ---------------------------------------------------------------------------
// PARStorage Implementation (RFC 9126)
// ---------------------------------------------------------------------------

// internalPARSession 用于在 Redis 中存储带过期时间的数据
type internalPARSession struct {
	Request   *oidc.AuthorizeRequest `json:"req"`
	ExpiresAt time.Time              `json:"exp"`
}

// PARSessionSave 保存 PAR 会话
func (r *RedisStorage) PARSessionSave(ctx context.Context, requestURI string, req *oidc.AuthorizeRequest, ttl time.Duration) error {
	if ttl <= 0 {
		return fmt.Errorf("invalid ttl: %v", ttl)
	}
	reqJSON, err := sonic.Marshal(&internalPARSession{
		Request:   req,
		ExpiresAt: time.Now().Add(ttl),
	})
	if err != nil {
		return fmt.Errorf("failed to marshal AuthorizeRequest: %w", err)
	}

	key := prefixPAR + requestURI
	return r.client.Set(ctx, key, reqJSON, ttl).Err()
}

// PARSessionConsume 获取并删除 PAR 会话（原子操作）
func (r *RedisStorage) PARSessionConsume(ctx context.Context, requestURI string) (*oidc.AuthorizeRequest, error) {
	key := prefixPAR + requestURI

	// 使用 Lua 脚本实现原子性: GET + DEL
	script := redis.NewScript(`
		local val = redis.call("GET", KEYS[1])
		if val then
			redis.call("DEL", KEYS[1])
		end
		return val
	`)

	result, err := script.Run(ctx, r.client, []string{key}).Result()

	// 优先检查系统错误
	if err != nil && err != redis.Nil {
		return nil, fmt.Errorf("redis error: %w", err)
	}
	if err == redis.Nil || result == nil {
		return nil, ErrPARSessionNotFound
	}

	valStr, ok := result.(string)
	if !ok {
		return nil, ErrInvalidDataType
	}
	var session internalPARSession
	if err := sonic.Unmarshal([]byte(valStr), &session); err != nil {
		return nil, fmt.Errorf("failed to unmarshal PAR session: %w", err)
	}

	// 应用层双重过期检查
	// 即便 Redis 没有及时删除，我们也在这里拦截
	if time.Now().After(session.ExpiresAt) {
		// 记录已从 Redis 删除（Lua脚本已执行删除），但数据已过期
		return nil, ErrPARSessionExpired
	}

	return session.Request, nil
}

// ---------------------------------------------------------------------------
// DPoP ReplayCache 实现
// ---------------------------------------------------------------------------

// CheckAndStore 实现 ReplayCache 接口
// 原子性地检查 JTI 是否已使用，若未使用则存储
// 返回 true 表示 JTI 已存在 (重放攻击)，false 表示首次使用
func (r *RedisStorage) CheckAndStore(ctx context.Context, jti string, ttl time.Duration) (bool, error) {
	key := prefixDPoPJTI + jti

	// SetNX: 如果 key 不存在则设置，返回 true
	// 如果 key 已存在则不设置，返回 false
	wasSet, err := r.client.SetNX(ctx, key, "1", ttl).Result()
	if err != nil {
		return false, fmt.Errorf("redis SetNX error: %w", err)
	}

	// wasSet == true: key 之前不存在，现在设置成功 → 首次使用 → 返回 false (非重放)
	// wasSet == false: key 已存在 → 重放攻击 → 返回 true
	return !wasSet, nil
}

// ---------------------------------------------------------------------------
// RevocationStorage (Access Token Blacklist) 实现
// ---------------------------------------------------------------------------

// AccessTokenRevoke 加入黑名单
func (r *RedisStorage) AccessTokenRevoke(ctx context.Context, jti string, expiration time.Time) error {
	key := prefixRevocation + jti
	ttl := time.Until(expiration)
	if ttl <= 0 {
		return nil // 已过期，无需撤销
	}
	// Value 可以是任意非空值，比如 "revoked"
	return r.client.Set(ctx, key, "revoked", ttl).Err()
}

// AccessTokenIsRevoked 检查是否在黑名单
func (r *RedisStorage) AccessTokenIsRevoked(ctx context.Context, jti string) (bool, error) {
	key := prefixRevocation + jti
	exists, err := r.client.Exists(ctx, key).Result()
	if err != nil {
		return false, err
	}
	return exists > 0, nil
}

// ---------------------------------------------------------------------------
// Refresh Token Grace Period Implementation (RFC 6749 最佳实践)
// ---------------------------------------------------------------------------

const prefixRotatingToken = "oidc:rt:rotating:"

// RefreshTokenMarkRotating 标记旧 Token 进入宽限期
// 在宽限期内，旧 Token 仍可刷新（但仅一次）
//
// 实现策略：
// - 在 Redis 中创建一个临时 key: oidc:rt:rotating:<tokenID>
// - TTL 设置为 gracePeriod (通常 30 秒)
// - 值可以是任意非空值（我们只关心 key 的存在性）
func (r *RedisStorage) RefreshTokenMarkRotating(ctx context.Context, tokenID oidc.Hash256, gracePeriod time.Duration) error {
	key := prefixRotatingToken + tokenID.String()
	return r.client.Set(ctx, key, "1", gracePeriod).Err()
}

// RefreshTokenInGracePeriod 检查 Token 是否在宽限期内
// 返回 true 表示可以允许一次重试刷新
func (r *RedisStorage) RefreshTokenInGracePeriod(ctx context.Context, tokenID oidc.Hash256) (bool, error) {
	key := prefixRotatingToken + tokenID.String()
	exists, err := r.client.Exists(ctx, key).Result()
	if err != nil {
		return false, fmt.Errorf("failed to check grace period: %w", err)
	}
	return exists > 0, nil
}

// ---------------------------------------------------------------------------
// KeyStorage Implementation
// ---------------------------------------------------------------------------

// JWKSave 存储 JWK
func (r *RedisStorage) JWKSave(ctx context.Context, key jwk.Key) error {
	if key.KeyID() == "" {
		return oidc.ErrKIDEmpty
	}

	// 序列化为 JSON (包含私钥)
	data, err := sonic.Marshal(key)
	if err != nil {
		return fmt.Errorf("failed to marshal JWK: %w", err)
	}

	redisKey := prefixKey + key.KeyID()
	// 存储，无过期时间 (除非显式删除)
	return r.client.Set(ctx, redisKey, data, 0).Err()
}

// JWKGet 获取 JWK
func (r *RedisStorage) JWKGet(ctx context.Context, kid string) (jwk.Key, error) {
	redisKey := prefixKey + kid
	val, err := r.client.Get(ctx, redisKey).Result()
	if err == redis.Nil {
		return nil, oidc.ErrKeyNotFound
	}
	if err != nil {
		return nil, err
	}

	key, err := jwk.ParseKey([]byte(val))
	if err != nil {
		return nil, fmt.Errorf("failed to parse JWK from redis: %w", err)
	}
	return key, nil
}

// JWKList 获取所有 JWK
func (r *RedisStorage) JWKList(ctx context.Context) ([]jwk.Key, error) {
	var keys []jwk.Key
	var cursor uint64

	// 使用 SCAN 遍历所有 key
	for {
		var redisKeys []string
		var err error
		redisKeys, cursor, err = r.client.Scan(ctx, cursor, prefixKey+"*", 100).Result()
		if err != nil {
			return nil, fmt.Errorf("scan failed: %w", err)
		}

		if len(redisKeys) > 0 {
			// 批量获取
			vals, err := r.client.MGet(ctx, redisKeys...).Result()
			if err != nil {
				return nil, fmt.Errorf("mget failed: %w", err)
			}

			for _, val := range vals {
				if val == nil {
					continue
				}
				valStr, ok := val.(string)
				if !ok {
					continue
				}
				key, err := jwk.ParseKey([]byte(valStr))
				if err != nil {
					// 忽略损坏的 key? 或者记录日志
					continue
				}
				keys = append(keys, key)
			}
		}

		if cursor == 0 {
			break
		}
	}

	return keys, nil
}

// JWKDelete 删除 JWK
func (r *RedisStorage) JWKDelete(ctx context.Context, kid string) error {
	redisKey := prefixKey + kid
	return r.client.Del(ctx, redisKey).Err()
}

// JWKMarkSigning 存储当前签名密钥 ID
func (r *RedisStorage) JWKMarkSigning(ctx context.Context, kid string) error {
	return r.client.Set(ctx, prefixSigningKey, kid, 0).Err()
}

// JWKGetSigning 获取当前签名密钥 ID
func (r *RedisStorage) JWKGetSigning(ctx context.Context) (string, error) {
	val, err := r.client.Get(ctx, prefixSigningKey).Result()
	if err == redis.Nil {
		return "", oidc.ErrKeyNotFound
	}
	if err != nil {
		return "", err
	}
	return val, nil
}

// ---------------------------------------------------------------------------
// ClientCache Implementation
// ---------------------------------------------------------------------------

const prefixClient = "oidc:client:"

func (r *RedisStorage) ClientFindByID(ctx context.Context, clientID oidc.BinaryUUID) (oidc.RegisteredClient, error) {
	key := prefixClient + clientID.String()
	clientStr, err := r.client.Get(ctx, key).Result()
	if err == redis.Nil {
		return nil, oidc.ErrClientNotFound
	}
	if err != nil {
		return nil, err
	}
	client := r.factory.New()
	if err := client.Deserialize(clientStr); err != nil {
		return nil, err
	}
	return client, nil
}

func (r *RedisStorage) ClientCache(ctx context.Context, client oidc.RegisteredClient, ttl time.Duration) error {
	data, err := client.Serialize()
	if err != nil {
		return fmt.Errorf("failed to serialize client: %w", err)
	}
	key := prefixClient + client.GetID().String()
	return r.client.Set(ctx, key, data, ttl).Err()
}

func (r *RedisStorage) ClientInvalidate(ctx context.Context, clientID oidc.BinaryUUID) error {
	key := prefixClient + clientID.String()
	return r.client.Del(ctx, key).Err()
}

// ---------------------------------------------------------------------------
// TokenCache Implementation
// ---------------------------------------------------------------------------

func (r *RedisStorage) RefreshTokenGet(ctx context.Context, tokenID oidc.Hash256) (*oidc.RefreshTokenSession, error) {
	key := prefixRefreshToken + tokenID.String()
	val, err := r.client.Get(ctx, key).Result()
	if err == redis.Nil {
		return nil, oidc.ErrTokenNotFound
	}
	if err != nil {
		return nil, err
	}

	var session oidc.RefreshTokenSession
	if err := sonic.Unmarshal([]byte(val), &session); err != nil {
		return nil, fmt.Errorf("failed to unmarshal refresh token: %w", err)
	}
	return &session, nil
}

func (r *RedisStorage) RefreshTokenCache(ctx context.Context, session *oidc.RefreshTokenSession, ttl time.Duration) error {
	data, err := sonic.Marshal(session)
	if err != nil {
		return fmt.Errorf("failed to marshal refresh token: %w", err)
	}
	key := prefixRefreshToken + session.ID.String()
	return r.client.Set(ctx, key, data, ttl).Err()
}

func (r *RedisStorage) RefreshTokenInvalidate(ctx context.Context, tokenID oidc.Hash256) error {
	key := prefixRefreshToken + tokenID.String()
	return r.client.Del(ctx, key).Err()
}

func (r *RedisStorage) RefreshTokensInvalidate(ctx context.Context, tokenIDs []oidc.Hash256) error {
	if len(tokenIDs) == 0 {
		return nil
	}

	keys := make([]string, len(tokenIDs))
	for i, id := range tokenIDs {
		keys[i] = prefixRefreshToken + id.String()
	}

	return r.client.Del(ctx, keys...).Err()
}
