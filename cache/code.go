package cache

import (
	"context"
	"fmt"
	"time"

	"github.com/bytedance/sonic"
	"github.com/oy3o/oidc"
	"github.com/redis/go-redis/v9"
)

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
// PARStorage Implementation (RFC 9126)
// ---------------------------------------------------------------------------

// PARSessionSave 保存 PAR 会话
func (r *RedisStorage) PARSessionSave(ctx context.Context, requestURI string, req *oidc.AuthorizeRequest, ttl time.Duration) error {
	if ttl <= 0 {
		return fmt.Errorf("invalid ttl: %v", ttl)
	}
	reqJSON, err := sonic.Marshal(req)
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
	var req oidc.AuthorizeRequest
	if err := sonic.Unmarshal([]byte(valStr), &req); err != nil {
		return nil, fmt.Errorf("failed to unmarshal PAR session: %w", err)
	}

	return &req, nil
}
