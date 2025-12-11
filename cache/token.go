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

func (r *RedisStorage) RefreshTokenSave(ctx context.Context, session *oidc.RefreshTokenSession, ttl time.Duration) error {
	data, err := sonic.Marshal(session)
	if err != nil {
		return fmt.Errorf("failed to marshal refresh token: %w", err)
	}
	key := prefixRefreshToken + session.ID.String()
	return r.client.Set(ctx, key, data, ttl).Err()
}

// RefreshTokenRotate 执行令牌轮换
// 这是一个原子操作（通过 Pipeline），包含以下步骤：
// 1. 保存新的 Refresh Token
// 2. 标记旧 Token 进入宽限期 (设置 Sidecar Key)
// 3. 更新旧 Token 的 TTL 为宽限期时长 (使其在宽限期后自动销毁)
func (r *RedisStorage) RefreshTokenRotate(ctx context.Context, oldTokenID oidc.Hash256, newSession *oidc.RefreshTokenSession, gracePeriod time.Duration) error {
	ttl := time.Until(newSession.ExpiresAt)
	if ttl <= 0 {
		return nil
	}

	// 序列化新 Token 数据
	newData, err := sonic.Marshal(newSession)
	if err != nil {
		return fmt.Errorf("failed to marshal new refresh token: %w", err)
	}

	// 准备 Key
	newKey := prefixRefreshToken + newSession.ID.String()
	oldKey := prefixRefreshToken + oldTokenID.String()

	// 使用 Pipeline 保证网络层面的批处理效率
	// 注意：如果对原子性要求极高（防止并发轮换竞态），建议改用 Lua 脚本
	// 但在这个场景下，Pipeline 配合业务层的乐观锁或状态检查通常足够
	_, err = r.client.TxPipelined(ctx, func(pipe redis.Pipeliner) error {
		// 1. 保存新 Token
		pipe.Set(ctx, newKey, newData, ttl)

		if gracePeriod > 0 {
			// 2. 修改旧 Token 的 TTL
			// 让旧 Token 在 Redis 中物理存活的时间 = 宽限期
			// 这样我们不需要手动删除它，Redis 会在宽限期后自动清理
			pipe.Expire(ctx, oldKey, gracePeriod)
		}

		return nil
	})
	if err != nil {
		return fmt.Errorf("failed to rotate refresh token: %w", err)
	}

	return nil
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
