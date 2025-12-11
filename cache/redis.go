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
	prefixClient       = "oidc:client:"
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
// ClientSave Implementation
// ---------------------------------------------------------------------------

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

func (r *RedisStorage) ClientSave(ctx context.Context, client oidc.RegisteredClient, ttl time.Duration) error {
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
