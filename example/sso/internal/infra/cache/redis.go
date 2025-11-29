package cache

import (
	"context"
	"fmt"
	"strconv"
	"time"

	"github.com/oy3o/oidc"
	oidc_gorm "github.com/oy3o/oidc/gorm"
	oidc_redis "github.com/oy3o/oidc/redis"
	"github.com/redis/go-redis/v9"
)

const (
	PrefixLoginFail = "sso:login:fail:" // + IP
	PrefixPoW       = "sso:pow:"        // + SessionID/IP
)

// CacheStorage 组合了 OIDC 的 Redis 实现和我们自定义的业务缓存
type CacheStorage struct {
	// 嵌入 oidc 官方的 Redis 实现
	// 它自动提供了 AuthCode, DeviceCode, DistributedLock, ReplayCache 等接口实现
	*oidc_redis.RedisStorage

	// 暴露原生客户端供自定义逻辑使用
	client *redis.Client
}

type clientFactory struct{}

func (f *clientFactory) New() oidc.RegisteredClient {
	return &oidc_gorm.ClientModel{}
}

// NewCacheStorage 初始化 Redis 连接
func NewCacheStorage(addr, password string, db int) (*CacheStorage, error) {
	rdb := redis.NewClient(&redis.Options{
		Addr:     addr,
		Password: password,
		DB:       db,
	})

	// Fail fast
	if err := rdb.Ping(context.Background()).Err(); err != nil {
		return nil, fmt.Errorf("failed to connect to redis: %w", err)
	}

	return &CacheStorage{
		RedisStorage: oidc_redis.NewRedisStorage(rdb, &clientFactory{}),
		client:       rdb,
	}, nil
}

// --- Login Failure Counter (Rate Limiting) ---

// IncrLoginFailure 增加登录失败计数，并设置过期时间（例如 10 分钟）
// 返回当前的失败次数
func (s *CacheStorage) IncrLoginFailure(ctx context.Context, ip string, ttl time.Duration) (int, error) {
	key := PrefixLoginFail + ip
	pipe := s.client.Pipeline()
	incr := pipe.Incr(ctx, key)
	pipe.Expire(ctx, key, ttl)
	_, err := pipe.Exec(ctx)
	if err != nil {
		return 0, err
	}
	return int(incr.Val()), nil
}

// GetLoginFailureCount 获取当前失败次数
func (s *CacheStorage) GetLoginFailureCount(ctx context.Context, ip string) (int, error) {
	key := PrefixLoginFail + ip
	val, err := s.client.Get(ctx, key).Result()
	if err == redis.Nil {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	return strconv.Atoi(val)
}

// ResetLoginFailure 登录成功后清除计数
func (s *CacheStorage) ResetLoginFailure(ctx context.Context, ip string) error {
	key := PrefixLoginFail + ip
	return s.client.Del(ctx, key).Err()
}

// --- PoW Challenge Storage ---

// PoWData 存储 PoW 的挑战参数
type PoWData struct {
	Seed       string `json:"seed"`
	Difficulty int    `json:"difficulty"`
}

// SavePoWChallenge 存储 PoW 挑战，使其与特定 Session/IP 绑定
func (s *CacheStorage) SavePoWChallenge(ctx context.Context, keyID string, seed string, difficulty int, ttl time.Duration) error {
	key := PrefixPoW + keyID
	// 简单起见，存为 "difficulty:seed" 格式的字符串，避免 JSON 序列化开销
	val := fmt.Sprintf("%d:%s", difficulty, seed)
	return s.client.Set(ctx, key, val, ttl).Err()
}

// GetPoWChallenge 获取挑战参数
func (s *CacheStorage) GetPoWChallenge(ctx context.Context, keyID string) (difficulty int, seed string, err error) {
	key := PrefixPoW + keyID
	val, err := s.client.Get(ctx, key).Result()
	if err == redis.Nil {
		return 0, "", nil // Not found
	}
	if err != nil {
		return 0, "", err
	}

	// 解析 "difficulty:seed"
	var diff int
	var sStr string
	_, err = fmt.Sscanf(val, "%d:%s", &diff, &sStr)
	if err != nil {
		return 0, "", fmt.Errorf("invalid pow data in cache")
	}
	return diff, sStr, nil
}

// DeletePoWChallenge 验证通过后删除挑战（防重放）
func (s *CacheStorage) DeletePoWChallenge(ctx context.Context, keyID string) error {
	key := PrefixPoW + keyID
	return s.client.Del(ctx, key).Err()
}
