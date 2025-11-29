package service

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"

	"sso/internal/config"
	"sso/internal/infra/cache"

	"github.com/google/uuid"
	"github.com/rs/zerolog/log"
)

type PoWService struct {
	cache *cache.CacheStorage
	cfg   config.PoWConfig
}

func NewPoWService(cache *cache.CacheStorage, cfg config.PoWConfig) *PoWService {
	return &PoWService{
		cache: cache,
		cfg:   cfg,
	}
}

// Generate 为指定客户端生成一个新的挑战
// key: 通常是 IP 地址或临时 Session ID
func (s *PoWService) Generate(ctx context.Context, key string) (seed string, difficulty int, err error) {
	// 1. 生成随机种子
	seed = uuid.New().String()
	difficulty = s.cfg.Difficulty

	// 2. 存入 Redis (关联 Key)
	// 如果该 Key 已有挑战，会覆盖旧的，这正好防止了囤积挑战
	err = s.cache.SavePoWChallenge(ctx, key, seed, difficulty, s.cfg.LockDuration)
	if err != nil {
		return "", 0, fmt.Errorf("failed to save pow challenge: %w", err)
	}

	log.Debug().Str("key", key).Str("seed", seed).Int("diff", difficulty).Msg("PoW challenge generated")
	return seed, difficulty, nil
}

// Verify 验证客户端提交的答案
// nonce: 客户端计算出的随机数
func (s *PoWService) Verify(ctx context.Context, key string, nonce string) (bool, error) {
	// 1. 获取存储的题目
	difficulty, seed, err := s.cache.GetPoWChallenge(ctx, key)
	if err != nil {
		return false, err
	}
	if seed == "" {
		// 题目不存在或已过期
		return false, nil
	}

	// 2. 计算 Hash: SHA256(seed + nonce)
	hash := sha256.Sum256([]byte(seed + nonce))
	hashStr := hex.EncodeToString(hash[:])

	// 3. 验证前导零数量 (Difficulty)
	// 构造目标前缀，例如 difficulty=4 -> "0000"
	targetPrefix := strings.Repeat("0", difficulty)
	if !strings.HasPrefix(hashStr, targetPrefix) {
		log.Warn().Str("key", key).Str("hash", hashStr).Msg("PoW verification failed: difficulty mismatch")
		return false, nil
	}

	// 4. [关键] 防重放：验证成功后立即删除题目
	// 这样同一个答案只能使用一次
	if err := s.cache.DeletePoWChallenge(ctx, key); err != nil {
		// 如果删除失败，理论上存在极短的时间窗口被重放
		// 但在登录场景下风险可控，记录错误即可
		log.Error().Err(err).Str("key", key).Msg("Failed to delete used PoW challenge")
	}

	log.Info().Str("key", key).Msg("PoW verification success")
	return true, nil
}
