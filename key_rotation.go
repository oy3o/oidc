package oidc

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/oy3o/o11y"
	"github.com/puzpuzpuz/xsync/v4"
	"github.com/rs/zerolog/log"
	"go.opentelemetry.io/otel/attribute"
)

// KeyRotationConfig 密钥轮换配置
type KeyRotationConfig struct {
	// RotationInterval 密钥轮换间隔（例如 30 天）
	RotationInterval time.Duration

	// GracePeriod 旧密钥保留期，用于验证旧 Token（例如 7 天）
	GracePeriod time.Duration

	// KeyType 生成的密钥类型
	KeyType KeyType

	// EnableAutoRotate 是否启用自动定时轮换
	EnableAutoRotate bool

	// CleanupInterval 清理过期密钥的检查间隔
	// 如果为 0，默认为 1 分钟
	// 测试时可设置为较短时间（如 1 秒）
	CleanupInterval time.Duration
}

// KeyRotationScheduler 密钥轮换调度器
// 负责编排密钥的完整生命周期：生成 → 签名 → 宽限期 → 删除
type KeyRotationScheduler struct {
	manager *KeyManager
	lock    DistributedLock // 分布式锁
	config  KeyRotationConfig

	// 当前活跃的签名密钥 ID
	currentKID atomic.Value // string

	// 待删除的旧密钥及其到期时间
	// map[kid]deleteAt
	pendingDeletes *xsync.Map[string, time.Time]

	// 停止信号
	stopChan chan struct{}
	stopOnce sync.Once

	// 防止并发轮换 (本地锁)
	rotationMu sync.Mutex

	// 已启动标志
	started atomic.Bool
}

// NewKeyRotationScheduler 创建密钥轮换调度器
func NewKeyRotationScheduler(manager *KeyManager, lock DistributedLock, config KeyRotationConfig) *KeyRotationScheduler {
	// 参数校验
	if manager == nil {
		panic("KeyManager cannot be nil")
	}
	if lock == nil {
		panic("DistributedLock cannot be nil")
	}
	if config.RotationInterval <= 0 {
		panic("RotationInterval must be positive")
	}
	if config.GracePeriod < 0 {
		panic("GracePeriod cannot be negative")
	}

	// 设置默认清理间隔
	if config.CleanupInterval <= 0 {
		config.CleanupInterval = 1 * time.Minute
	}

	s := &KeyRotationScheduler{
		manager:        manager,
		lock:           lock,
		config:         config,
		stopChan:       make(chan struct{}),
		pendingDeletes: xsync.NewMap[string, time.Time](),
	}

	// 初始化 currentKID（从 manager 获取当前签名密钥）
	// 注意：这里需要 Context，但 New 方法通常不传 Context。
	// 我们可以延迟到 Start 时获取，或者这里先留空。
	// 为了保持兼容性，我们尝试用 Background Context 获取一次，失败也无妨。
	kid, _, err := manager.GetSigningKey(context.Background())
	if err == nil {
		s.currentKID.Store(kid)
	}

	return s
}

// Start 启动后台自动轮换任务
// 返回的 error 仅在严重初始化问题时非 nil
func (s *KeyRotationScheduler) Start(ctx context.Context) error {
	// 确保只启动一次
	if s.started.CompareAndSwap(false, true) {
		// 如果没有当前密钥，先生成一个
		// 注意：这里也需要加锁，防止多实例同时生成初始密钥
		if s.currentKID.Load() == nil {
			// 尝试获取锁，如果获取失败说明其他实例正在初始化，我们等待即可
			locked, err := s.lock.Lock(ctx, "init_key", 10*time.Second)
			if err != nil {
				s.started.Store(false)
				return fmt.Errorf("failed to acquire init lock: %w", err)
			}

			if locked {
				defer s.lock.Unlock(ctx, "init_key")
				// Double check inside lock
				if kid, _, err := s.manager.GetSigningKey(ctx); err == nil {
					s.currentKID.Store(kid)
				} else {
					if err := s.RotateNow(ctx); err != nil {
						s.started.Store(false)
						return fmt.Errorf("initial key generation failed: %w", err)
					}
				}
			} else {
				// 没抢到锁，等待一会再检查
				time.Sleep(100 * time.Millisecond)
				if kid, _, err := s.manager.GetSigningKey(ctx); err == nil {
					s.currentKID.Store(kid)
				}
			}
		}

		// 如果启用自动轮换，启动后台任务
		if s.config.EnableAutoRotate {
			go s.autoRotationLoop(ctx)
		}

		// 启动清理任务
		go s.cleanupLoop(ctx)
		return nil
	}

	return ErrSchedulerAlreadyStarted
}

// Stop 停止调度器
func (s *KeyRotationScheduler) Stop() {
	s.stopOnce.Do(func() {
		close(s.stopChan)
	})
}

// RotateNow 立即触发一次密钥轮换
// 适用于安全事件响应或手动干预
func (s *KeyRotationScheduler) RotateNow(ctx context.Context) error {
	// 本地锁防止单实例并发
	s.rotationMu.Lock()
	defer s.rotationMu.Unlock()

	// 分布式锁防止多实例并发
	// 锁 TTL 设为 1 分钟，足够生成密钥
	locked, err := s.lock.Lock(ctx, "rotate_key", 1*time.Minute)
	if err != nil {
		return fmt.Errorf("failed to acquire rotation lock: %w", err)
	}
	if !locked {
		return ErrRotationInProgress
	}
	defer s.lock.Unlock(ctx, "rotate_key")

	// 使用 o11y.Run 包装轮换逻辑，提供追踪、日志和指标
	return o11y.Run(ctx, "oidc.key_rotation", func(ctx context.Context, state o11y.State) error {
		state.Log.Info().
			Str("key_type", string(s.config.KeyType)).
			Dur("grace_period", s.config.GracePeriod).
			Msg("Starting key rotation")

		// 1. 生成新密钥
		newKID, err := s.manager.Generate(ctx, s.config.KeyType, false)
		if err != nil {
			return fmt.Errorf("failed to generate new key: %w", err)
		}

		// 2. 记录旧密钥 ID
		var oldKID string
		if kid := s.currentKID.Load(); kid != nil {
			oldKID = kid.(string)
		}

		// 3. 切换签名密钥
		if err := s.manager.SetSigningKeyID(ctx, newKID); err != nil {
			// 清理失败的新密钥
			_ = s.manager.RemoveKey(ctx, newKID)
			return fmt.Errorf("failed to set signing key: %w", err)
		}

		// 4. 更新当前密钥 ID
		s.currentKID.Store(newKID)

		// 5. 如果有旧密钥，标记为待删除
		if oldKID != "" && s.config.GracePeriod > 0 {
			deleteAt := time.Now().Add(s.config.GracePeriod)
			s.pendingDeletes.Store(oldKID, deleteAt)
		} else if oldKID != "" {
			// 没有宽限期，立即删除
			_ = s.manager.RemoveKey(ctx, oldKID)
		}

		// 记录成功的追踪属性和指标
		state.SetAttributes(
			attribute.String("new_kid", newKID),
			attribute.String("old_kid", oldKID),
			attribute.String("key_type", string(s.config.KeyType)),
		)
		state.IncCounter("oidc.key_rotation.total")

		state.Log.Info().
			Str("new_kid", newKID).
			Str("old_kid", oldKID).
			Msg("Key rotation completed successfully")

		return nil
	})
}

// autoRotationLoop 自动轮换循环
func (s *KeyRotationScheduler) autoRotationLoop(ctx context.Context) {
	ticker := time.NewTicker(s.config.RotationInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			// 尝试轮换
			if err := s.RotateNow(ctx); err != nil {
				// 如果是因为锁被占用，说明其他实例正在轮换，可以忽略
				// 其他错误需要记录以便监控
				log.Error().Err(err).Msg("Failed to auto-rotate key")
			}
		case <-s.stopChan:
			return
		case <-ctx.Done():
			return
		}
	}
}

// cleanupLoop 清理过期密钥循环
func (s *KeyRotationScheduler) cleanupLoop(ctx context.Context) {
	// 使用配置的清理间隔
	ticker := time.NewTicker(s.config.CleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			now := time.Now()
			s.pendingDeletes.Range(func(kid string, deleteAt time.Time) bool {
				if now.After(deleteAt) {
					// 到期，删除密钥
					if err := s.manager.RemoveKey(ctx, kid); err != nil {
						log.Error().Err(err).Str("kid", kid).Msg("Failed to remove expired key")
					}
					s.pendingDeletes.Delete(kid)
				}
				return true
			})
		case <-s.stopChan:
			return
		case <-ctx.Done():
			return
		}
	}
}

// GetCurrentKeyID 获取当前签名密钥 ID
func (s *KeyRotationScheduler) GetCurrentKeyID() string {
	if kid := s.currentKID.Load(); kid != nil {
		return kid.(string)
	}
	return ""
}

// GetPendingDeletes 获取待删除密钥列表（用于监控）
func (s *KeyRotationScheduler) GetPendingDeletes() map[string]time.Time {
	result := make(map[string]time.Time)
	s.pendingDeletes.Range(func(kid string, deleteAt time.Time) bool {
		result[kid] = deleteAt
		return true
	})
	return result
}
