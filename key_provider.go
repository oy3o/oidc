package oidc

import (
	"context"
	"fmt"
	"time"

	"github.com/puzpuzpuz/xsync/v4"
)

// KeyProvider 定义密钥获取接口，支持内存、KMS、HSM 等多种实现
// 这是依赖倒置原则的体现：核心逻辑依赖抽象接口，而非具体实现
type KeyProvider interface {
	// GetKey 获取指定版本的密钥
	GetKey(ctx context.Context, kid string) ([]byte, error)

	// GetActiveKey 获取当前活跃的签名密钥
	GetActiveKey(ctx context.Context) (string, []byte, error)

	// ListKeys 列出所有可用密钥（用于验证）
	// 返回 map[kid]key，包括活跃密钥和处于宽限期的旧密钥
	ListKeys(ctx context.Context) (map[string][]byte, error)
}

// MemoryKeyProvider 内存实现，保持现有行为
// 适用于开发环境和不需要 KMS 的简单部署
type MemoryKeyProvider struct {
	keys        *xsync.Map[string, []byte]
	activeKeyID string

	// 已弃用但仍可验证的密钥（密钥轮换时使用）
	// map[kid]过期时间
	deprecated *xsync.Map[string, time.Time]
}

// NewMemoryKeyProvider 创建内存密钥提供者
func NewMemoryKeyProvider() *MemoryKeyProvider {
	return &MemoryKeyProvider{
		keys:       xsync.NewMap[string, []byte](),
		deprecated: xsync.NewMap[string, time.Time](),
	}
}

// GetKey 实现 KeyProvider 接口
func (m *MemoryKeyProvider) GetKey(ctx context.Context, kid string) ([]byte, error) {
	key, ok := m.keys.Load(kid)
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrKeyNotFound, kid)
	}

	// 检查是否已过期（对于 deprecated keys）
	if expireAt, isDeprecated := m.deprecated.Load(kid); isDeprecated {
		if time.Now().After(expireAt) {
			return nil, fmt.Errorf("%w: %s", ErrKeyExpired, kid)
		}
	}

	return key, nil
}

// GetActiveKey 实现 KeyProvider 接口
func (m *MemoryKeyProvider) GetActiveKey(ctx context.Context) (string, []byte, error) {
	if m.activeKeyID == "" {
		return "", nil, ErrNoActiveKey
	}

	key, ok := m.keys.Load(m.activeKeyID)
	if !ok {
		return "", nil, fmt.Errorf("active key %s not found: %w", m.activeKeyID, ErrKeyNotFound)
	}

	return m.activeKeyID, key, nil
}

// ListKeys 实现 KeyProvider 接口
func (m *MemoryKeyProvider) ListKeys(ctx context.Context) (map[string][]byte, error) {
	now := time.Now()
	result := make(map[string][]byte, m.keys.Size())

	m.keys.Range(func(kid string, key []byte) bool {
		// 过滤掉已过期的 deprecated keys
		if expireAt, isDeprecated := m.deprecated.Load(kid); isDeprecated {
			if now.After(expireAt) {
				return true
			}
		}
		// 复制密钥，避免外部修改
		keyCopy := make([]byte, len(key))
		copy(keyCopy, key)
		result[kid] = keyCopy
		return true
	})

	return result, nil
}

// AddKey 添加新密钥
func (m *MemoryKeyProvider) AddKey(kid string, key []byte) error {
	if kid == "" {
		return ErrKIDEmpty
	}
	if len(key) < 32 {
		return ErrKeyTooShort
	}

	// 复制密钥，避免外部修改
	keyCopy := make([]byte, len(key))
	copy(keyCopy, key)
	m.keys.Store(kid, keyCopy)

	// 如果这是第一个密钥，自动设为活跃
	if m.activeKeyID == "" {
		m.activeKeyID = kid
	}

	return nil
}

// SetActiveKey 设置活跃密钥
func (m *MemoryKeyProvider) SetActiveKey(kid string) error {
	if _, ok := m.keys.Load(kid); !ok {
		return fmt.Errorf("%w: %s", ErrKeyNotFound, kid)
	}

	m.activeKeyID = kid
	return nil
}

// RotateKey 轮换密钥（优雅轮换）
// 1. 添加新密钥
// 2. 切换活跃密钥
// 3. 将旧密钥标记为 deprecated（但保留验证能力）
func (m *MemoryKeyProvider) RotateKey(newKID string, newKey []byte, gracePeriod time.Duration) error {
	if newKID == "" {
		return ErrKIDEmpty
	}
	if len(newKey) < 32 {
		return ErrKeyTooShort
	}

	// 保存旧的活跃密钥 ID
	oldKID := m.activeKeyID

	// 添加新密钥
	keyCopy := make([]byte, len(newKey))
	copy(keyCopy, newKey)
	m.keys.Store(newKID, keyCopy)

	// 切换活跃密钥
	m.activeKeyID = newKID

	// 将旧密钥标记为 deprecated
	if oldKID != "" {
		m.deprecated.Store(oldKID, time.Now().Add(gracePeriod))
	}

	return nil
}

// RemoveKey 删除密钥
// 注意：不能删除当前活跃的密钥
func (m *MemoryKeyProvider) RemoveKey(kid string) error {
	if kid == m.activeKeyID {
		return ErrCannotRemoveActiveKey
	}

	m.keys.Delete(kid)
	m.deprecated.Delete(kid)
	return nil
}

// CleanupExpiredKeys 清理已过期的 deprecated keys
// 应该定期调用（例如通过 cron）
func (m *MemoryKeyProvider) CleanupExpiredKeys(ctx context.Context) int {
	now := time.Now()
	count := 0

	m.deprecated.Range(func(kid string, expireAt time.Time) bool {
		if now.After(expireAt) {
			m.keys.Delete(kid)
			m.deprecated.Delete(kid)
			count++
		}
		return true
	})

	return count
}
