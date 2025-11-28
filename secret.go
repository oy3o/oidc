package oidc

import (
	"context"
	"encoding/hex"
	"fmt"
	"os"
	"time"
)

// LoadTokenSecret 从环境变量加载 Token Secret
func LoadTokenSecret() ([]byte, error) {
	hexStr := os.Getenv("OIDC_TOKEN_SECRET")
	if hexStr == "" {
		return nil, fmt.Errorf("env OIDC_TOKEN_SECRET is required")
	}
	// 解码为原始字节
	return hex.DecodeString(hexStr)
}

// SecretManager 管理 HMAC 密钥，用于 Refresh Token 签名
// 现在使用 KeyProvider 抽象，支持内存、KMS、HSM 等多种实现
type SecretManager struct {
	provider KeyProvider
}

// NewSecretManager 创建新的密钥管理器（使用内存提供者）
func NewSecretManager() *SecretManager {
	return &SecretManager{
		provider: NewMemoryKeyProvider(),
	}
}

// NewSecretManagerWithProvider 创建密钥管理器（使用自定义提供者）
func NewSecretManagerWithProvider(provider KeyProvider) *SecretManager {
	return &SecretManager{
		provider: provider,
	}
}

// AddKey 添加密钥（向后兼容的便捷方法）
// 注意：仅在 provider 是 MemoryKeyProvider 时可用
func (s *SecretManager) AddKey(id string, hexSecret string) error {
	b, err := hex.DecodeString(hexSecret)
	if err != nil {
		return fmt.Errorf("invalid hex string: %w", err)
	}

	// 类型断言以支持内存提供者
	if memProvider, ok := s.provider.(*MemoryKeyProvider); ok {
		return memProvider.AddKey(id, b)
	}

	return fmt.Errorf("AddKey is only supported for MemoryKeyProvider")
}

// SetActiveKey 设置活跃密钥（向后兼容的便捷方法）
// 注意：仅在 provider 是 MemoryKeyProvider 时可用
func (s *SecretManager) SetActiveKey(kid string) error {
	if memProvider, ok := s.provider.(*MemoryKeyProvider); ok {
		return memProvider.SetActiveKey(kid)
	}
	return fmt.Errorf("SetActiveKey is only supported for MemoryKeyProvider")
}

// GetSigningKey 获取签名用的密钥 (HMAC Key)
// 返回 (key, kid)
func (s *SecretManager) GetSigningKey(ctx context.Context) ([]byte, string) {
	kid, key, err := s.provider.GetActiveKey(ctx)
	if err != nil {
		return nil, ""
	}
	return key, kid
}

// GetVerificationKey 根据 Token 中的 kid 获取验证密钥
func (s *SecretManager) GetVerificationKey(ctx context.Context, kid string) ([]byte, error) {
	key, err := s.provider.GetKey(ctx, kid)
	if err != nil {
		return nil, fmt.Errorf("unknown key id: %s", kid)
	}
	return key, nil
}

// RotateKey 轮换密钥（优雅轮换）
// gracePeriod: 旧密钥保留用于验证的时间
func (s *SecretManager) RotateKey(newKID string, newHexSecret string, gracePeriod time.Duration) error {
	newKey, err := hex.DecodeString(newHexSecret)
	if err != nil {
		return fmt.Errorf("invalid hex string: %w", err)
	}

	if memProvider, ok := s.provider.(*MemoryKeyProvider); ok {
		return memProvider.RotateKey(newKID, newKey, gracePeriod)
	}

	return fmt.Errorf("RotateKey is only supported for MemoryKeyProvider")
}

// CleanupExpiredKeys 清理已过期的密钥
// 返回清理的密钥数量
func (s *SecretManager) CleanupExpiredKeys() (int, error) {
	if memProvider, ok := s.provider.(*MemoryKeyProvider); ok {
		return memProvider.CleanupExpiredKeys(context.Background()), nil
	}
	return 0, fmt.Errorf("CleanupExpiredKeys is only supported for MemoryKeyProvider")
}
