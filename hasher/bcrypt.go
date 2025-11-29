package hasher

import (
	"context"

	"go.opentelemetry.io/otel"
	"golang.org/x/crypto/bcrypt"
)

// BcryptHasher 是使用Bcrypt算法的Hasher实现。
type BcryptHasher struct {
	// cost 是哈希算法的计算成本。值越高越安全，但计算也越慢。
	// 将其作为结构体字段，可以在初始化时配置，而不是硬编码。
	cost int
}

var _ Hasher = (*BcryptHasher)(nil)

// NewBcryptHasher 创建一个新的BcryptHasher实例。
// 它接收一个cost参数，提供了灵活性，同时在函数内部强制执行一个合理的最小成本值，
// 防止在配置时意外设置一个不安全的值。
func NewBcryptHasher(cost int) *BcryptHasher {
	// 安全默认值：确保成本至少为 bcrypt.DefaultCost + 1 (当前为11)。
	// 这是一个防御性编程的例子，防止不安全的配置。
	if cost < bcrypt.DefaultCost+1 {
		cost = bcrypt.DefaultCost + 1
	}
	return &BcryptHasher{cost: cost}
}

// Hash 使用配置的成本对密码进行哈希。
func (h *BcryptHasher) Hash(ctx context.Context, password []byte) ([]byte, error) {
	tracer := otel.Tracer("sso/hasher")
	_, span := tracer.Start(ctx, "BcryptHasher.Hash")
	defer span.End()
	return bcrypt.GenerateFromPassword(password, h.cost)
}

// Compare 安全地比较哈希值和明文密码。
// bcrypt.CompareHashAndPassword 内置了对定时攻击的防护。
func (h *BcryptHasher) Compare(ctx context.Context, hashedPassword []byte, password []byte) error {
	tracer := otel.Tracer("sso/hasher")
	_, span := tracer.Start(ctx, "BcryptHasher.Compare")
	defer span.End()
	return bcrypt.CompareHashAndPassword(hashedPassword, password)
}
