package hasher

import (
	"context"
	"fmt"

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

// DummyCompare 执行一次虚拟的哈希比较。
// 即使账户不存在，也要消耗与真实成本对等的 CPU 时间。
func (h *BcryptHasher) DummyCompare(ctx context.Context) error {
	// 1. 构建一个格式正确的假 Bcrypt 哈希字符串。
	// Bcrypt 格式: $2a$[cost]$[22个字符的盐][31个字符的哈希]
	// 我们必须确保这里的 cost 与实例配置的 h.cost 一致，否则计算耗时会暴露真相。

	// 这里使用一个 53 字符长的合法 fake 盐与哈希（22 盐 + 31 哈希）
	const dummySaltAndHash = "RS4eK8.O8Z.99Eshq9atvOUP9yS4eK8.O8Z.99Eshq9atvOUP9yS4e"
	dummyHash := fmt.Sprintf("$2a$%02d$%s", h.cost, dummySaltAndHash)

	// 2. 执行比较。
	// 即使我们知道它必败，也要让 bcrypt 内部进行完整的密文计算。
	_ = bcrypt.CompareHashAndPassword([]byte(dummyHash), []byte("dummy_password"))

	// 3. 始终返回不匹配错误。
	// 注意：ErrPasswordMismatch 应该在你的接口层或包中统一定义。
	return ErrPasswordMismatch
}
