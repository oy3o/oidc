package hasher

import "context"

// Hasher 定义了密码哈希和验证的接口。
// 这是一种策略模式的应用，将具体的哈希算法与业务逻辑解耦。
type Hasher interface {
	// Hash 对给定的明文密码进行哈希处理。
	// 返回哈希后的字节切片或错误。
	Hash(ctx context.Context, password []byte) ([]byte, error)

	// Compare 将明文密码与已有的哈希值进行比较。
	// 如果匹配，则返回nil；否则返回错误。
	Compare(ctx context.Context, hashedPassword []byte, password []byte) error
}
