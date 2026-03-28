package hasher

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"strings"

	"go.opentelemetry.io/otel"
	"golang.org/x/crypto/argon2"
)

// Argon2Hasher 是使用 Argon2id 算法的 Hasher 实现。
type Argon2Hasher struct {
	// OWASP 推荐的参数
	time    uint32
	memory  uint32
	threads uint8
	keyLen  uint32
	saltLen uint32
}

var _ Hasher = (*Argon2Hasher)(nil)

// NewArgon2Hasher 创建一个带有推荐参数的新实例。
// 这些参数可以从配置中读取以增加灵活性。
func NewArgon2Hasher(memory uint32, time uint32, threads uint8, keyLen uint32, saltLen uint32) *Argon2Hasher {
	// 设置理智的默认值
	if memory == 0 {
		memory = 64 * 1024
	} // 64 MB
	if time == 0 {
		time = 1
	}
	if threads == 0 {
		threads = 4
	}
	if keyLen == 0 {
		keyLen = 32
	}
	if saltLen == 0 {
		saltLen = 16
	}

	return &Argon2Hasher{
		time:    time,
		memory:  memory,
		threads: threads,
		keyLen:  keyLen,
		saltLen: saltLen,
	}
}

// Hash 对给定的明文密码进行哈希处理。
func (h *Argon2Hasher) Hash(ctx context.Context, password []byte) ([]byte, error) {
	tracer := otel.Tracer("sso/hasher")
	_, span := tracer.Start(ctx, "Argon2Hasher.Hash")
	defer span.End()
	// 1. 生成一个安全的随机盐
	saltBytes := make([]byte, h.saltLen)
	if _, err := rand.Read(saltBytes); err != nil {
		return nil, fmt.Errorf("failed to generate salt: %w", err)
	}

	// 2. 使用 Argon2id 派生密钥（哈希）
	hash := argon2.IDKey(password, saltBytes, h.time, h.memory, h.threads, h.keyLen)

	// 3. 将所有参数和结果编码成一个标准的字符串，以便存储
	// 格式: $argon2id$v=19$m=<memory>,t=<time>,p=<threads>$<salt>$<hash>
	b64Salt := base64.RawStdEncoding.EncodeToString(saltBytes)
	b64Hash := base64.RawStdEncoding.EncodeToString(hash)

	encodedHash := fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, h.memory, h.time, h.threads, b64Salt, b64Hash)

	return []byte(encodedHash), nil
}

// Compare 将明文密码与已有的哈希值进行比较。
func (h *Argon2Hasher) Compare(ctx context.Context, hashedPassword []byte, password []byte) error {
	tracer := otel.Tracer("sso/hasher")
	_, span := tracer.Start(ctx, "Argon2Hasher.Compare")
	defer span.End()

	// 1. 从存储的哈希字符串中解析出参数
	params, salt, hash, err := h.decodeHash(string(hashedPassword))
	if err != nil {
		return fmt.Errorf("failed to decode hash: %w", err)
	}

	// 2. 使用相同的参数、盐和用户输入的密码，重新计算哈希
	otherHash := argon2.IDKey(password, salt, params.time, params.memory, params.threads, params.keyLen)

	// 3. [安全] 使用恒定时间比较法来防止时序攻击
	if subtle.ConstantTimeCompare(hash, otherHash) == 1 {
		return nil // 匹配成功
	}

	return ErrPasswordMismatch
}

// DummyCompare 执行一次虚拟的哈希比较，用于防止计时攻击。
// 即使账户不存在，也通过执行相同的计算量来掩盖差异。
func (h *Argon2Hasher) DummyCompare(ctx context.Context) error {
	// 1. 模拟一个伪造的盐和密码
	// 长度应与配置中的盐长度一致，以保持计算开销对等
	dummySalt := make([]byte, h.saltLen)
	dummyPassword := []byte("dummy_password_for_timing_protection")

	// 2. 执行与真实比较相同的 Argon2 计算
	// 这消耗了主要的 CPU 和内存资源
	dummyHash := argon2.IDKey(
		dummyPassword,
		dummySalt,
		h.time,
		h.memory,
		h.threads,
		h.keyLen,
	)

	// 3. 模拟恒定时间比较
	// 虽然我们知道这一定会失败，但调用 subtle.ConstantTimeCompare 能保持调用栈特征一致
	subtle.ConstantTimeCompare(dummyHash, dummyHash)

	// 4. 始终返回不匹配错误
	return ErrPasswordMismatch
}

type argon2Params struct {
	time    uint32
	memory  uint32
	threads uint8
	keyLen  uint32
}

// decodeHash 从 Argon2 哈希字符串中解析出所有组件
func (h *Argon2Hasher) decodeHash(encodedHash string) (p *argon2Params, salt, hash []byte, err error) {
	vals := strings.Split(encodedHash, "$")
	if len(vals) != 6 {
		return nil, nil, nil, ErrInvalidHashFormat
	}

	var version int
	_, err = fmt.Sscanf(vals[2], "v=%d", &version)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to parse version: %w", err)
	}
	if version != argon2.Version {
		return nil, nil, nil, fmt.Errorf("%w: %d", ErrIncompatibleVersion, version)
	}

	p = &argon2Params{}
	_, err = fmt.Sscanf(vals[3], "m=%d,t=%d,p=%d", &p.memory, &p.time, &p.threads)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to parse argon2 params: %w", err)
	}

	salt, err = base64.RawStdEncoding.DecodeString(vals[4])
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to decode salt: %w", err)
	}

	hash, err = base64.RawStdEncoding.DecodeString(vals[5])
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to decode hash: %w", err)
	}
	p.keyLen = uint32(len(hash))

	return p, salt, hash, nil
}
