package oidc

import (
	"database/sql/driver"
	"fmt"
)

// String 是一种自定义字符串类型，用于防止敏感信息在日志中被意外打印。
// 注意：当用于存储 Client Secret 时，此字段应存储哈希后的值，而非明文。
// 在 ClientMetadata 中，Secret 字段通过 Hasher 接口哈希后再赋值给此类型。
type String string

// String 方法重写了默认行为，使其在被格式化打印时返回一个屏蔽后的字符串。
func (s String) String() string {
	return "[REDACTED]"
}

// Go 语法格式化接口 (%#v) - 往常容易被忽略的泄露点
func (s String) GoString() string {
	return "Secret.String(***)"
}

// MarshalJSON 方法确保在将配置序列化为JSON时，敏感字段也被屏蔽。
func (s String) MarshalJSON() ([]byte, error) {
	return []byte(`"[REDACTED]"`), nil
}

// Value 实现 driver.Valuer 接口, 告诉数据库如何写入 String
func (s String) Value() (driver.Value, error) {
	return string(s), nil
}

// Scan 实现 sql.Scanner 接口, 告诉 Go 如何从数据库读取值到 String
func (s *String) Scan(value interface{}) error {
	if value == nil {
		*s = ""
		return nil
	}
	switch v := value.(type) {
	case []byte:
		*s = String(v)
	case string:
		*s = String(v)
	default:
		return fmt.Errorf("unsupported type for secret.String: %T", value)
	}
	return nil
}

// Bytes 是一种自定义字节切片类型，用于防止敏感信息在日志中被意外打印。
// 注意：当用于存储密码或 Secret 的哈希值时，应确保存储的是哈希后的值。
type Bytes []byte

// Bytes 方法重写了默认行为，使其在被格式化打印时返回一个屏蔽后的字符串。
func (s Bytes) String() string {
	return "[REDACTED]"
}

// Go 语法格式化接口 (%#v) - 往常容易被忽略的泄露点
func (s Bytes) GoString() string {
	return "Secret.Bytes(***)"
}

// MarshalJSON 方法确保在将配置序列化为JSON时，敏感字段也被屏蔽。
func (s Bytes) MarshalJSON() ([]byte, error) {
	return []byte(`"[REDACTED]"`), nil
}

// Value 实现 driver.Valuer 接口, 告诉数据库如何写入 Bytes
func (s Bytes) Value() (driver.Value, error) {
	return []byte(s), nil
}

// Scan 实现 sql.Scanner 接口, 告诉 Go 如何从数据库读取值到 Bytes
func (s *Bytes) Scan(value interface{}) error {
	if value == nil {
		*s = nil
		return nil
	}
	b, ok := value.([]byte)
	if !ok {
		return fmt.Errorf("unsupported type for secret.Bytes: %T", value)
	}
	// 必须复制字节切片，因为底层的数组可能会被驱动重用
	dest := make(Bytes, len(b))
	copy(dest, b)
	*s = dest
	return nil
}
