package oidc

import (
	"database/sql/driver"
	"encoding/hex"

	"github.com/bytedance/sonic"
	"github.com/google/uuid"
)

// Hash256 自定义类型，零依赖
type Hash256 []byte

// Value 实现 driver.Valuer 接口 (写入数据库)
func (h Hash256) Value() (driver.Value, error) {
	if len(h) == 0 {
		return nil, nil
	}
	if len(h) != 32 {
		return nil, ErrHash256InvalidLength
	}
	// 为了兼容 Postgres Varchar(64)
	return h.String(), nil
}

// Scan 实现 sql.Scanner 接口 (从数据库读取)
func (h *Hash256) Scan(value interface{}) error {
	if value == nil {
		*h = nil
		return nil
	}
	switch v := value.(type) {
	case []byte:
		if len(v) != 32 {
			return ErrHash256ScanInvalidLength
		}
		// 必须深拷贝
		dst := make(Hash256, 32)
		copy(dst, v)
		*h = dst
	case string:
		// 某些驱动（如 SQLite）可能返回 string
		// 如果是 hex 字符串 (长度64)
		if len(v) == 64 {
			b, err := hex.DecodeString(v)
			if err != nil {
				return err
			}
			*h = b
			return nil
		}
		// 或者是某些驱动把 binary 强转为 string
		*h = Hash256(v)
	default:
		return ErrHash256UnsupportedType
	}
	return nil
}

// ---------------------------------------------------------
// JSON 接口：让前端看到 Hex 字符串
// ---------------------------------------------------------

func (h Hash256) MarshalJSON() ([]byte, error) {
	return sonic.Marshal(h.String())
}

func (h *Hash256) UnmarshalJSON(data []byte) error {
	var hexStr string
	if err := sonic.Unmarshal(data, &hexStr); err != nil {
		return err
	}
	if hexStr == "" {
		*h = nil
		return nil
	}
	bytes, err := hex.DecodeString(hexStr)
	if err != nil {
		return err
	}
	if len(bytes) != 32 {
		return ErrInvalidHexStringLength
	}
	*h = bytes
	return nil
}

func (h Hash256) String() string {
	if len(h) == 0 {
		return ""
	}
	return hex.EncodeToString(h)
}

// BinaryUUID 包装标准 UUID，强制数据库交互使用二进制
type BinaryUUID uuid.UUID

// ---------------------------------------------------------
// 1. 数据库接口：强制使用二进制
// ---------------------------------------------------------

// Value 实现 driver.Valuer (写入数据库)
func (b BinaryUUID) Value() (driver.Value, error) {
	// 关键点：这里调用 MarshalBinary 转为 []byte
	// 这样 GORM 才会把它当做 binary 数据处理
	return uuid.UUID(b).MarshalBinary()
}

// Scan 实现 sql.Scanner (从数据库读取)
func (b *BinaryUUID) Scan(value interface{}) error {
	if value == nil {
		*b = BinaryUUID(uuid.Nil)
		return nil
	}

	// 复用 google/uuid 的解析逻辑，它很强大，能处理 string 和 []byte
	var u uuid.UUID
	var err error

	switch v := value.(type) {
	case []byte:
		if len(v) == 16 {
			u, err = uuid.FromBytes(v)
		} else {
			// 兼容某些驱动可能把 varchar(36) 转成 []byte 返回的情况
			u, err = uuid.ParseBytes(v)
		}
	case [16]byte:
		u = uuid.UUID(v)
	case string:
		u, err = uuid.Parse(v)
	default:
		return ErrBinaryUUIDUnsupportedType
	}

	if err != nil {
		return err
	}
	*b = BinaryUUID(u)
	return nil
}

// ---------------------------------------------------------
// 2. JSON 接口：保持前端友好 (String)
// ---------------------------------------------------------

// MarshalJSON 必须重写！否则 Go 会把底层 []byte 转成 Base64 字符串
func (b BinaryUUID) MarshalJSON() ([]byte, error) {
	return sonic.Marshal(uuid.UUID(b).String())
}

// UnmarshalJSON 从字符串解析
func (b *BinaryUUID) UnmarshalJSON(data []byte) error {
	var s string
	if err := sonic.Unmarshal(data, &s); err != nil {
		return err
	}
	id, err := uuid.Parse(s)
	if err != nil {
		return err
	}
	*b = BinaryUUID(id)
	return nil
}

// String 实现 fmt.Stringer
func (b BinaryUUID) String() string {
	return uuid.UUID(b).String()
}

// NewBinaryUUID 创建一个 uuid v7
func NewBinaryUUID() (BinaryUUID, error) {
	id, err := uuid.NewV7()
	if err != nil {
		return BinaryUUID(uuid.Nil), err
	}
	return BinaryUUID(id), nil
}
