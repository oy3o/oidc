package oidc

import (
	"database/sql/driver"
	"encoding/hex"

	"github.com/bytedance/sonic"
	"github.com/google/uuid"
	"gorm.io/gorm"
	"gorm.io/gorm/schema"
)

// Hash256 自定义类型，零依赖
type Hash256 []byte

// Value 实现 driver.Valuer 接口 (写入数据库)
// 存储格式：hex string，兼容 Postgres VARCHAR(64) / SQLite TEXT
func (h Hash256) Value() (driver.Value, error) {
	if len(h) == 0 {
		return nil, nil
	}
	if len(h) != 32 {
		return nil, ErrHash256InvalidLength
	}
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
		// 驱动返回裸二进制（长度 32）
		if len(v) == 32 {
			dst := make(Hash256, 32)
			copy(dst, v)
			*h = dst
			return nil
		}
		// 某些驱动（如 lib/pq）把 VARCHAR(64) 以 []byte 形式返回（长度 64）
		if len(v) == 64 {
			decoded, err := hex.DecodeString(string(v))
			if err != nil {
				return err
			}
			*h = decoded
			return nil
		}
		return ErrHash256ScanInvalidLength

	case string:
		// hex 字符串（长度 64）
		if len(v) == 64 {
			decoded, err := hex.DecodeString(v)
			if err != nil {
				return err
			}
			*h = decoded
			return nil
		}
		// 某些驱动把 binary 强转为 string（长度 32）
		if len(v) == 32 {
			dst := make(Hash256, 32)
			copy(dst, v)
			*h = dst
			return nil
		}
		return ErrHash256ScanInvalidLength

	default:
		return ErrHash256UnsupportedType
	}
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
	decoded, err := hex.DecodeString(hexStr)
	if err != nil {
		return err
	}
	if len(decoded) != 32 {
		return ErrInvalidHexStringLength
	}
	*h = decoded
	return nil
}

func (h Hash256) String() string {
	if len(h) == 0 {
		return ""
	}
	return hex.EncodeToString(h)
}

// GormDBDataType 针对不同数据库返回合法的字段类型
func (Hash256) GormDBDataType(db *gorm.DB, _ *schema.Field) string {
	switch db.Dialector.Name() {
	case "postgres":
		return "VARCHAR(64)"
	case "mysql":
		return "CHAR(64)"
	case "sqlite":
		return "TEXT"
	}
	return "VARCHAR(64)"
}

// BinaryUUID 包装标准 UUID，强制数据库交互使用二进制
type BinaryUUID uuid.UUID

// ---------------------------------------------------------
// 1. 数据库接口：强制使用二进制
// ---------------------------------------------------------

// Value 实现 driver.Valuer (写入数据库)
func (b BinaryUUID) Value() (driver.Value, error) {
	return uuid.UUID(b).MarshalBinary()
}

// Scan 实现 sql.Scanner (从数据库读取)
func (b *BinaryUUID) Scan(value interface{}) error {
	if value == nil {
		*b = BinaryUUID(uuid.Nil)
		return nil
	}

	var u uuid.UUID
	var err error

	switch v := value.(type) {
	case []byte:
		if len(v) == 16 {
			u, err = uuid.FromBytes(v)
		} else {
			// 兼容某些驱动把 varchar(36) 转成 []byte 返回的情况
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

// GormDBDataType 针对不同数据库返回合法的二进制字段类型
func (BinaryUUID) GormDBDataType(db *gorm.DB, _ *schema.Field) string {
	switch db.Dialector.Name() {
	case "postgres":
		return "UUID"
	case "mysql":
		return "BINARY(16)"
	case "sqlite":
		return "BLOB"
	}
	return "BINARY(16)"
}

// ---------------------------------------------------------
// 2. JSON 接口：保持前端友好 (String)
// ---------------------------------------------------------

// MarshalJSON 必须重写！否则 Go 会把底层 [16]byte 转成 Base64 字符串
func (b BinaryUUID) MarshalJSON() ([]byte, error) {
	return sonic.Marshal(uuid.UUID(b).String())
}

// UnmarshalJSON 从字符串解析，空字符串映射为 uuid.Nil
func (b *BinaryUUID) UnmarshalJSON(data []byte) error {
	var s string
	if err := sonic.Unmarshal(data, &s); err != nil {
		return err
	}
	if s == "" {
		*b = BinaryUUID(uuid.Nil)
		return nil
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
