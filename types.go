package oidc

import (
	"database/sql/driver"
	"fmt"

	"github.com/bytedance/sonic"
	"gorm.io/gorm"
	"gorm.io/gorm/schema"
)

// --- SecretString ---

type SecretString string

func (s SecretString) String() string   { return "[REDACTED]" }
func (s SecretString) GoString() string { return "Secret.String(***)" }

func (s SecretString) MarshalJSON() ([]byte, error) {
	return []byte(`"[REDACTED]"`), nil
}

// UnmarshalJSON 允许从 JSON 中读取原始值（JSON string → SecretString）
func (s *SecretString) UnmarshalJSON(b []byte) error {
	var str string
	if err := sonic.Unmarshal(b, &str); err != nil {
		return err
	}
	*s = SecretString(str)
	return nil
}

func (s SecretString) Value() (driver.Value, error) {
	return string(s), nil
}

func (s *SecretString) Scan(value interface{}) error {
	if value == nil {
		*s = ""
		return nil
	}
	switch v := value.(type) {
	case []byte:
		*s = SecretString(v)
	case string:
		*s = SecretString(v)
	default:
		return fmt.Errorf("unsupported type for SecretString: %T", value)
	}
	return nil
}

// GormDBDataType 针对不同数据库返回合法的字段类型
func (SecretString) GormDBDataType(db *gorm.DB, _ *schema.Field) string {
	switch db.Dialector.Name() {
	case "postgres":
		return "TEXT"
	case "mysql":
		return "TEXT"
	case "sqlite":
		return "TEXT"
	}
	return "TEXT"
}

// --- SecretBytes ---

type SecretBytes []byte

func (s SecretBytes) String() string   { return "[REDACTED]" }
func (s SecretBytes) GoString() string { return "Secret.Bytes(***)" }

func (s SecretBytes) MarshalJSON() ([]byte, error) {
	return []byte(`"[REDACTED]"`), nil
}

// UnmarshalJSON 允许从 JSON 中读取原始值。
// 注意：Go 标准 JSON（及 sonic）对 []byte 的编解码使用 base64，
// 因此 JSON 中的值必须是 base64 编码的字符串，而非普通字符串。
func (s *SecretBytes) UnmarshalJSON(b []byte) error {
	var raw []byte
	if err := sonic.Unmarshal(b, &raw); err != nil {
		return err
	}
	*s = SecretBytes(raw)
	return nil
}

func (s SecretBytes) Value() (driver.Value, error) {
	if s == nil {
		return nil, nil
	}
	return []byte(s), nil
}

func (s *SecretBytes) Scan(value interface{}) error {
	if value == nil {
		*s = nil
		return nil
	}
	var raw []byte
	switch v := value.(type) {
	case []byte:
		raw = v
	case string:
		raw = []byte(v)
	default:
		return fmt.Errorf("unsupported type for SecretBytes: %T", value)
	}
	// 深度拷贝，防止驱动层重用缓冲区
	dest := make(SecretBytes, len(raw))
	copy(dest, raw)
	*s = dest
	return nil
}

// GormDBDataType 针对不同数据库返回合法的二进制字段类型
func (SecretBytes) GormDBDataType(db *gorm.DB, _ *schema.Field) string {
	switch db.Dialector.Name() {
	case "postgres":
		return "BYTEA"
	case "mysql":
		return "BLOB"
	case "sqlite":
		return "BLOB"
	}
	return "BLOB"
}

// --- StringSlice ---

type StringSlice []string

func (ss StringSlice) Value() (driver.Value, error) {
	if ss == nil {
		return nil, nil // 允许数据库存储 NULL
	}
	if len(ss) == 0 {
		return "[]", nil
	}
	return sonic.MarshalString(ss)
}

func (ss *StringSlice) Scan(value interface{}) error {
	if value == nil {
		*ss = nil
		return nil
	}
	var raw []byte
	switch v := value.(type) {
	case []byte:
		raw = v
	case string:
		raw = []byte(v)
	default:
		return fmt.Errorf("failed to scan StringSlice: %v", value)
	}
	if len(raw) == 0 {
		*ss = []string{}
		return nil
	}
	return sonic.Unmarshal(raw, ss)
}

// GormDBDataType 针对不同的数据库返回不同的 JSON 类型定义
func (StringSlice) GormDBDataType(db *gorm.DB, _ *schema.Field) string {
	switch db.Dialector.Name() {
	case "mysql", "sqlite":
		return "JSON"
	case "postgres":
		return "JSONB"
	}
	return "TEXT"
}
