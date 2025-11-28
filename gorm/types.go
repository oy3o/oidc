package gorm

import (
	"database/sql/driver"
	"fmt"

	"github.com/bytedance/sonic"
)

// StringSlice 用于在数据库中以 JSON 格式存储 []string
type StringSlice []string

func (ss StringSlice) Value() (driver.Value, error) {
	if len(ss) == 0 {
		return "[]", nil
	}
	return sonic.Marshal(ss)
}

func (ss *StringSlice) Scan(value interface{}) error {
	if value == nil {
		*ss = []string{}
		return nil
	}
	var bytes []byte
	switch v := value.(type) {
	case []byte:
		bytes = v
	case string:
		bytes = []byte(v)
	default:
		return fmt.Errorf("failed to scan StringSlice: %v", value)
	}
	if len(bytes) == 0 {
		*ss = []string{}
		return nil
	}
	return sonic.Unmarshal(bytes, ss)
}
