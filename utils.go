package oidc

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"

	"github.com/bytedance/sonic"
)

// RandomString 生成指定长度的随机字符串 (URL Safe Base64)
func RandomString(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("failed to generate random string: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// DecodeJSON 是一个安全的 JSON 解码辅助函数。
// 它启用 UseNumber() 选项，防止大整数（如 expires_in 或 ID）被错误解析为 float64 导致精度丢失。
func DecodeJSON(r io.Reader, v any) error {
	d := sonic.ConfigDefault.NewDecoder(r)
	d.UseNumber()
	return d.Decode(v)
}
