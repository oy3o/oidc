package oidc

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"

	"github.com/bytedance/sonic"
	"github.com/google/uuid"
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

// ParseUUID 辅助函数
func ParseUUID(s string) (BinaryUUID, error) {
	id, err := uuid.Parse(s)
	if err != nil {
		return BinaryUUID{}, err
	}
	return BinaryUUID(id), nil
}

// GetAndVerifyClient 解析 clientID 并从存储中获取验证客户端
func GetAndVerifyClient(ctx context.Context, storage ClientStorage, clientIDStr string) (RegisteredClient, error) {
	clientID, err := ParseUUID(clientIDStr)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid client_id", ErrInvalidRequest)
	}

	client, err := storage.ClientGetByID(ctx, clientID)
	if err != nil {
		if errors.Is(err, ErrClientNotFound) {
			return nil, fmt.Errorf("%w: invalid client", ErrInvalidClient)
		}
		return nil, err
	}

	return client, nil
}
