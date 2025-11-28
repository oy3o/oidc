//go:build !test

package oidc

import "context"

// PasswordGrant 生产存根实现，总是返回 "unsupported grant type" 错误。
// 这个函数确保了在生产构建中调用 password grant 逻辑会安全地失败，并且二进制文件中不包含任何实际的处理代码。
func PasswordGrant(ctx context.Context, storage Storage, hasher Hasher, issuer *Issuer, req *TokenRequest) (*IssuerResponse, error) {
	return nil, ErrUnsupportedGrantType
}
