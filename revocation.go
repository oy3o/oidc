package oidc

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// RevocationRequest 封装 RFC 7009 撤销请求参数
type RevocationRequest struct {
	Token         string `form:"token" json:"token"`
	TokenTypeHint string `form:"token_type_hint" json:"token_type_hint"` // "access_token" 或 "refresh_token" (可选)
	ClientID      string `form:"client_id" json:"client_id"`
	ClientSecret  string `form:"client_secret" json:"client_secret"`
}

// RevokeToken 是一个无状态函数，直接由 Server 调用
func RevokeToken(ctx context.Context, storage Storage, secretManager *SecretManager, hasher Hasher, verifier TokenVerifier, req *RevocationRequest) error {
	// 1. 客户端认证 (Client Authentication)
	client, err := AuthenticateClient(ctx, storage, req.ClientID, req.ClientSecret, hasher)
	if err != nil {
		return err
	}

	// 2. 根据 hint 尝试撤销
	// 如果提供了 hint，优先尝试对应的类型，失败后再尝试另一种。
	// 如果未提供 hint，则尝试所有可能类型。
	var revokeErr error

	switch req.TokenTypeHint {
	case "refresh_token":
		revokeErr = RevokeRefreshToken(ctx, storage, secretManager, req.Token, client)
		if errors.Is(revokeErr, ErrTokenNotFound) || errors.Is(revokeErr, jwt.ErrTokenMalformed) {
			// 如果不是 Refresh Token，尝试当作 Access Token 处理
			revokeErr = RevokeAccessToken(ctx, storage, verifier, req.Token, client)
		}
	case "access_token":
		revokeErr = RevokeAccessToken(ctx, storage, verifier, req.Token, client)
		if errors.Is(revokeErr, jwt.ErrTokenMalformed) {
			// 如果格式不对（例如不是 JWT），尝试当作 Refresh Token 处理
			revokeErr = RevokeRefreshToken(ctx, storage, secretManager, req.Token, client)
		}
	default:
		// 未指定 hint，先尝试 Access Token (通常是 JWT，格式校验快)
		revokeErr = RevokeAccessToken(ctx, storage, verifier, req.Token, client)
		if errors.Is(revokeErr, jwt.ErrTokenMalformed) {
			// 格式不对，尝试 Refresh Token
			revokeErr = RevokeRefreshToken(ctx, storage, secretManager, req.Token, client)
		}
	}

	// 3. 处理结果
	// RFC 7009 Section 2.2: 如果服务器无法定位令牌，应返回 200 OK。
	if errors.Is(revokeErr, ErrTokenNotFound) {
		return nil
	}

	// 如果是其他错误（如存储失败），则返回错误
	return revokeErr
}

// RevokeAccessToken 处理 JWT Access Token 的撤销 (加入黑名单)
func RevokeAccessToken(ctx context.Context, storage RevocationStorage, verifier TokenVerifier, tokenStr string, client RegisteredClient) error {
	// 解析并验证 JWT 签名
	// 注意：我们需要验证签名以防止伪造 Token 进行 DoS 攻击 (Revocation DoS)，
	// 但我们不应该因为 Token 已过期而拒绝撤销 (虽然过期 Token 撤销没意义，但 RFC 建议返回 200)。
	claims, err := verifier.ParseAccessToken(ctx, tokenStr)
	if err != nil {
		// 如果 Token 已过期，视为撤销成功 (无需操作)
		if errors.Is(err, jwt.ErrTokenExpired) {
			return nil
		}
		// 如果签名无效或格式错误，返回错误
		return fmt.Errorf("invalid access token: %w", err)
	}

	// 验证 Token 是否属于调用者 Client
	if !isClientAuthorizedForToken(client, claims) {
		return fmt.Errorf("%w: client unauthorized to revoke this token", ErrUnauthorizedClient)
	}

	// 防止 ClockSkew 导致的误判
	if claims.ExpiresAt != nil && time.Now().After(claims.ExpiresAt.Time.Add(5*time.Minute)) {
		return nil
	}

	// JWT 必须有 JTI (ID) 才能被加入黑名单
	if claims.ID == "" {
		// 无状态且无 ID 的 Token 无法被撤销
		return nil
	}

	// 计算剩余有效期
	expiration := time.Now().Add(24 * time.Hour) // 默认兜底
	if claims.ExpiresAt != nil {
		expiration = claims.ExpiresAt.Time
	}

	// 加入黑名单
	if err := storage.Revoke(ctx, claims.ID, expiration); err != nil {
		return fmt.Errorf("failed to revoke access token: %w", err)
	}

	return nil
}

// RevokeRefreshToken 处理 Opaque Refresh Token 的撤销 (物理删除/标记)
func RevokeRefreshToken(ctx context.Context, storage TokenStorage, secretManager *SecretManager, tokenStr string, client RegisteredClient) error {
	// 0. 确认 Refresh Token 的有效性
	if tokenStr == "" {
		return fmt.Errorf("%w: refresh_token is required", ErrInvalidRequest)
	}
	if err := ValidateStructuredRefreshToken(ctx, secretManager, RefreshToken(tokenStr)); err != nil {
		return err
	}

	// 1. 计算哈希 (Refresh Token 在 DB 中存的是哈希)
	tokenHash := RefreshToken(tokenStr).HashForDB()

	// 2. 查找令牌
	session, err := storage.GetRefreshToken(ctx, tokenHash)
	if err != nil {
		// 包含 ErrTokenNotFound
		return err
	}

	// 3. 验证归属权
	if session.ClientID != client.GetID() {
		return fmt.Errorf("%w: client unauthorized to revoke this token", ErrUnauthorizedClient)
	}

	// 4. 执行撤销
	if err := storage.RevokeRefreshToken(ctx, tokenHash); err != nil {
		return fmt.Errorf("failed to revoke refresh token: %w", err)
	}

	return nil
}

// isClientAuthorizedForToken 检查客户端是否有权撤销该 Token
func isClientAuthorizedForToken(client RegisteredClient, claims *AccessTokenClaims) bool {
	clientID := client.GetID().String()

	// 1. 检查 azp (Authorized Party) - 最优先
	if claims.AuthorizedParty != "" {
		return claims.AuthorizedParty == clientID
	}

	// 2. 检查 aud (Audience)
	for _, aud := range claims.Audience {
		if aud == clientID {
			return true
		}
	}

	return false
}
