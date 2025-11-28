package oidc

import (
	"context"
	"fmt"
	"strings"

	"github.com/google/uuid"
)

// TokenVerifier 定义了 UserInfoHandler 所需的令牌验证能力。
// 由 Server 层实现，通常包括验签、验证 Issuer、验证过期时间、验证撤销状态。
// 注意：该接口不应在内部强制验证 Audience，因为 UserInfo 的 Audience 可能是动态的 ClientID。
type TokenVerifier interface {
	VerifyAccessToken(ctx context.Context, tokenStr string) (*AccessTokenClaims, error)
	// ParseAccessToken 解析并验证 Token 签名和 Issuer，但不检查撤销状态。
	// 用于撤销操作或需要自行处理撤销检查的场景。
	ParseAccessToken(ctx context.Context, tokenStr string) (*AccessTokenClaims, error)
}

// GetUserInfo 根据 claims 获取用户信息
func GetUserInfo(ctx context.Context, storage UserInfoGetter, verifier TokenVerifier, claims *AccessTokenClaims) (*UserInfo, error) {
	// 1. 验证 Token
	if claims == nil {
		return nil, fmt.Errorf("%w: invalid token", ErrInvalidGrant)
	}

	// 处理 DPoP 绑定检查
	// 如果 Access Token 绑定了 DPoP (cnf.jkt)，则请求必须包含匹配的 DPoP Proof
	if claims.Confirmation != nil {
		if jkt, ok := claims.Confirmation["jkt"].(string); ok && jkt != "" {
			currentJKT := ExtractDPoPJKT(ctx)
			if currentJKT != jkt {
				return nil, fmt.Errorf("%w: DPoP proof mismatch", ErrInvalidGrant)
			}
		}
	}

	// 2. 解析 UserID (Subject)
	if claims.Subject == "" {
		return nil, fmt.Errorf("%w: token missing subject", ErrInvalidGrant)
	}

	// 确保 Subject 格式正确
	userIDRaw, err := uuid.Parse(claims.Subject)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid subject format", ErrInvalidGrant)
	}
	userID := BinaryUUID(userIDRaw)

	// 3. 获取用户信息
	// 仅返回 scope 允许的字段 (profile, email, phone 等)
	info, err := storage.GetUserInfo(ctx, userID, strings.Fields(claims.Scope))
	if err != nil {
		return nil, err
	}

	// 安全防御：确保 Storage 返回的用户 ID 确实与 Token 中的一致
	// 防止 Storage 实现层出现 ID 混淆或越权漏洞
	if info.Subject != "" && info.Subject != claims.Subject {
		return nil, fmt.Errorf("%w: user info subject mismatch", ErrInvalidGrant)
	}

	// 4. 确保响应中的 sub 与 Token 中的 sub 一致
	// OIDC Core 1.0 Section 5.3.2
	info.Subject = claims.Subject

	return info, nil
}
