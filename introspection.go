package oidc

import (
	"context"
	"fmt"
	"time"
)

// IntrospectionResponse RFC 7662 Introspection Response
type IntrospectionResponse struct {
	Active    bool   `json:"active"`
	Scope     string `json:"scope,omitempty"`
	ClientID  string `json:"client_id,omitempty"`
	Username  string `json:"username,omitempty"`
	TokenType string `json:"token_type,omitempty"`
	Exp       int64  `json:"exp,omitempty"`
	Iat       int64  `json:"iat,omitempty"`
	Nbf       int64  `json:"nbf,omitempty"`
	Sub       string `json:"sub,omitempty"`
	Aud       string `json:"aud,omitempty"`
	Iss       string `json:"iss,omitempty"`
	Jti       string `json:"jti,omitempty"`

	// DPoP (RFC 9449): Confirmation claim
	Cnf map[string]interface{} `json:"cnf,omitempty"`
}

// Introspect 验证 Token 状态
// RFC 7662: OAuth 2.0 Token Introspection
func Introspect(ctx context.Context, storage Storage, verifier TokenVerifier, tokenStr, clientIDStr, clientSecret string, hasher Hasher) (*IntrospectionResponse, error) {
	// 0. 验证调用者身份 (Client Authentication)
	// Introspection 是高度敏感的操作，必须验证调用者是否有权查询
	_, err := AuthenticateClient(ctx, storage, clientIDStr, clientSecret, hasher)
	if err != nil {
		// 认证失败返回 401/400
		return nil, err
	}

	// 1. 尝试作为 Access Token 解析 (JWT)
	claims, err := verifier.ParseAccessToken(ctx, tokenStr)
	if err == nil {
		// 检查是否撤销
		if claims.ID != "" {
			revoked, err := storage.IsRevoked(ctx, claims.ID)
			if err != nil {
				return nil, fmt.Errorf("failed to check revocation: %w", err)
			}
			if revoked {
				return &IntrospectionResponse{Active: false}, nil
			}
		}

		// 安全获取 Audience
		aud := ""
		if len(claims.Audience) > 0 {
			aud = claims.Audience[0]
		}

		return &IntrospectionResponse{
			Active:    true,
			Scope:     claims.Scope,
			ClientID:  claims.AuthorizedParty,
			Username:  claims.Subject, // 通常 sub 是 userID
			TokenType: "Bearer",
			Exp:       claims.ExpiresAt.Time.Unix(),
			Iat:       claims.IssuedAt.Time.Unix(),
			Sub:       claims.Subject,
			Aud:       aud,
			Iss:       claims.Issuer,
			Jti:       claims.ID,
			Cnf:       claims.Confirmation, // [DPoP] 包含 cnf claim
		}, nil
	}

	// 2. 尝试作为 Refresh Token 解析 (Opaque)
	// Refresh Token 是哈希存储的，所以我们需要先计算哈希
	// 注意：这里假设 tokenStr 是原始的 Refresh Token 字符串
	tokenHash := RefreshToken(tokenStr).HashForDB()
	session, err := storage.GetRefreshToken(ctx, tokenHash)
	if err == nil {
		// 检查是否过期
		if time.Now().After(session.ExpiresAt) {
			return &IntrospectionResponse{Active: false}, nil
		}

		return &IntrospectionResponse{
			Active:    true,
			Scope:     session.Scope,
			ClientID:  session.ClientID.String(),
			Username:  session.UserID.String(),
			TokenType: "Refresh",
			Exp:       session.ExpiresAt.Unix(),
			Iat:       session.AuthTime.Unix(),
			Sub:       session.UserID.String(),
			// RT 通常没有 aud, iss, jti 字段，或者需要从 session 中恢复
		}, nil
	}

	// 3. 既不是 AT 也不是 RT，或者已失效
	return &IntrospectionResponse{Active: false}, nil
}
