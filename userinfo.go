package oidc

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/bytedance/sonic"
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

// UserInfo 表示 OIDC UserInfo 端点的标准响应结构。
// 参见: OIDC Core 1.0, Section 5.1.
type UserInfo struct {
	Subject             string  `json:"sub"`
	Name                *string `json:"name,omitempty"`
	GivenName           *string `json:"given_name,omitempty"`
	FamilyName          *string `json:"family_name,omitempty"`
	Nickname            *string `json:"nickname,omitempty"`
	PreferredUsername   *string `json:"preferred_username,omitempty"`
	Profile             *string `json:"profile,omitempty"`
	Picture             *string `json:"picture,omitempty"`
	Website             *string `json:"website,omitempty"`
	Email               *string `json:"email,omitempty"`
	EmailVerified       *bool   `json:"email_verified,omitempty"`
	Gender              *string `json:"gender,omitempty"`
	Birthdate           *string `json:"birthdate,omitempty"`
	Zoneinfo            *string `json:"zoneinfo,omitempty"`
	Locale              *string `json:"locale,omitempty"`
	PhoneNumber         *string `json:"phone_number,omitempty"`
	PhoneNumberVerified *bool   `json:"phone_number_verified,omitempty"`
	UpdatedAt           int64   `json:"updated_at,omitempty"`

	// Metadata 存储扩展字段 (Custom Claims)。
	// json:"-" 表示标准库忽略该字段，我们将在 MarshalJSON 中手动将其合并到顶层。
	Metadata map[string]interface{} `json:"-"`
}

// MarshalJSON 自定义序列化逻辑
func (u *UserInfo) MarshalJSON() ([]byte, error) {
	// 1. 准备一个目标 map，用于合并数据
	result := make(map[string]interface{})

	// 2. 先填充 Metadata (作为默认值/底层值)
	// 这样可以确保标准字段稍后写入时，如果有重名 key，标准字段会覆盖 Metadata
	for k, v := range u.Metadata {
		result[k] = v
	}

	// 3. 序列化标准字段
	// 技巧：使用 type Alias UserInfo 防止递归调用死循环
	type Alias UserInfo
	standardBytes, err := sonic.Marshal((*Alias)(u))
	if err != nil {
		return nil, err
	}

	// 4. 将标准字段反序列化到 map 中 (这一步执行覆盖操作)
	if err := sonic.Unmarshal(standardBytes, &result); err != nil {
		return nil, err
	}

	// 5. 最终输出合并后的 JSON
	return sonic.Marshal(result)
}

// 预编译标准字段集合，使用空结构体做 Value 实现 Set，查找复杂度 O(1)
var standardClaims = map[string]struct{}{
	"sub":                   {},
	"name":                  {},
	"given_name":            {},
	"family_name":           {},
	"nickname":              {},
	"preferred_username":    {},
	"profile":               {},
	"picture":               {},
	"website":               {},
	"email":                 {},
	"email_verified":        {},
	"gender":                {},
	"birthdate":             {},
	"zoneinfo":              {},
	"locale":                {},
	"phone_number":          {},
	"phone_number_verified": {},
	"updated_at":            {},
}

// UnmarshalJSON 自定义反序列化逻辑
func (u *UserInfo) UnmarshalJSON(data []byte) error {
	// Step 1: 解析标准字段 (Fast Path)
	// 使用 Alias 避免递归调用 UnmarshalJSON
	type Alias UserInfo
	if err := sonic.Unmarshal(data, (*Alias)(u)); err != nil {
		return err
	}

	// Step 2: 解析 JSON 结构到 RawMessage (延迟解析)
	// 这一步很快，因为它只扫描结构，不分配具体的对象值，所有值都只是切片引用
	var rawMap map[string]json.RawMessage
	if err := sonic.Unmarshal(data, &rawMap); err != nil {
		return err
	}

	// Step 3: 提取并解析 Metadata
	if len(rawMap) > 0 {
		u.Metadata = make(map[string]interface{})

		for k, v := range rawMap {
			// 如果是标准字段，直接跳过 (O(1) Check)
			if _, isStandard := standardClaims[k]; isStandard {
				continue
			}

			// 只有非标准字段，才进行 interface{} 的反序列化
			// 这里只对剩余的几个 Metadata 字段产生反射和分配开销
			var val interface{}
			if err := sonic.Unmarshal(v, &val); err == nil {
				u.Metadata[k] = val
			}
		}
	}

	return nil
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
	userID, err := ParseUUID(claims.Subject)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid subject format", ErrInvalidGrant)
	}

	// 3. 获取用户信息
	// 仅返回 scope 允许的字段 (profile, email, phone 等)
	info, err := storage.UserGetInfoByID(ctx, userID, strings.Fields(claims.Scope))
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
