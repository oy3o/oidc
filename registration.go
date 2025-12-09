package oidc

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"
)

// ClientRegistrationRequest RFC 7591 Client Registration Request
type ClientRegistrationRequest struct {
	RedirectURIs  []string `json:"redirect_uris"`
	GrantTypes    []string `json:"grant_types"`
	ResponseTypes []string `json:"response_types"`
	Scope         string   `json:"scope"`
	ClientName    string   `json:"client_name"`
	LogoURI       string   `json:"logo_uri,omitempty"`
	ClientURI     string   `json:"client_uri,omitempty"`

	// auth_method 决定了是否需要生成 secret
	// options: client_secret_basic, client_secret_post, none, private_key_jwt
	TokenEndpointAuthMethod string `json:"token_endpoint_auth_method"`

	// 扩展字段：绑定所有者
	OwnerID string `json:"-"`
}

// ClientRegistrationResponse RFC 7591 Response
type ClientRegistrationResponse struct {
	ClientID              string `json:"client_id"`
	ClientSecret          string `json:"client_secret,omitempty"` // 仅在创建或重置时返回明文
	ClientSecretExpiresAt int64  `json:"client_secret_expires_at,omitempty"`

	RedirectURIs []string `json:"redirect_uris"`
	GrantTypes   []string `json:"grant_types"`
	Scope        string   `json:"scope"`
	ClientName   string   `json:"client_name"`
	LogoURI      string   `json:"logo_uri,omitempty"`

	TokenEndpointAuthMethod string `json:"token_endpoint_auth_method"`
	RegistrationAccessToken string `json:"registration_access_token,omitempty"`
	RegistrationClientURI   string `json:"registration_client_uri,omitempty"`
}

// ClientUpdateRequest RFC 7591 Client Update Request
type ClientUpdateRequest struct {
	ClientID string `json:"client_id"`
	*ClientRegistrationRequest
}

// ListQuery 列表查询参数
type ListQuery struct {
	Offset int
	Limit  int
}

// RegisterClient 处理新客户端注册
// hasher: 必填，用于对生成的 Secret 进行哈希处理后再存入 DB
func RegisterClient(ctx context.Context, storage ClientStorage, hasher Hasher, req *ClientRegistrationRequest) (*ClientRegistrationResponse, error) {
	// 1. 输入验证
	if err := ValidateRegistrationRequest(req, AllowedSchemes); err != nil {
		return nil, err
	}

	// 2. 生成 Client ID
	uuidV7, err := uuid.NewV7()
	if err != nil {
		return nil, fmt.Errorf("failed to generate client id: %w", err)
	}
	clientID := BinaryUUID(uuidV7)

	// 3. 准备存储元数据
	// 如果 req.OwnerID 也是 UUID 格式，需解析；这里假设它已验证
	var ownerID BinaryUUID
	if req.OwnerID != "" {
		if uid, err := uuid.Parse(req.OwnerID); err == nil {
			ownerID = BinaryUUID(uid)
		}
	}

	// 设置默认 Grant Types
	grantTypes := req.GrantTypes
	if len(grantTypes) == 0 {
		grantTypes = []string{"authorization_code"}
	}

	isConfidential := isConfidentialClient(req.TokenEndpointAuthMethod)
	metadata := &ClientMetadata{
		ID:                      clientID,
		OwnerID:                 ownerID, // 需在 ClientMetadata 结构体中添加此字段
		RedirectURIs:            req.RedirectURIs,
		GrantTypes:              grantTypes,
		Scope:                   req.Scope,
		Name:                    req.ClientName,
		LogoURI:                 req.LogoURI,
		TokenEndpointAuthMethod: req.TokenEndpointAuthMethod,
		IsConfidentialClient:    isConfidential,
		CreatedAt:               time.Now(),
	}

	// 4. 确定是否需要 Secret (机密客户端)
	var plainSecret string
	var secretExpiresAt int64 = 0 // 0 表示永不过期
	if isConfidential {
		// 生成高强度随机密钥 (32字节 = 256位)
		plainSecret, err = RandomString(32)
		if err != nil {
			return nil, fmt.Errorf("failed to generate secret: %w", err)
		}

		// [安全] 进行哈希处理
		if hasher == nil {
			return nil, ErrSecretHasherRequired
		}
		hashedSecret, err := hasher.Hash(ctx, []byte(plainSecret))
		if err != nil {
			return nil, fmt.Errorf("failed to hash secret: %w", err)
		}

		metadata.Secret = SecretString(hashedSecret)
	}

	// 5. 持久化
	_, err = storage.ClientCreate(ctx, metadata)
	if err != nil {
		return nil, fmt.Errorf("repository failed: %w", err)
	}

	// 6. 构造响应 (返回明文 Secret)
	resp := &ClientRegistrationResponse{
		ClientID:                clientID.String(),
		ClientSecret:            plainSecret,
		ClientSecretExpiresAt:   secretExpiresAt,
		RedirectURIs:            metadata.RedirectURIs,
		GrantTypes:              metadata.GrantTypes,
		Scope:                   metadata.Scope,
		ClientName:              metadata.Name,
		LogoURI:                 metadata.LogoURI,
		TokenEndpointAuthMethod: req.TokenEndpointAuthMethod,
	}

	return resp, nil
}

// UnregisterClient 注销客户端
// 注意：实际业务中通常需要验证是否有权删除（如验证 Registration Access Token 或 OwnerID）
func UnregisterClient(ctx context.Context, storage ClientStorage, clientIDStr string) error {
	id, err := ParseUUID(clientIDStr)
	if err != nil {
		return fmt.Errorf("%w: invalid client id", ErrInvalidRequest)
	}

	if err := storage.ClientDeleteByID(ctx, id); err != nil {
		return err
	}
	return nil
}

// ClientUpdate 更新客户端信息
// RFC 7592: Update Request
func ClientUpdate(ctx context.Context, storage ClientStorage, req *ClientUpdateRequest) (*ClientRegistrationResponse, error) {
	clientID, err := ParseUUID(req.ClientID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid client id", ErrInvalidRequest)
	}

	// 1. 获取现有客户端 (确保存在)
	_, err = storage.ClientFindByID(ctx, clientID)
	if err != nil {
		return nil, err
	}

	// 2. 验证新输入
	if err := ValidateRegistrationRequest(req.ClientRegistrationRequest, AllowedSchemes); err != nil {
		return nil, err
	}

	// 3. 准备更新数据
	// 注意：通常 Update 不会重置 Secret，除非显式请求 Rotate。
	// 这里保留原 Secret，仅更新元数据。
	// 若需支持 Rotate Secret，应单独提供 RotateSecret 接口或通过特定参数触发。

	// 从 oldClient 恢复部分不可变更或未变更的数据
	// 注意：这里假设 RegisteredClient 接口暴露了获取 Metadata 的方法，或者直接转换
	// 为简化，这里演示逻辑：

	metadata := &ClientMetadata{
		ID:                      clientID,
		RedirectURIs:            req.RedirectURIs,
		GrantTypes:              req.GrantTypes,
		Scope:                   req.Scope,
		Name:                    req.ClientName,
		LogoURI:                 req.LogoURI,
		TokenEndpointAuthMethod: req.TokenEndpointAuthMethod,
		IsConfidentialClient:    isConfidentialClient(req.TokenEndpointAuthMethod),
	}

	updated, err := storage.ClientUpdate(ctx, clientID, metadata)
	if err != nil {
		return nil, err
	}

	return &ClientRegistrationResponse{
		ClientID:     updated.GetID().String(),
		RedirectURIs: updated.GetRedirectURIs(),
		ClientName:   req.ClientName, // 简化返回
		Scope:        req.Scope,
	}, nil
}

// ListClient 列出所有客户端
func ListClient(ctx context.Context, storage ClientStorage, query ListQuery) ([]RegisteredClient, error) {
	return storage.ClientListAll(ctx, query)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

var AllowedSchemes = map[string]struct{}{
	"http":  {},
	"https": {},
}

// ValidateRegistrationRequest 集中处理校验逻辑
func ValidateRegistrationRequest(req *ClientRegistrationRequest, allowedSchemes map[string]struct{}) error {
	if req.ClientName == "" {
		return fmt.Errorf("%w: client_name is required", ErrInvalidRequest)
	}

	if len(req.RedirectURIs) == 0 {
		return fmt.Errorf("%w: at least one redirect_uri is required", ErrInvalidRequest)
	}

	if allowedSchemes == nil {
		allowedSchemes = AllowedSchemes
	}

	for _, uri := range req.RedirectURIs {
		u, err := url.Parse(uri)
		if err != nil || !u.IsAbs() {
			return fmt.Errorf("%w: invalid redirect_uri: %s", ErrInvalidRequest, uri)
		}

		// [安全增强] Redirect URI 验证
		// 1. 对于 http/https scheme，必须使用 https（生产环境）
		// 2. localhost 仅在开发模式下允许
		// 3. 自定义 Scheme 必须严格白名单
		switch u.Scheme {
		case "https":
			// HTTPS 总是允许
		case "http":
			// HTTP 仅允许 localhost（开发环境）
			// TODO: 添加 DevMode 配置，生产环境禁用
			if u.Hostname() != "localhost" && u.Hostname() != "127.0.0.1" {
				return fmt.Errorf("%w: http scheme only allowed for localhost, got %s", ErrInvalidRequest, u.Hostname())
			}
		default:
			scheme := strings.ToLower(u.Scheme)
			if _, ok := allowedSchemes[scheme]; !ok {
				return fmt.Errorf("%w: invalid redirect_uri scheme: %s", ErrInvalidRequest, u.Scheme)
			}
		}

		// 禁止使用 Fragment (#)
		if u.Fragment != "" {
			return fmt.Errorf("%w: redirect_uri must not contain fragment: %s", ErrInvalidRequest, uri)
		}
	}

	return nil
}

// isConfidentialClient 判断客户端类型
func isConfidentialClient(method string) bool {
	// 默认为 confidential
	if method == "" {
		return true
	}
	// 公共客户端不需要 secret
	if method == "none" {
		return false
	}
	// 其他方法 (client_secret_basic, client_secret_post, etc.) 需要 secret
	return true
}
