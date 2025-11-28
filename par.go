package oidc

import (
	"context"
	"fmt"
	"regexp"
	"time"

	"github.com/google/uuid"
)

// PARRequest 表示推送授权请求的参数
// RFC 9126 Section 2
type PARRequest struct {
	// 客户端认证信息 (必需)
	ClientID     string `form:"client_id" json:"client_id"`
	ClientSecret string `form:"client_secret" json:"client_secret"` // 对于机密客户端

	// 授权请求参数 (与标准 /authorize 端点相同)
	RedirectURI  string `form:"redirect_uri" json:"redirect_uri"`
	ResponseType string `form:"response_type" json:"response_type"`
	Scope        string `form:"scope" json:"scope"`
	State        string `form:"state" json:"state"`
	Nonce        string `form:"nonce" json:"nonce"`

	// PKCE
	CodeChallenge       string `form:"code_challenge" json:"code_challenge"`
	CodeChallengeMethod string `form:"code_challenge_method" json:"code_challenge_method"`

	// DPoP (RFC 9449): JWK Thumbprint from DPoP proof
	// 由 HTTP Handler 验证 DPoP Proof 后提取并传入
	DPoPJKT string `form:"-" json:"-"`

	// 扩展参数
	AdditionalParams map[string]string `form:"-" json:"-"`
}

// PARResponse 表示 PAR 端点的响应
// RFC 9126 Section 2.2
type PARResponse struct {
	RequestURI string `json:"request_uri"` // 格式: urn:ietf:params:oauth:request_uri:...
	ExpiresIn  int    `json:"expires_in"`  // 秒数，典型值 60
}

// PushedAuthorization 处理推送授权请求
// RFC 9126: 客户端通过后端通道提交授权参数，获得 request_uri
//
// 安全要求：
// - 必须验证客户端身份 (Client Secret 或 mTLS)
// - 所有授权参数必须经过验证
// - request_uri 只能使用一次
// - TTL 应较短 (推荐 60 秒)
func PushedAuthorization(
	ctx context.Context,
	storage Storage,
	hasher Hasher,
	req *PARRequest,
) (*PARResponse, error) {
	// 1. 验证客户端身份 (PAR 端点需要客户端认证)
	_, err := AuthenticateClient(ctx, storage, req.ClientID, req.ClientSecret, hasher)
	if err != nil {
		return nil, fmt.Errorf("%w: client authentication failed", ErrUnauthorizedClient)
	}
	if req.DPoPJKT == "" {
		req.DPoPJKT = ExtractDPoPJKT(ctx)
	}

	// 2. 构造 AuthorizeRequest 并验证
	authorizeReq := &AuthorizeRequest{
		ClientID:            req.ClientID,
		RedirectURI:         req.RedirectURI,
		ResponseType:        req.ResponseType,
		Scope:               req.Scope,
		State:               req.State,
		Nonce:               req.Nonce,
		CodeChallenge:       req.CodeChallenge,
		CodeChallengeMethod: req.CodeChallengeMethod,
		DPoPJKT:             req.DPoPJKT, // DPoP 绑定
	}

	// 3. 执行标准的授权请求验证 (复用 RequestAuthorize 的验证逻辑)
	_, err = RequestAuthorize(ctx, storage, authorizeReq)
	if err != nil {
		return nil, err
	}

	// 4. 生成 request_URI
	// RFC 9126 要求格式: urn:ietf:params:oauth:request_uri:<唯一标识>
	uuidV7, err := uuid.NewV7()
	if err != nil {
		return nil, fmt.Errorf("failed to generate request_uri: %w", err)
	}
	requestURI := fmt.Sprintf("urn:ietf:params:oauth:request_uri:%s", uuidV7.String())

	// 5. [安全] 验证 payload 大小，防止 DoS 攻击
	// 限制为 100KB（可配置）
	const maxPayloadSize = 100 * 1024 // 100KB
	// 估算序列化后的大小
	estimatedSize := len(authorizeReq.ClientID) + len(authorizeReq.RedirectURI) +
		len(authorizeReq.ResponseType) + len(authorizeReq.Scope) +
		len(authorizeReq.State) + len(authorizeReq.Nonce) +
		len(authorizeReq.CodeChallenge) + len(authorizeReq.CodeChallengeMethod)
	if estimatedSize > maxPayloadSize {
		return nil, fmt.Errorf("%w: PAR request payload too large (max %d bytes)", ErrInvalidRequest, maxPayloadSize)
	}

	// 6. 存储 PAR 会话 (TTL = 60 秒)
	const parTTLSeconds = 60
	err = storage.SavePARSession(ctx, requestURI, authorizeReq, time.Duration(parTTLSeconds)*time.Second)
	if err != nil {
		return nil, fmt.Errorf("failed to save PAR session: %w", err)
	}

	// 7. 返回响应
	return &PARResponse{
		RequestURI: requestURI,
		ExpiresIn:  parTTLSeconds,
	}, nil
}

// RFC 8141 URN 简易正则: ^urn:[a-zA-Z0-9][a-zA-Z0-9-]{0,31}:.+$
var urnRegex = regexp.MustCompile(`^urn:[a-zA-Z0-9][a-zA-Z0-9-]{0,31}:.+$`)

// ValidateURN 验证 URN 格式
func ValidateURN(uri string) error {
	if !urnRegex.MatchString(uri) {
		return fmt.Errorf("invalid urn format")
	}
	// 如果正则通过，通常 url.Parse 也就没问题了，但为了保险可以再 Parse 一次
	return nil
}

// LoadPARSession 从 request_uri 加载授权请求参数
// 仅在 /authorize 端点内部使用
func LoadPARSession(ctx context.Context, storage PARStorage, requestURI string) (*AuthorizeRequest, error) {
	// 验证 request_uri 格式
	if err := ValidateURN(requestURI); err != nil {
		return nil, fmt.Errorf("%w: invalid request_uri format", ErrInvalidRequest)
	}

	// 获取并删除会话 (原子操作，确保只使用一次)
	req, err := storage.GetAndDeletePARSession(ctx, requestURI)
	if err != nil {
		return nil, fmt.Errorf("%w: request_uri not found or expired", ErrInvalidRequest)
	}

	return req, nil
}
