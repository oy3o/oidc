package oidc

import (
	"context"
	"crypto"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// DefaultSupportedSigningAlgs 默认支持的签名算法
var DefaultSupportedSigningAlgs = []string{"RS256", "RS384", "RS512", "ES256", "ES384", "ES512", "EdDSA"}

// KeySource 定义了验证器如何获取公钥。
// 它可以是静态的 JWKS，也可以是远程 URL (OIDC Discovery)。
type KeySource interface {
	// GetKey 根据 Key ID (kid) 返回对应的公钥。
	// 如果 kid 为空，且源中只有一个 key，应返回该 key。
	GetKey(ctx context.Context, kid string) (crypto.PublicKey, error)
}

// ClientVerifier 用于客户端验证 OIDC ID Token。
type ClientVerifier struct {
	issuer               string
	keySet               KeySource
	clientID             string
	supportedSigningAlgs []string
	nowFunc              func() time.Time // 用于测试的时间注入
}

// NewClientVerifier 创建一个新的客户端验证器。
// issuer: 必须完全匹配 Token 中的 iss。
// clientID: 必须包含在 Token 的 aud 中。
func NewClientVerifier(issuer, clientID string, keySet KeySource) *ClientVerifier {
	return &ClientVerifier{
		issuer:               issuer,
		clientID:             clientID,
		keySet:               keySet,
		supportedSigningAlgs: DefaultSupportedSigningAlgs,
		nowFunc:              time.Now,
	}
}

// SetSupportedSigningAlgs 设置支持的签名算法
func (v *ClientVerifier) SetSupportedSigningAlgs(algs []string) {
	v.supportedSigningAlgs = algs
}

// Verify 解析并验证原始 ID Token 字符串。
func (v *ClientVerifier) Verify(ctx context.Context, rawToken string) (*IDTokenClaims, error) {
	// 1. 定义 KeyFunc：这是 jwt/v5 解析流程的回调，用于提供验证用的公钥
	keyFunc := func(token *jwt.Token) (interface{}, error) {
		// 验证签名算法是否符合预期 (强制非对称加密)
		if alg, ok := token.Header["alg"].(string); !ok || !slices.Contains(v.supportedSigningAlgs, alg) {
			return nil, ErrUnexpectedSigningMethod
		}

		// 获取 Key ID
		kid, _ := token.Header["kid"].(string)

		// 从 KeySource 获取公钥
		pubKey, err := v.keySet.GetKey(ctx, kid)
		if err != nil {
			return nil, fmt.Errorf("failed to get public key: %w", err)
		}
		return pubKey, nil
	}

	// 2. 解析 Token (同时会验证签名和标准 Claims 的格式)
	var claims IDTokenClaims
	token, err := jwt.ParseWithClaims(rawToken, &claims, keyFunc)
	if err != nil {
		if errors.Is(err, jwt.ErrTokenExpired) {
			return nil, ErrTokenExpired
		}
		if errors.Is(err, jwt.ErrTokenSignatureInvalid) {
			return nil, ErrTokenSignatureInvalid
		}
		return nil, fmt.Errorf("failed to parse token: %w", err)
	}

	if !token.Valid {
		return nil, ErrTokenIsInvalid
	}

	// 3. 业务逻辑验证 (OIDC Core 1.0)

	// 禁止没有过期时间的 token
	if claims.ExpiresAt == nil {
		return nil, ErrExpClaimRequired
	}

	// 确认发布者与预期一致
	if claims.Issuer != v.issuer {
		return nil, fmt.Errorf("%w: expected %s, got %s", ErrInvalidIssuer, v.issuer, claims.Issuer)
	}

	// 确认颁发目标包括自身
	// jwt/v5 的 ParseWithClaims 默认会验证 aud 是否存在，但我们需要验证它是否包含我们的 clientID
	if !tokenAudienceContains(claims.Audience, v.clientID) {
		return nil, fmt.Errorf("%w: expected audience %s, got %v", ErrInvalidAudience, v.clientID, claims.Audience)
	}

	// Authorized Party Check (OIDC Core Section 3.1.3.7)
	// 如果 aud 有多个值，azp 必须存在 (OIDC Core Section 3.1.3.7)
	if len(claims.Audience) > 1 && claims.AuthorizedParty == "" {
		return nil, ErrAZPRequired
	}

	// 如果 azp 存在，它必须是发给我的 (Client 必须验证自己就是发起方)
	if claims.AuthorizedParty != "" && claims.AuthorizedParty != v.clientID {
		return nil, ErrAZPMismatch
	}

	return &claims, nil
}

// ResourceVerifier 用于资源服务器验证 OIDC ID Token。
type ResourceVerifier struct {
	issuer               string
	keySet               KeySource
	resourceURI          string
	trustedClients       []string
	supportedSigningAlgs []string
	nowFunc              func() time.Time // 用于测试的时间注入
}

// NewResourceVerifier 创建一个新的客户端验证器。
// issuer: 必须完全匹配 Token 中的 iss。
// resourceURI: 必须包含在 Token 的 aud 中。
// trustedClients: 如果不为nil, 会限制使用本服务的请求客户端
func NewResourceVerifier(issuer, resourceURI string, keySet KeySource, trustedClients []string) *ResourceVerifier {
	// No need to convert to map anymore, slices.Contains will be used directly
	return &ResourceVerifier{
		issuer:               issuer,
		keySet:               keySet,
		resourceURI:          resourceURI,
		trustedClients:       trustedClients, // Assign directly
		supportedSigningAlgs: DefaultSupportedSigningAlgs,
		nowFunc:              time.Now,
	}
}

// SetSupportedSigningAlgs 设置支持的签名算法
func (v *ResourceVerifier) SetSupportedSigningAlgs(algs []string) {
	v.supportedSigningAlgs = algs
}

// Verify 解析并验证原始 ID Token 字符串。
func (v *ResourceVerifier) Verify(ctx context.Context, rawToken string) (*AccessTokenClaims, error) {
	// 1. 定义 KeyFunc：这是 jwt/v5 解析流程的回调，用于提供验证用的公钥
	keyFunc := func(token *jwt.Token) (interface{}, error) {
		// 验证签名算法是否符合预期 (强制非对称加密)
		if alg, ok := token.Header["alg"].(string); !ok || !slices.Contains(v.supportedSigningAlgs, alg) {
			return nil, ErrUnexpectedSigningMethod
		}

		// 获取 Key ID
		kid, _ := token.Header["kid"].(string)

		// 从 KeySource 获取公钥
		pubKey, err := v.keySet.GetKey(ctx, kid)
		if err != nil {
			return nil, fmt.Errorf("failed to get public key: %w", err)
		}
		return pubKey, nil
	}

	// 2. 解析 Token (同时会验证签名和标准 Claims 的格式)
	var claims AccessTokenClaims
	token, err := jwt.ParseWithClaims(rawToken, &claims, keyFunc)
	if err != nil {
		if errors.Is(err, jwt.ErrTokenExpired) {
			return nil, ErrTokenExpired
		}
		if errors.Is(err, jwt.ErrTokenSignatureInvalid) {
			return nil, ErrTokenSignatureInvalid
		}
		return nil, fmt.Errorf("failed to parse token: %w", err)
	}

	if !token.Valid {
		return nil, ErrTokenIsInvalid
	}

	// 3. 业务逻辑验证 (OIDC Core 1.0)

	// 禁止没有过期时间的 token
	if claims.ExpiresAt == nil {
		return nil, ErrExpClaimRequired
	}

	// 确认发布者与预期一致
	if claims.Issuer != v.issuer {
		return nil, fmt.Errorf("%w: expected %s, got %s", ErrInvalidIssuer, v.issuer, claims.Issuer)
	}

	// 确认颁发目标包括自身
	// jwt/v5 的 ParseWithClaims 默认会验证 aud 是否存在，但我们需要验证它是否包含我们的 resourceURI
	if !tokenAudienceContains(claims.Audience, v.resourceURI) {
		return nil, fmt.Errorf("%w: expected audience %s, got %v", ErrInvalidAudience, v.resourceURI, claims.Audience)
	}

	// Authorized Party Check (OIDC Core Section 3.1.3.7)
	//  OIDC 协议性检查：如果 aud > 1，azp 必须存在
	if len(claims.Audience) > 1 && claims.AuthorizedParty == "" {
		return nil, ErrAZPRequired
	}

	// 如果启用了白名单 (trustedClients 不为空)，则必须检查 azp
	if len(v.trustedClients) > 0 {
		// 开启了白名单，但 Token 没带 azp, 拒绝，因为无法确认来源。
		if claims.AuthorizedParty == "" {
			return nil, ErrAZPRequiredForTrust
		}
		// 必须是我们信任的客户端
		if !slices.Contains(v.trustedClients, claims.AuthorizedParty) {
			return nil, ErrAZPNotAuthorized
		}
	}

	return &claims, nil
}

// StaticKeySet 是 KeySource 的一个简单实现，用于基于本地 JWKS 验证 (单元测试或本地开发用)
type StaticKeySet struct {
	Keys map[string]crypto.PublicKey
}

func NewStaticKeySet() *StaticKeySet {
	return &StaticKeySet{Keys: make(map[string]crypto.PublicKey)}
}

func (s *StaticKeySet) Add(kid string, pub crypto.PublicKey) {
	s.Keys[kid] = pub
}

func (s *StaticKeySet) GetKey(ctx context.Context, kid string) (crypto.PublicKey, error) {
	// 如果没有指定 kid 且只有一个 key，直接返回
	if kid == "" && len(s.Keys) == 1 {
		for _, k := range s.Keys {
			return k, nil
		}
	}

	key, ok := s.Keys[kid]
	if !ok {
		return nil, ErrKeyNotFound
	}
	return key, nil
}

// helper
func tokenAudienceContains(aud jwt.ClaimStrings, clientID string) bool {
	for _, a := range aud {
		if a == clientID {
			return true
		}
	}
	return false
}
