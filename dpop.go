package oidc

import (
	"context"
	"crypto"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/bytedance/sonic"
	"github.com/golang-jwt/jwt/v5"
	"github.com/lestrrat-go/jwx/v2/jwk"
)

// DPoPProof 表示 DPoP Proof JWT 的 Claims
// RFC 9449 Section 4.2
type DPoPProof struct {
	jwt.RegisteredClaims

	// htm: HTTP 方法 (必需)
	HTM string `json:"htm"`

	// htu: HTTP URI (必需，不包含查询参数和片段)
	HTU string `json:"htu"`

	// Nonce: 可选，服务器可以要求客户端包含 nonce 以防重放
	Nonce string `json:"nonce,omitempty"`
}

// VerifyDPoPProof 验证 HTTP 请求中的 DPoP Proof
// 返回 JWK Thumbprint (jkt) 用于绑定到 Access Token
//
// RFC 9449 验证步骤：
// 1. 解析 DPoP header 中的 JWT
// 2. 验证 JWT 签名 (公钥在 header 的 jwk 字段)
// 3. 验证 htm 和 htu 与请求匹配
// 4. 验证 iat 时间窗口 (推荐 ±60秒)
// 5. 验证 jti 防重放 (使用 ReplayCache)
// 6. 计算并返回 JKT (JWK Thumbprint)
//
// w: 可选的 ResponseWriter，用于在验证失败时设置服务器时间响应头
func VerifyDPoPProof(
	ctx context.Context,
	req *http.Request,
	w http.ResponseWriter,
	cache ReplayCache,
	httpMethod, httpURI string,
) (jkt string, err error) {
	// 1. 提取 DPoP header
	dpopHeader := req.Header.Get("DPoP")
	if dpopHeader == "" {
		return "", fmt.Errorf("%w: missing DPoP header", ErrInvalidRequest)
	}

	// 2. 解析 JWT (先不验证签名，需要从 header 提取公钥)
	var claims DPoPProof
	token, err := jwt.ParseWithClaims(dpopHeader, &claims, func(token *jwt.Token) (interface{}, error) {
		// 从 JWT header 提取 JWK
		jwkRaw, ok := token.Header["jwk"]
		if !ok {
			return nil, fmt.Errorf("%w: missing jwk in DPoP header", ErrInvalidRequest)
		}

		jwkMap, ok := jwkRaw.(map[string]interface{})
		if !ok {
			return nil, fmt.Errorf("%w: invalid jwk format", ErrInvalidRequest)
		}

		// 将 JWK 转换为公钥
		pubKey, err := jwkToPublicKey(jwkMap)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrInvalidRequest, err)
		}

		return pubKey, nil
	})
	if err != nil {
		return "", fmt.Errorf("%w: failed to parse DPoP proof: %v", ErrInvalidRequest, err)
	}

	if !token.Valid {
		return "", fmt.Errorf("%w: invalid DPoP proof", ErrInvalidRequest)
	}

	// 3. 验证 typ header (必须是 "dpop+jwt")
	typ, ok := token.Header["typ"].(string)
	if !ok || typ != "dpop+jwt" {
		return "", fmt.Errorf("%w: DPoP typ must be 'dpop+jwt'", ErrInvalidRequest)
	}

	// 4. 验证 alg (不能是 'none')
	alg, ok := token.Header["alg"].(string)
	if !ok || alg == "none" {
		return "", fmt.Errorf("%w: token signature is invalid, DPoP alg cannot be 'none'", ErrInvalidRequest)
	}

	// 5. 验证 htm 和 htu
	if claims.HTM != httpMethod {
		return "", fmt.Errorf("%w: DPoP htm mismatch: expected %s, got %s",
			ErrInvalidRequest, httpMethod, claims.HTM)
	}

	if claims.HTU != httpURI {
		return "", fmt.Errorf("%w: DPoP htu mismatch: expected %s, got %s",
			ErrInvalidRequest, httpURI, claims.HTU)
	}

	// 6. 验证 iat 时间窗口 (±60秒)
	if claims.IssuedAt == nil {
		return "", fmt.Errorf("%w: DPoP proof missing iat claim", ErrInvalidRequest)
	}

	now := time.Now()
	iat := claims.IssuedAt.Time
	skew := now.Sub(iat)
	absSkew := skew
	if absSkew < 0 {
		absSkew = -absSkew
	}

	// TODO: 考虑记录时间偏差统计，用于异常检测
	if absSkew > 60*time.Second {
		// [安全] 不再通过 header 暴露精确的服务器时间，减少信息泄露
		// 客户端可以通过标准的 Date header 获取大致时间
		// SetServerTimeHeader(w)

		// 返回详细的时间信息（仅用于内部日志，不暴露给客户端）
		return "", &DPoPTimeSkewError{
			Info: DPoPTimeSkewInfo{
				ServerTime: now,
				ClientTime: iat,
				Skew:       skew,
			},
			Err: fmt.Errorf("%w: DPoP proof iat too far from current time", ErrInvalidRequest),
		}
	}

	// 7. 验证 jti 防重放
	if claims.ID == "" {
		return "", fmt.Errorf("%w: DPoP proof missing jti claim", ErrInvalidRequest)
	}

	// 检查并存储 JTI (TTL 为 DPoP proof 的有效期 + 宽限时间)
	ttl := 120 * time.Second // 60秒有效期 + 60秒宽限
	isReplay, err := cache.CheckAndStore(ctx, claims.ID, ttl)
	if err != nil {
		return "", fmt.Errorf("failed to check DPoP replay: %w", err)
	}
	if isReplay {
		return "", fmt.Errorf("%w: DPoP proof jti has been used", ErrInvalidRequest)
	}

	// 8. 计算 JKT (JWK Thumbprint)
	jwkMap := token.Header["jwk"].(map[string]interface{})
	jkt, err = ComputeJKT(jwkMap)
	if err != nil {
		return "", fmt.Errorf("failed to compute JKT: %w", err)
	}

	return jkt, nil
}

// ComputeJKT 计算 JWK Thumbprint (RFC 7638)
// 用于生成 cnf.jkt claim
func ComputeJKT(jwk map[string]interface{}) (string, error) {
	// 1. 提取并校验 kty
	kty, ok := jwk["kty"].(string)
	if !ok || kty == "" {
		return "", ErrInvalidJWKType
	}

	// 2. 准备 Thumbprint 输入 map
	// 注意：必须确保提取的值都是字符串，且必须存在
	var thumbprintInput map[string]interface{}

	switch kty {
	case "RSA":
		if !checkFields(jwk, "e", "n") {
			return "", ErrMissingJWKFields
		}
		thumbprintInput = map[string]interface{}{
			"e":   jwk["e"],
			"kty": kty,
			"n":   jwk["n"],
		}
	case "EC":
		if !checkFields(jwk, "crv", "x", "y") {
			return "", ErrMissingJWKFields
		}
		thumbprintInput = map[string]interface{}{
			"crv": jwk["crv"],
			"kty": kty,
			"x":   jwk["x"],
			"y":   jwk["y"],
		}
	case "OKP": // Ed25519 / X25519
		if !checkFields(jwk, "crv", "x") {
			return "", ErrMissingJWKFields
		}
		thumbprintInput = map[string]interface{}{
			"crv": jwk["crv"],
			"kty": kty,
			"x":   jwk["x"],
		}
	case "oct": // 对称密钥 (HMAC)
		if !checkFields(jwk, "k") {
			return "", ErrMissingJWKFields
		}
		thumbprintInput = map[string]interface{}{
			"k":   jwk["k"],
			"kty": kty,
		}
	default:
		return "", ErrInvalidJWKType
	}

	// 3. 序列化为规范 JSON
	// 使用 json.Marshal 默认会按字典序排序 key，这是符合 RFC 要求的。
	jsonBytes, err := sonic.ConfigStd.Marshal(thumbprintInput)
	if err != nil {
		return "", err
	}

	// 4. SHA-256 哈希
	hash := sha256.Sum256(jsonBytes)

	// 5. Base64url 编码 (无 Padding)
	return base64.RawURLEncoding.EncodeToString(hash[:]), nil
}

// checkFields 辅助函数：确保字段存在且为字符串
func checkFields(jwk map[string]interface{}, fields ...string) bool {
	for _, f := range fields {
		v, ok := jwk[f]
		// JWK 的核心参数必须是字符串
		if !ok {
			return false
		}
		if s, isStr := v.(string); !isStr || s == "" {
			return false
		}
	}
	return true
}

// jwkToPublicKey 将 JWK map 转换为 crypto.PublicKey
func jwkToPublicKey(jwkMap map[string]interface{}) (crypto.PublicKey, error) {
	// 使用 lestrrat-go/jwx 解析 JWK
	// 1. 将 map 序列化为 JSON
	jwkBytes, err := sonic.ConfigStd.Marshal(jwkMap)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal JWK: %w", err)
	}

	// 2. 使用 jwx 解析
	key, err := jwk.ParseKey(jwkBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse JWK: %w", err)
	}

	// 3. 提取原始公钥
	var pubKey crypto.PublicKey
	if err := key.Raw(&pubKey); err != nil {
		return nil, fmt.Errorf("failed to extract public key from JWK: %w", err)
	}

	return pubKey, nil
}

// BuildDPoPBoundAccessTokenURI 构建资源请求 URI (去除查询参数和片段)
// RFC 9449 要求 htu 与实际请求的 URI 匹配(不含查询参数)
func BuildDPoPBoundAccessTokenURI(fullURL string) (string, error) {
	// 解析并移除 query 和 fragment
	idx := strings.IndexAny(fullURL, "?#")
	if idx == -1 {
		return fullURL, nil
	}
	return fullURL[:idx], nil
}
