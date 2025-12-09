package oidc

import (
	"context"
	"crypto"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"fmt"
	"hash"
	"strings"
	"time"

	"github.com/bytedance/sonic"
	"github.com/golang-jwt/jwt/v5"
)

// IDTokenClaims 表示 OIDC ID Token 的标准载荷。
// 参见: OIDC Core 1.0, Section 2.
type IDTokenClaims struct {
	jwt.RegisteredClaims

	// OIDC 特定声明
	Nonce           string `json:"nonce,omitempty"`     // 关联客户端会话的字符串值，用于缓解重放攻击
	AuthTime        int64  `json:"auth_time,omitempty"` // 终端用户认证发生的时间
	AuthorizedParty string `json:"azp,omitempty"`       // 授权方 (Authorized Party)，当 aud 包含多个值时必须存在
	AtHash          string `json:"at_hash,omitempty"`   // Access Token 的哈希值，用于验证 Access Token
	CHash           string `json:"c_hash,omitempty"`    // Code 的哈希值

	// Profile 声明 (标准 Scope: profile, email, phone)
	Name              *string `json:"name,omitempty"`
	PreferredUsername *string `json:"preferred_username,omitempty"`
	Picture           *string `json:"picture,omitempty"`

	Email         *string `json:"email,omitempty"`
	EmailVerified *bool   `json:"email_verified,omitempty"` // 指针用于区分 false 和 null

	PhoneNumber         *string `json:"phone_number,omitempty"`
	PhoneNumberVerified *bool   `json:"phone_number_verified,omitempty"`
}

func (ic *IDTokenClaims) SignedString(method jwt.SigningMethod, privateKey crypto.PrivateKey) (IDToken, error) {
	token := jwt.NewWithClaims(method, ic)
	signedString, err := token.SignedString(privateKey)
	if err != nil {
		return "", err
	}
	return IDToken(signedString), nil
}

type IDToken SecretString

// AccessTokenClaims 表示自定义的 Access Token 载荷。
// 虽然 OAuth2 没有严格规定 Access Token 格式，但使用 JWT 是常见做法。
type AccessTokenClaims struct {
	jwt.RegisteredClaims

	// --- OAuth2 协议核心字段 ---
	Scope string `json:"scope,omitempty"` // 核心权限字段！例如 "read:orders write:profile"

	// --- 扩展字段 ---
	AuthorizedParty string `json:"azp,omitempty"` // 哪个 Client 发起的请求？(用于限流、审计)

	// --- DPoP (RFC 9449) ---
	// Confirmation claim: 用于 DPoP sender-constrained tokens
	// 格式: {"jkt": "<JWK Thumbprint>"}
	Confirmation map[string]interface{} `json:"cnf,omitempty"`
}

func (ac *AccessTokenClaims) SignedString(method jwt.SigningMethod, privateKey crypto.PrivateKey) (AccessToken, error) {
	token := jwt.NewWithClaims(method, ac)
	signedString, err := token.SignedString(privateKey)
	if err != nil {
		return "", err
	}
	return AccessToken(signedString), nil
}

type AccessToken SecretString

// Hash 根据签名算法计算 Access Token 的哈希值
// 规范要求：Hash 算法必须匹配 ID Token 的签名算法
func (ac AccessToken) Hash(alg jwt.SigningMethod) (string, error) {
	return Hash(alg, string(ac))
}

type RefreshToken SecretString

// HashForDB 刷新 token 使用 sha256 进行 hash
// 如果是结构化 Token (kid.meta.rand.sig)，只 Hash 随机部分 (rand)
// 这配合签名验证可防止数据库 DoS，同时保证数据库索引的唯一性和安全性
func (t RefreshToken) HashForDB() Hash256 {
	s := string(t)
	parts := strings.Split(s, ".")

	// 结构化 Token 格式: kid.meta.rand.sig (4 parts)
	if len(parts) == 4 {
		// 仅对随机部分 (parts[2]) 进行哈希
		// 这样数据库中存储的是 SHA256(base64(randBytes))
		h := sha256.Sum256([]byte(parts[2]))
		return Hash256(h[:])
	}

	// 兼容旧非结构化 Token：对整体进行哈希
	h := sha256.Sum256([]byte(s))
	return Hash256(h[:])
}

// IssueStructuredRefreshToken 生成一个结构化的 Refresh Token
func IssueStructuredRefreshToken(ctx context.Context, sm *SecretManager, userID string, ttl time.Duration) (RefreshToken, error) {
	// 1. 随机部分 (用于防重放和数据库索引)
	randBytes := make([]byte, 32)
	rand.Read(randBytes)

	// 2. 元数据
	meta := struct {
		UID string `json:"u"`
		Exp int64  `json:"e"`
	}{
		UID: userID,
		Exp: time.Now().Add(ttl).Unix(),
	}
	metaJson, err := sonic.Marshal(meta)
	if err != nil {
		return "", err
	}

	// 3. 密钥
	key, kid := sm.GetSigningKey(ctx)
	if key == nil {
		return "", ErrNoSigningKey
	}

	// 4. 拼接前缀
	// 格式: rt.base64(meta).base64(rand)
	payload := fmt.Sprintf("%s.%s.%s",
		kid,
		base64.RawURLEncoding.EncodeToString(metaJson),
		base64.RawURLEncoding.EncodeToString(randBytes),
	)

	// 5. 签名 (使用服务器内部密钥，不对外公开)
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(payload))
	signature := mac.Sum(nil)

	// 6. 最终 Token
	token := fmt.Sprintf("%s.%s", payload, base64.RawURLEncoding.EncodeToString(signature))

	return RefreshToken(token), nil
}

// 验证 Token (在查库之前)
func ValidateStructuredRefreshToken(ctx context.Context, sm *SecretManager, token RefreshToken) error {
	parts := strings.Split(string(token), ".")
	if len(parts) != 4 {
		return ErrTokenFormatInvalid
	}

	// 1. 验证签名 (CPU 操作，极快)
	payload := parts[0] + "." + parts[1] + "." + parts[2]
	providedSig, _ := base64.RawURLEncoding.DecodeString(parts[3])

	key, err := sm.GetVerificationKey(ctx, parts[0])
	if err != nil {
		return err
	}

	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(payload))
	expectedSig := mac.Sum(nil)

	if !hmac.Equal(providedSig, expectedSig) {
		return ErrTokenForged // 伪造的 Token，直接拒绝，不查库
	}

	// 2. 验证过期 (CPU 操作)
	metaJson, _ := base64.RawURLEncoding.DecodeString(parts[1])
	var meta struct {
		Exp int64 `json:"e"`
	}

	if err := sonic.Unmarshal(metaJson, &meta); err != nil {
		return err
	}

	if time.Now().Unix() > meta.Exp {
		return ErrTokenExpired // 已过期，直接拒绝，不查库
	}

	return nil // 通过初步检查，现在去查数据库看是否被撤销
}

type Code SecretString

// Hash 根据签名算法计算 Code 的哈希值
// 规范要求：Hash 算法必须匹配 ID Token 的签名算法
func (c Code) Hash(alg jwt.SigningMethod) (string, error) {
	return Hash(alg, string(c))
}

// Hash 根据签名算法计算字符串的哈希值
// OIDC 规范：使用 ID 令牌头部指定的哈希算法对令牌 ASCII 表示的字节进行哈希处理。取哈希值的左半部分并进行 base64url 编码。
func Hash(method jwt.SigningMethod, str string) (string, error) {
	var hasher hash.Hash

	// 根据签名算法选择 Hash 算法 (RFC 7518 Section 3)
	// EdDSA (Ed25519) 通常不指定具体的 Hash 算法用于 OIDC hash 计算，
	// 但 OIDC Core Errata 修正中通常建议使用 SHA-512 作为默认。
	switch method {
	case jwt.SigningMethodRS256, jwt.SigningMethodES256, jwt.SigningMethodPS256:
		hasher = sha256.New()
	case jwt.SigningMethodRS384, jwt.SigningMethodES384, jwt.SigningMethodPS384:
		hasher = sha512.New384()
	case jwt.SigningMethodRS512, jwt.SigningMethodES512, jwt.SigningMethodPS512:
		hasher = sha512.New()
	case jwt.SigningMethodEdDSA:
		hasher = sha512.New()
	default:
		return "", ErrUnsupportedAlgForHash
	}

	hasher.Write([]byte(str))
	hashBytes := hasher.Sum(nil)

	halfLen := len(hashBytes) / 2
	leftHalf := hashBytes[:halfLen]

	// Base64Url 编码
	return base64.RawURLEncoding.EncodeToString(leftHalf), nil
}
