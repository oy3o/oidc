package oidc

import "errors"

// Error 代表一个标准的 OAuth2 错误
type Error struct {
	Code        string `json:"error"`             // e.g. "invalid_request"
	Description string `json:"error_description"` // e.g. "Missing client_id"
	StatusCode  int    `json:"-"`                 // HTTP 状态码 (仅用于 Token 端点)
}

// Error 实现 error 接口
func (e *Error) Error() string {
	if e.Description != "" {
		return e.Code + ": " + e.Description
	}
	return e.Code
}

// NewError 创建一个新的 OAuth2 错误
func NewError(code string, description string, statusCode int) *Error {
	return &Error{
		Code:        code,
		Description: description,
		StatusCode:  statusCode,
	}
}

// HTTPStatus 实现 httpx.ErrorCoder 接口 (隐式)
func (e *Error) HTTPStatus() int {
	return e.StatusCode
}

// BizStatus 实现 httpx.BizCoder 接口 (隐式)
func (e *Error) BizStatus() string {
	return e.Code
}

// PublicMessage 实现 httpx.PublicError 接口 (隐式)
// OAuth2 错误（如 invalid_grant）需要返回给客户端以供调试或处理，因此视为 safe。
func (e *Error) PublicMessage() string {
	if e.Description != "" {
		return e.Code + ": " + e.Description
	}
	return e.Code
}

// ---------------------------------------------------------------------------
// 便捷的错误构造函数
// 这些函数简化了创建标准 OAuth2 错误的过程
// ---------------------------------------------------------------------------

// InvalidRequestError 创建 invalid_request 错误 (HTTP 400)
func InvalidRequestError(description string) *Error {
	return NewError("invalid_request", description, 400)
}

// InvalidClientError 创建 invalid_client 错误 (HTTP 401)
func InvalidClientError(description string) *Error {
	return NewError("invalid_client", description, 401)
}

// InvalidGrantError 创建 invalid_grant 错误 (HTTP 400)
func InvalidGrantError(description string) *Error {
	return NewError("invalid_grant", description, 400)
}

// UnauthorizedClientError 创建 unauthorized_client 错误 (HTTP 400)
func UnauthorizedClientError(description string) *Error {
	return NewError("unauthorized_client", description, 400)
}

// UnsupportedGrantTypeError 创建 unsupported_grant_type 错误 (HTTP 400)
func UnsupportedGrantTypeError(description string) *Error {
	return NewError("unsupported_grant_type", description, 400)
}

// InvalidScopeError 创建 invalid_scope 错误 (HTTP 400)
func InvalidScopeError(description string) *Error {
	return NewError("invalid_scope", description, 400)
}

// AccessDeniedError 创建 access_denied 错误 (HTTP 403)
func AccessDeniedError(description string) *Error {
	return NewError("access_denied", description, 403)
}

// ServerError 创建 server_error 错误 (HTTP 500)
func ServerErrorWithDescription(description string) *Error {
	return NewError("server_error", description, 500)
}

// TemporarilyUnavailableError 创建 temporarily_unavailable 错误 (HTTP 503)
func TemporarilyUnavailableError(description string) *Error {
	return NewError("temporarily_unavailable", description, 503)
}

// AuthorizationPendingError 创建 authorization_pending 错误 (HTTP 400)
// 用于 Device Flow
func AuthorizationPendingError(description string) *Error {
	return NewError("authorization_pending", description, 400)
}

// SlowDownError 创建 slow_down 错误 (HTTP 400)
// 用于 Device Flow
func SlowDownError(description string) *Error {
	return NewError("slow_down", description, 400)
}

// ExpiredTokenError 创建 expired_token 错误 (HTTP 400)
// 用于 Device Flow
func ExpiredTokenError(description string) *Error {
	return NewError("expired_token", description, 400)
}

// ServerError 创建 server_error 错误 (HTTP 500)
func ServerError(description string) *Error {
	return NewError("server_error", description, 500)
}

// ---------------------------------------------------------------------------
// OAuth 2.0 / OIDC 标准错误定义
// 参见: RFC 6749 Section 5.2 & OIDC Core 1.0
// ---------------------------------------------------------------------------

var (
	// ErrInvalidRequest 请求缺少必需的参数、包含无效的参数值、包含多个同名参数，或者格式不正确。
	ErrInvalidRequest = errors.New("invalid_request")

	// ErrInvalidClient 客户端认证失败（例如：未知的客户端、未包含客户端认证信息、不支持的认证方法）。
	ErrInvalidClient = errors.New("invalid_client")

	// ErrInvalidGrant 提供的授权许可（例如：授权码、资源所有者凭据）或刷新令牌无效、过期、已撤销、与重定向 URI 不匹配，或不属于该客户端。
	ErrInvalidGrant = errors.New("invalid_grant")

	// ErrUnauthorizedClient 经过认证的客户端无权使用此授权许可类型。
	ErrUnauthorizedClient = errors.New("unauthorized_client")

	// ErrUnsupportedGrantType 授权服务器不支持该授权许可类型。
	ErrUnsupportedGrantType = errors.New("unsupported_grant_type")

	// ErrInvalidScope 请求的范围无效、未知、格式不正确，或超出了资源所有者授予的范围。
	ErrInvalidScope = errors.New("invalid_scope")

	// ErrAccessDenied 资源所有者或授权服务器拒绝了请求。
	ErrAccessDenied = errors.New("access_denied")

	// ErrServerError 授权服务器遇到意外情况，无法完成请求。
	ErrServerError = errors.New("server_error")

	// ErrTemporarilyUnavailable 授权服务器目前因过载或维护而无法处理请求。
	ErrTemporarilyUnavailable = errors.New("temporarily_unavailable")
)

// ---------------------------------------------------------------------------
// Device Flow Errors (RFC 8628)
// ---------------------------------------------------------------------------

var (
	// ErrAuthorizationPending 设备授权请求待处理，客户端应继续轮询。
	ErrAuthorizationPending = errors.New("authorization_pending")

	// ErrSlowDown 客户端轮询过于频繁，应减慢轮询速率。
	ErrSlowDown = errors.New("slow_down")

	// ErrExpiredToken 设备码已过期。
	ErrExpiredToken = errors.New("expired_token")
)

// ---------------------------------------------------------------------------
// Token 验证错误
// 内部逻辑错误，通常不直接返回给前端，但用于内部控制流
// ---------------------------------------------------------------------------

var (
	ErrTokenExpired          = errors.New("token is expired")
	ErrTokenSignatureInvalid = errors.New("token signature is invalid")
	ErrInvalidIssuer         = errors.New("invalid issuer")
	ErrInvalidAudience       = errors.New("invalid audience")
	ErrInvalidNonce          = errors.New("invalid nonce")
	ErrNotFound              = errors.New("resource not found")
	ErrTokenFormatInvalid    = errors.New("token format is invalid")
	ErrTokenForged           = errors.New("token forged")
)

// ---------------------------------------------------------------------------
// Storage Errors
// 定义存储层可能返回的通用错误
// 业务层实现接口时，如果遇到"未找到"的情况，必须返回这些特定的 error，
// 以便 OIDC 逻辑层能区分"系统错误"和"逻辑未命中"。
// ---------------------------------------------------------------------------

var (
	ErrClientNotFound = errors.New("client not found")
	ErrTokenNotFound  = errors.New("token not found or expired")
	ErrCodeNotFound   = errors.New("authorization code not found or consumed")
	ErrUserNotFound   = errors.New("user not found")
)

// ---------------------------------------------------------------------------
// Key Manager Errors
// ---------------------------------------------------------------------------

var (
	// ErrKeyNil 密钥不能为 nil
	ErrKeyNil = errors.New("key cannot be nil")

	// ErrInvalidRSAKey 无效的 RSA 私钥
	ErrInvalidRSAKey = errors.New("invalid RSA private key")

	// ErrRSAKeyTooSmall RSA 私钥必须至少 2048 位
	ErrRSAKeyTooSmall = errors.New("RSA private key must be at least 2048 bits")

	// ErrInvalidEd25519KeySize 无效的 Ed25519 私钥大小
	ErrInvalidEd25519KeySize = errors.New("invalid Ed25519 private key size")

	// ErrNoSigningKey 未配置签名密钥
	ErrNoSigningKey = errors.New("no signing key configured")

	// ErrKeyNotFound 密钥未找到
	ErrKeyNotFound = errors.New("key not found")

	// ErrTokenRevoked 表示 Access Token 已被撤销 (例如用户登出或安全事件)
	ErrTokenRevoked = errors.New("token has been revoked")

	// ErrCannotRemoveSigningKey 不能删除当前的签名密钥
	ErrCannotRemoveSigningKey = errors.New("cannot remove current signing key")

	// ErrUnsupportedKeyType 不支持的密钥类型
	ErrUnsupportedKeyType = errors.New("unsupported key type")

	// ErrCircuitBreakerOpen 断路器打开
	ErrCircuitBreakerOpen = errors.New("remote JWKS unavailable (circuit breaker open)")

	// ErrKeyExpired 密钥已过期
	ErrKeyExpired = errors.New("key expired")

	// ErrNoActiveKey 未设置活跃密钥
	ErrNoActiveKey = errors.New("no active key set")

	// ErrKIDEmpty KID 不能为空
	ErrKIDEmpty = errors.New("kid cannot be empty")

	// ErrKeyTooShort 密钥长度不足
	ErrKeyTooShort = errors.New("key must be at least 32 bytes")

	// ErrCannotRemoveActiveKey 不能删除活跃密钥
	ErrCannotRemoveActiveKey = errors.New("cannot remove active key")

	// ErrUnsupportedECDSACurve 不支持的 ECDSA 曲线
	ErrUnsupportedECDSACurve = errors.New("unsupported ECDSA curve")

	// ErrUnsupportedPrivateKeyType 不支持的私钥类型
	ErrUnsupportedPrivateKeyType = errors.New("unsupported private key type")

	// ErrSigningKeyMissing 当前签名密钥丢失
	ErrSigningKeyMissing = errors.New("current signing key is missing")

	// ErrKeyInterfaceNotImplemented 存储的密钥未实现 Key 接口
	ErrKeyInterfaceNotImplemented = errors.New("stored key does not implement Key interface")

	// ErrNoActiveRefreshTokenKey 没有用于刷新令牌的活跃密钥
	ErrNoActiveRefreshTokenKey = errors.New("hmac key check failed: no active key for refresh tokens")

	// ErrSchedulerAlreadyStarted 调度器已启动
	ErrSchedulerAlreadyStarted = errors.New("scheduler already started")

	// ErrRotationInProgress 另一个实例正在进行轮换
	ErrRotationInProgress = errors.New("rotation already in progress by another instance")

	// ErrMemoryProviderOnly 操作仅支持 MemoryKeyProvider
	ErrMemoryProviderOnly = errors.New("operation only supported for MemoryKeyProvider")
)

// ---------------------------------------------------------------------------
// PKCE Errors
// ---------------------------------------------------------------------------

var (
	// ErrPKCEVerifierEmpty PKCE verifier 不能为空
	ErrPKCEVerifierEmpty = errors.New("pkce verifier cannot be empty")

	// ErrPKCEVerifierInvalidLength PKCE verifier 长度无效
	ErrPKCEVerifierInvalidLength = errors.New("invalid pkce verifier length")

	// ErrPKCEVerifierInvalidChars PKCE verifier 包含无效字符
	ErrPKCEVerifierInvalidChars = errors.New("invalid characters in pkce verifier")

	// ErrPKCEVerificationFailed PKCE 验证失败
	ErrPKCEVerificationFailed = errors.New("pkce verification failed")

	// ErrPKCERandomnessGenerationFailed PKCE 随机数生成失败
	ErrPKCERandomnessGenerationFailed = errors.New("failed to generate randomness for pkce")

	// ErrUnsupportedPKCEChallengeMethod 不支持的 PKCE challenge 方法
	ErrUnsupportedPKCEChallengeMethod = errors.New("unsupported pkce challenge method")
)

// ---------------------------------------------------------------------------
// PAR Errors
// ---------------------------------------------------------------------------

// ErrInvalidURNFormat 无效的 URN 格式
var ErrInvalidURNFormat = errors.New("invalid urn format")

// ---------------------------------------------------------------------------
// JWKS Errors
// ---------------------------------------------------------------------------

var (
	// ErrKeyNotEC 密钥不是 EC 类型
	ErrKeyNotEC = errors.New("key is not EC")

	// ErrKeyNotRSA 密钥不是 RSA 类型
	ErrKeyNotRSA = errors.New("key is not RSA")

	// ErrKeyNotEd25519 密钥不是 Ed25519 类型
	ErrKeyNotEd25519 = errors.New("key is not Ed25519")

	// ErrInvalidEd25519PublicKeySize 无效的 Ed25519 公钥大小
	ErrInvalidEd25519PublicKeySize = errors.New("invalid Ed25519 public key size")

	// ErrInvalidJWKType 无效的 JWK 类型
	ErrInvalidJWKType = errors.New("invalid JWK type")

	// ErrMissingJWKFields 缺少 JWK 字段
	ErrMissingJWKFields = errors.New("missing JWK fields")

	// ErrUnsupportedJWKPublicKeyType 不支持的 JWK 公钥类型
	ErrUnsupportedJWKPublicKeyType = errors.New("jwks: unsupported key type")

	// ErrUnsupportedKtyForThumbprint 不支持的 kty 用于指纹计算
	ErrUnsupportedKtyForThumbprint = errors.New("unsupported kty for thumbprint")

	// ErrUnsupportedCurve 不支持的曲线
	ErrUnsupportedCurve = errors.New("jwks: unsupported curve")
)

// ---------------------------------------------------------------------------
// Issuer Errors
// ---------------------------------------------------------------------------

var (
	// ErrIssuerEmpty 发行者不能为空
	ErrIssuerEmpty = errors.New("issuer cannot be empty")

	// ErrInvalidIssuerURL 发行者必须是有效的 URL
	ErrInvalidIssuerURL = errors.New("issuer must be a valid URL")

	// ErrInvalidTTL Token TTL 必须大于 0
	ErrInvalidTTL = errors.New("token TTL must be greater than 0")

	// ErrKeyManagerNil KeyManager 不能为 nil
	ErrKeyManagerNil = errors.New("keyManager cannot be nil")

	// ErrSecretManagerNil SecretManager 不能为 nil
	ErrSecretManagerNil = errors.New("secretManager cannot be nil")

	// ErrFailedToGenerateUUID 生成 UUID 失败
	ErrFailedToGenerateUUID = errors.New("failed to generate UUIDv7")

	// ErrUnsupportedSigningKeyType 不支持的签名密钥类型
	ErrUnsupportedSigningKeyType = errors.New("unsupported signing key type")

	// ErrUnsupportedAlgForHash 不支持的哈希计算算法
	ErrUnsupportedAlgForHash = errors.New("unsupported alg for hash calculation")
)

// ---------------------------------------------------------------------------
// Database / Serialization Errors (Index Types)
// ---------------------------------------------------------------------------

var (
	// ErrHash256InvalidLength Hash256 必须为 32 字节
	ErrHash256InvalidLength = errors.New("Hash256 must be exactly 32 bytes")

	// ErrHash256ScanInvalidLength 扫描失败: Hash256 应为 32 字节
	ErrHash256ScanInvalidLength = errors.New("scan failed: expected 32 bytes for Hash256")

	// ErrHash256UnsupportedType 扫描失败: Hash256 不支持的类型
	ErrHash256UnsupportedType = errors.New("scan failed: unsupported type for Hash256")

	// ErrInvalidHexStringLength 无效的十六进制字符串长度
	ErrInvalidHexStringLength = errors.New("invalid hex string length")

	// ErrBinaryUUIDUnsupportedType BinaryUUID 无法扫描的类型
	ErrBinaryUUIDUnsupportedType = errors.New("BinaryUUID: cannot scan type")
)

// ---------------------------------------------------------------------------
// Business Flow Errors
// ---------------------------------------------------------------------------

var (
	// ErrUserIDRequired 生成授权码需要 user_id
	ErrUserIDRequired = errors.New("user_id is required to generate authorization code")

	// ErrTokenIsInvalid Token 无效
	ErrTokenIsInvalid = errors.New("token is invalid")

	// ErrExpClaimRequired exp 声明是必需的
	ErrExpClaimRequired = errors.New("exp claim is required")

	// ErrAZPRequired 当存在多个受众时需要 azp 声明
	ErrAZPRequired = errors.New("azp claim is required when multiple audiences are present")

	// ErrAZPMismatch azp 与 client_id 不匹配
	ErrAZPMismatch = errors.New("azp does not match client_id")

	// ErrAZPRequiredForTrust 受信任的客户端验证需要 azp 声明
	ErrAZPRequiredForTrust = errors.New("azp claim is required for trusted client validation")

	// ErrAZPNotAuthorized azp 未被授权访问资源
	ErrAZPNotAuthorized = errors.New("azp is not authorized to access resource")

	// ErrUnexpectedSigningMethod 意外的签名方法
	ErrUnexpectedSigningMethod = errors.New("unexpected signing method")

	// ErrHasherNotConfigured Hasher 未配置
	ErrHasherNotConfigured = errors.New("hasher not configured")

	// ErrInvalidIdentifier 无效的标识符
	ErrInvalidIdentifier = errors.New("invalid identifier")

	// ErrUserNotConfirmed 用户未确认
	ErrUserNotConfirmed = errors.New("user not confirmed")

	// ErrUserForbidden 用户被禁用
	ErrUserForbidden = errors.New("user forbidden")

	// ErrDefaultPassword 使用默认密码
	ErrDefaultPassword = errors.New("default password")

	// ErrIssuerURLRequired issuer URL 是必需的
	ErrIssuerURLRequired = errors.New("issuer url is required")

	// ErrStorageRequired storage 实现是必需的
	ErrStorageRequired = errors.New("storage implementation is required")

	// ErrHasherRequired hasher 实现是必需的
	ErrHasherRequired = errors.New("hasher implementation is required")

	// ErrSecretHasherRequired 机密客户端需要 secret hasher
	ErrSecretHasherRequired = errors.New("secret hasher is required for confidential clients")

	// ErrEnvTokenSecretRequired 环境变量 OIDC_TOKEN_SECRET 是必需的
	ErrEnvTokenSecretRequired = errors.New("env OIDC_TOKEN_SECRET is required")
)

// ---------------------------------------------------------------------------
// Client SDK Errors
// ---------------------------------------------------------------------------

var (
	// ErrPARNotSupported 服务器不支持 PAR
	ErrPARNotSupported = errors.New("server does not support PAR")

	// ErrDeviceFlowNotSupported 服务器不支持设备流
	ErrDeviceFlowNotSupported = errors.New("server does not support device flow")

	// ErrRevocationNotSupported 服务器不支持撤销
	ErrRevocationNotSupported = errors.New("server does not support revocation")

	// ErrIntrospectionNotSupported 服务器不支持内省
	ErrIntrospectionNotSupported = errors.New("server does not support introspection")

	// ErrNonceMismatch nonce 不匹配
	ErrNonceMismatch = errors.New("nonce mismatch")

	// ErrUnparseableError 请求失败且错误无法解析
	ErrUnparseableError = errors.New("request failed with unparseable error")
)
