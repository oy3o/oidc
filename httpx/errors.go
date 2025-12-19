package httpx

import (
	"errors"
	"net/http"

	"github.com/bytedance/sonic"
	"github.com/oy3o/httpx"
	"github.com/oy3o/oidc"
)

// httpx errors
var (
	ErrIdentityNotFound     = errors.New("identity not found in context")
	ErrIdentityTypeMismatch = errors.New("identity type mismatch")
)

// Error 按照 RFC 6749 格式写入错误响应
func Error(w http.ResponseWriter, r *http.Request, err error, opts ...httpx.ErrorOption) {
	w.Header().Set("Content-Type", "application/json")

	// 1. 尝试直接断言 *oidc.Error
	var oidcErr *oidc.Error
	if errors.As(err, &oidcErr) {
		w.WriteHeader(oidcErr.StatusCode)
		sonic.ConfigDefault.NewEncoder(w).Encode(oidcErr)
		return
	}

	// 2. 尝试映射 Sentinel Errors
	if mappedErr := mapSentinelToError(err); mappedErr != nil {
		w.WriteHeader(mappedErr.StatusCode)
		sonic.ConfigDefault.NewEncoder(w).Encode(mappedErr)
		return
	}

	// 3. 默认 500
	w.WriteHeader(http.StatusInternalServerError)
	sonic.ConfigDefault.NewEncoder(w).Encode(&oidc.Error{
		Code:        "server_error",
		Description: err.Error(),
	})
}

// mapSentinelToError 将预定义的 error 变量转换为 *oidc.Error 结构
func mapSentinelToError(err error) *oidc.Error {
	switch {
	case errors.Is(err, oidc.ErrInvalidRequest):
		return oidc.InvalidRequestError(err.Error())
	case errors.Is(err, oidc.ErrInvalidClient):
		return oidc.InvalidClientError("client authentication failed")
	case errors.Is(err, oidc.ErrInvalidGrant):
		return oidc.InvalidGrantError("invalid grant")
	case errors.Is(err, oidc.ErrUnauthorizedClient):
		return oidc.UnauthorizedClientError("unauthorized client")
	case errors.Is(err, oidc.ErrUnsupportedGrantType):
		return oidc.UnsupportedGrantTypeError("unsupported grant type")
	case errors.Is(err, oidc.ErrInvalidScope):
		return oidc.InvalidScopeError("invalid scope")
	case errors.Is(err, oidc.ErrAccessDenied):
		return oidc.AccessDeniedError("access denied")
	case errors.Is(err, oidc.ErrAuthorizationPending):
		return oidc.AuthorizationPendingError("authorization pending")
	case errors.Is(err, oidc.ErrSlowDown):
		return oidc.SlowDownError("slow down")
	case errors.Is(err, oidc.ErrExpiredToken):
		return oidc.ExpiredTokenError("token expired")
	}
	return nil
}
