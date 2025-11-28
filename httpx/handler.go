package httpx

import (
	"errors"
	"net/http"

	"github.com/bytedance/sonic"

	"github.com/oy3o/httpx"
	"github.com/oy3o/oidc"
)

// TokenHandler 封装 OIDC Token Endpoint (/token)。
func TokenHandler(s *oidc.Server) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// RFC 6749 Section 5.1: Cache-Control: no-store
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Pragma", "no-cache")
		w.Header().Set("Content-Type", "application/json;charset=UTF-8")

		var req oidc.TokenRequest
		// 注意：httpx.Bind 可能会返回校验错误，这里统一包装为 invalid_request
		if err := httpx.Bind(r, &req); err != nil {
			Error(w, oidc.InvalidRequestError("failed to parse request: "+err.Error()))
			return
		}

		resp, err := s.Exchange(r.Context(), &req)
		if err != nil {
			Error(w, err)
			return
		}

		w.WriteHeader(http.StatusOK)
		sonic.ConfigDefault.NewEncoder(w).Encode(resp)
	}
}

// DiscoveryHandler 封装 OIDC Discovery Endpoint
// GET /.well-known/openid-configuration
// 必须允许 CORS
func DiscoveryHandler(s *oidc.Server) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// 允许跨域，以便前端应用读取配置
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Content-Type", "application/json;charset=UTF-8")
		w.Header().Set("Cache-Control", "public, max-age=3600")
		sonic.ConfigDefault.NewEncoder(w).Encode(s.Discovery())
	}
}

// JWKSHandler 封装 JWK Set Endpoint
// GET /jwks.json
// 必须允许 CORS
func JWKSHandler(s *oidc.Server) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Content-Type", "application/json;charset=UTF-8")
		w.Header().Set("Cache-Control", "public, max-age=3600")

		jwks, err := s.KeyManager().ExportJWKS(r.Context())
		if err != nil {
			http.Error(w, "internal server error", http.StatusInternalServerError)
			return
		}
		sonic.ConfigDefault.NewEncoder(w).Encode(jwks)
	}
}

// UserInfoHandler 封装 OIDC UserInfo Endpoint
func UserInfoHandler(s *oidc.Server) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json;charset=UTF-8")

		claims, err := GetClaims(r.Context())
		if err != nil {
			Error(w, oidc.AccessDeniedError("missing or invalid token"))
			return
		}

		info, err := s.GetUserInfo(r.Context(), claims)
		if err != nil {
			Error(w, err)
			return
		}

		w.WriteHeader(http.StatusOK)
		sonic.ConfigDefault.NewEncoder(w).Encode(info)
	}
}

// RevocationHandler 封装 /revoke
func RevocationHandler(s *oidc.Server) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req oidc.RevocationRequest
		if err := httpx.Bind(r, &req); err != nil {
			Error(w, oidc.InvalidRequestError(err.Error()))
			return
		}
		if err := s.RevokeToken(r.Context(), &req); err != nil {
			Error(w, err)
			return
		}
		w.WriteHeader(http.StatusOK)
	}
}

// IntrospectionHandler 封装 Token Introspection Endpoint (/introspect)
// RFC 7662: OAuth 2.0 Token Introspection
func IntrospectionHandler(s *oidc.Server) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Pragma", "no-cache")
		w.Header().Set("Content-Type", "application/json;charset=UTF-8")

		if err := r.ParseForm(); err != nil {
			Error(w, oidc.InvalidRequestError("failed to parse parameters"))
			return
		}

		token := r.Form.Get("token")
		if token == "" {
			Error(w, oidc.InvalidRequestError("missing token parameter"))
			return
		}

		clientID, clientSecret, ok := r.BasicAuth()
		if !ok {
			clientID = r.Form.Get("client_id")
			clientSecret = r.Form.Get("client_secret")
		}

		resp, err := s.Introspect(r.Context(), token, clientID, clientSecret)
		if err != nil {
			Error(w, err)
			return
		}

		w.WriteHeader(http.StatusOK)
		sonic.ConfigDefault.NewEncoder(w).Encode(resp)
	}
}

// PARHandler 封装 /par
func PARHandler(s *oidc.Server) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Pragma", "no-cache")
		w.Header().Set("Content-Type", "application/json;charset=UTF-8")

		var req oidc.PARRequest
		if err := httpx.Bind(r, &req); err != nil {
			Error(w, oidc.InvalidRequestError(err.Error()))
			return
		}

		resp, err := s.PushedAuthorization(r.Context(), &req)
		if err != nil {
			Error(w, err)
			return
		}

		w.WriteHeader(http.StatusCreated)
		sonic.ConfigDefault.NewEncoder(w).Encode(resp)
	}
}

// DeviceAuthorizationHandler 封装 /device/authorize
func DeviceAuthorizationHandler(s *oidc.Server) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Type", "application/json;charset=UTF-8")

		var req oidc.DeviceAuthorizationRequest
		if err := httpx.Bind(r, &req); err != nil {
			Error(w, oidc.InvalidRequestError(err.Error()))
			return
		}

		resp, err := s.DeviceAuthorization(r.Context(), &req)
		if err != nil {
			Error(w, err)
			return
		}

		w.WriteHeader(http.StatusOK)
		sonic.ConfigDefault.NewEncoder(w).Encode(resp)
	}
}

// --- Helpers ---

// Error 按照 RFC 6749 格式写入错误响应
func Error(w http.ResponseWriter, err error) {
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
