package httpx

import (
	"context"
	"net/http"

	"github.com/oy3o/httpx"
	"github.com/oy3o/oidc"
)

// TokenHandler [POST] /token
// RFC 6749: Token Endpoint
func TokenHandler(s *oidc.Server) http.HandlerFunc {
	return httpx.NewResponder(func(ctx context.Context, req *oidc.TokenRequest) (*OidcResponse, error) {
		resp, err := s.Exchange(ctx, req)
		if err != nil {
			return nil, err
		}

		return &OidcResponse{
			Data:    resp,
			NoCache: true, // 必须 No-Store
		}, nil
	}, httpx.AddBinders(&httpx.ClientAuthBinder{}), httpx.WithErrorFunc(Error))
}

// DiscoveryHandler [GET] /.well-known/openid-configuration
// OIDC Discovery
func DiscoveryHandler(s *oidc.Server) http.HandlerFunc {
	// struct{} 表示无需绑定任何参数
	return httpx.NewResponder(func(ctx context.Context, _ *struct{}) (*OidcResponse, error) {
		return &OidcResponse{
			Data: s.Discovery(),
			Cors: true, // 必须允许跨域
		}, nil
	})
}

// JWKSHandler [GET] /.well-known/jwks.json
// OIDC Key Set
func JWKSHandler(s *oidc.Server) http.HandlerFunc {
	return httpx.NewResponder(func(ctx context.Context, _ *struct{}) (*OidcResponse, error) {
		jwks, err := s.KeyManager().ExportJWKS(ctx)
		if err != nil {
			return nil, err
		}
		return &OidcResponse{
			Data: jwks,
			Cors: true, // 必须允许跨域
		}, nil
	}, httpx.WithErrorFunc(Error))
}

// UserInfoHandler [GET/POST] /userinfo
// OIDC UserInfo
func UserInfoHandler(s *oidc.Server) http.HandlerFunc {
	return httpx.NewResponder(func(ctx context.Context, _ *struct{}) (*OidcResponse, error) {
		// 1. 获取 Token Claims (依赖前置 Middleware 解析 Bearer Token)
		claims, err := GetClaims(ctx)
		if err != nil {
			// 返回 standard error，由 httpx ErrorHook 转换为 JSON 格式
			return nil, oidc.AccessDeniedError("missing or invalid token")
		}

		// 2. 获取用户信息
		info, err := s.GetUserInfo(ctx, claims)
		if err != nil {
			return nil, err
		}

		return &OidcResponse{
			Data: info,
			// UserInfo 响应不应被公开缓存，但通常也不强制 No-Store，视具体需求而定
			NoCache: true,
		}, nil
	}, httpx.WithErrorFunc(Error))
}

// RevocationHandler [POST] /revoke
// RFC 7009: Token Revocation
func RevocationHandler(s *oidc.Server) http.HandlerFunc {
	return httpx.NewResponder(func(ctx context.Context, req *oidc.RevocationRequest) (*OidcResponse, error) {
		if err := s.RevokeToken(ctx, req); err != nil {
			return nil, err
		}
		// 成功返回 200 OK 且无 Body
		return &OidcResponse{
			Status: http.StatusOK,
		}, nil
	}, httpx.AddBinders(&httpx.ClientAuthBinder{}), httpx.WithErrorFunc(Error))
}

// IntrospectionHandler [POST] /introspect
// RFC 7662: Token Introspection
func IntrospectionHandler(s *oidc.Server) http.HandlerFunc {
	return httpx.NewResponder(func(ctx context.Context, req *oidc.IntrospectionRequest) (*OidcResponse, error) {
		if req.Token == "" {
			return nil, oidc.InvalidRequestError("missing token parameter")
		}

		resp, err := s.Introspect(ctx, req.Token, req.ClientID, req.ClientSecret)
		if err != nil {
			return nil, err
		}

		return &OidcResponse{
			Data:    resp,
			NoCache: true, // RFC 7662 建议
		}, nil
	}, httpx.AddBinders(&httpx.ClientAuthBinder{}), httpx.WithErrorFunc(Error))
}

// PARHandler [POST] /par
// RFC 9126: Pushed Authorization Requests
func PARHandler(s *oidc.Server) http.HandlerFunc {
	return httpx.NewResponder(func(ctx context.Context, req *oidc.PARRequest) (*OidcResponse, error) {
		resp, err := s.PushedAuthorization(ctx, req)
		if err != nil {
			return nil, err
		}

		return &OidcResponse{
			Status:  http.StatusCreated, // 201 Created
			Data:    resp,
			NoCache: true,
		}, nil
	}, httpx.AddBinders(&httpx.ClientAuthBinder{}), httpx.WithErrorFunc(Error))
}

// DeviceAuthorizationHandler [POST] /device/authorize
// RFC 8628: Device Authorization Grant
func DeviceAuthorizationHandler(s *oidc.Server) http.HandlerFunc {
	return httpx.NewResponder(func(ctx context.Context, req *oidc.DeviceAuthorizationRequest) (*OidcResponse, error) {
		resp, err := s.DeviceAuthorization(ctx, req)
		if err != nil {
			return nil, err
		}

		return &OidcResponse{
			Data:    resp,
			NoCache: true,
		}, nil
	}, httpx.AddBinders(&httpx.ClientAuthBinder{}), httpx.WithErrorFunc(Error))
}
