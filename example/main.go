// Package main demonstrates how to integrate OIDC with DPoP and PAR support
// using the httpx and appx frameworks.
package main

import (
	"fmt"
	"net/http"

	"github.com/oy3o/oidc"
	// "github.com/oy3o/httpx" // 假设已导入
	// "github.com/oy3o/appx" // 假设已导入
)

// 示例：如何集成 OIDC Server 和 HTTP 路由

func setupOIDCServer() (*oidc.Server, oidc.Storage, error) {
	// 1. 初始化存储（GORM + Redis）
	// db := ... // 初始化 GORM DB
	// hasher := ... // 初始化 Hasher
	// storage := gorm.NewGormStorage(db, hasher)

	// redisClient := redis.NewClient(&redis.Options{
	// 	Addr: "localhost:6379",
	// })
	// replayCache := redis.NewRedisStorage(redisClient)

	// 2. 初始化 OIDC Server
	// cfg := oidc.ServerConfig{
	// 	Issuer:  "https://auth.example.com",
	// 	Storage: storage,
	// 	Hasher:  hasher,
	// }
	// server, err := oidc.NewServer(cfg)
	// if err != nil {
	// 	return nil, nil, err
	// }

	// 3. 添加签名密钥
	// server.KeyManager().Add(oidc.KeyEntry{
	// 	ID:         "key-1",
	// 	PrivateKey: privateKey,
	// 	Algorithm:  "RS256",
	// })

	// return server, storage, nil
	return nil, nil, nil // placeholder
}

func setupHTTPRoutes(mux *http.ServeMux, server *oidc.Server, storage oidc.Storage) {
	// 获取 ReplayCache (假设 storage 也实现了 ReplayCache)
	_, ok := storage.(oidc.ReplayCache)
	if !ok {
		panic("storage does not implement ReplayCache")
	}

	// =========================================================================
	// PAR 端点 (RFC 9126)
	// =========================================================================
	// POST /par - 推送授权请求
	// 客户端认证是必需的（通过 Basic Auth 或 client_secret）
	// mux.HandleFunc("POST /par", httpx.NewHandler(
	// 	oidc.HandlePAR(server),
	// 	httpx.WithNoEnvelope(), // PAR 响应不使用 envelope
	// ))

	// =========================================================================
	// Token 端点 - 可选 DPoP 支持
	// =========================================================================
	// POST /token - 令牌交换端点
	// 使用可选的 DPoP 中间件：如果提供了 DPoP header 则验证
	// mux.Handle("POST /token", oidc.DPoPOptionalMiddleware(replayCache)(
	// 	httpx.NewHandler(
	// 		oidc.HandleToken(server),
	// 		httpx.WithNoEnvelope(),
	// 	),
	// ))

	// =========================================================================
	// Token 端点 - 必需 DPoP 支持 (更安全)
	// =========================================================================
	// 如果您想强制所有 token 请求都使用 DPoP，使用 Required 模式
	// mux.Handle("POST /token", oidc.DPoPRequiredMiddleware(replayCache)(
	// 	httpx.NewHandler(
	// 		oidc.HandleToken(server),
	// 		httpx.WithNoEnvelope(),
	// 	),
	// ))

	// =========================================================================
	// UserInfo 端点 - DPoP 保护
	// =========================================================================
	// GET /userinfo - 用户信息端点
	// DPoP 绑定的 Access Token 需要提供 DPoP proof
	// mux.Handle("GET /userinfo", oidc.DPoPOptionalMiddleware(replayCache)(
	// 	http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	// 		ctx := r.Context()
	//
	// 		// 提取 Bearer Token
	// 		tokenStr := extractBearerToken(r)
	// 		if tokenStr == "" {
	// 			http.Error(w, "missing token", http.StatusUnauthorized)
	// 			return
	// 		}
	//
	// 		// 获取用户信息
	// 		userInfo, err := server.GetUserInfo(ctx, tokenStr)
	// 		if err != nil {
	// 			http.Error(w, err.Error(), http.StatusUnauthorized)
	// 			return
	// 		}
	//
	// 		// 返回 JSON
	// 		json.NewEncoder(w).Encode(userInfo)
	// 	}),
	// ))

	// =========================================================================
	// Authorize 端点 - 支持 PAR request_uri
	// =========================================================================
	// GET /authorize - 授权端点
	// 支持标准参数和 PAR 的 request_uri
	// mux.HandleFunc("GET /authorize", func(w http.ResponseWriter, r *http.Request) {
	// 	ctx := r.Context()
	//
	// 	// 1. 解析请求参数
	// 	req := &oidc.AuthorizeHandlerRequest{
	// 		ClientID:            r.URL.Query().Get("client_id"),
	// 		RedirectURI:         r.URL.Query().Get("redirect_uri"),
	// 		ResponseType:        r.URL.Query().Get("response_type"),
	// 		Scope:               r.URL.Query().Get("scope"),
	// 		State:               r.URL.Query().Get("state"),
	// 		Nonce:               r.URL.Query().Get("nonce"),
	// 		CodeChallenge:       r.URL.Query().Get("code_challenge"),
	// 		CodeChallengeMethod: r.URL.Query().Get("code_challenge_method"),
	// 		RequestURI:          r.URL.Query().Get("request_uri"), // PAR
	// 	}
	//
	// 	// 2. 验证授权请求（如果有 request_uri，会自动加载）
	// 	authorizeReq := req.ToAuthorizeRequest()
	// 	client, err := server.RequestAuthorize(ctx, authorizeReq)
	// 	if err != nil {
	// 		http.Error(w, err.Error(), http.StatusBadRequest)
	// 		return
	// 	}
	//
	// 	// 3. 显示登录页面或同意页面
	// 	// ... (业务逻辑)
	//
	// 	// 4. 用户同意后，生成授权码
	// 	authorizeReq.UserID = "user-123" // 从会话获取
	// 	authorizeReq.AuthTime = time.Now()
	//
	// 	redirectURL, err := server.ResponseAuthorized(ctx, authorizeReq)
	// 	if err != nil {
	// 		http.Error(w, err.Error(), http.StatusInternalServerError)
	// 		return
	// 	}
	//
	// 	// 5. 重定向到客户端
	// 	http.Redirect(w, r, redirectURL, http.StatusFound)
	// })
}

// 辅助函数：从 Authorization header 提取 Bearer Token
func extractBearerToken(r *http.Request) string {
	auth := r.Header.Get("Authorization")
	if len(auth) > 7 && auth[:7] == "Bearer " {
		return auth[7:]
	}
	return ""
}

// =========================================================================
// DPoP 使用示例 (客户端视角)
// =========================================================================

func exampleDPoPClient() {
	// 1. 客户端生成密钥对
	// privateKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	// 2. 构造 DPoP Proof JWT
	// header: {"typ": "dpop+jwt", "alg": "ES256", "jwk": {...}}
	// payload: {"jti": "unique-id", "htm": "POST", "htu": "https://example.com/token", "iat": 1234567890}

	// 3. 发送请求
	// req, _ := http.NewRequest("POST", "https://example.com/token", body)
	// req.Header.Set("DPoP", dpopProof)
	// req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	// 4. 接收响应（包含 DPoP 绑定的 Access Token）
	// {"access_token": "...", "token_type": "DPoP", ...}

	// 5. 使用 Access Token 访问资源（需要再次提供 DPoP proof）
	// req2, _ := http.NewRequest("GET", "https://example.com/userinfo", nil)
	// req2.Header.Set("Authorization", "DPoP "+accessToken)
	// req2.Header.Set("DPoP", newDPoPProof) // 新的 proof，jti 不同
}

// =========================================================================
// PAR 使用示例 (客户端视角)
// =========================================================================

func examplePARClient() {
	// 1. 推送授权请求到 /par 端点
	// POST /par
	// Authorization: Basic <client-credentials>
	// Content-Type: application/x-www-form-urlencoded
	//
	// response_type=code&client_id=...&redirect_uri=...&scope=openid

	// 2. 接收 request_uri
	// {"request_uri": "urn:ietf:params:oauth:request_uri:6esc_11acc5bpkm888", "expires_in": 60}

	// 3. 使用 request_uri 发起授权
	// GET /authorize?request_uri=urn:ietf:params:oauth:request_uri:6esc_11acc5bpkm888&client_id=...

	// 4. 用户同意后获取授权码（标准流程）
}

func main() {
	fmt.Println("OIDC Integration Example")
	fmt.Println("See source code for detailed examples")

	// Uncomment to run
	// server, storage, err := setupOIDCServer()
	// if err != nil {
	// 	panic(err)
	// }
	//
	// mux := http.NewServeMux()
	// setupHTTPRoutes(mux, server, storage)
	//
	// http.ListenAndServe(":8080", mux)
}
