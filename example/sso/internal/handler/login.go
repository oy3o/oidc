package handler

import (
	"html/template"
	"net/http"
	"time"

	"sso/internal/domain"

	"github.com/oy3o/httpx"
	"github.com/oy3o/oidc"
	odic_gorm "github.com/oy3o/oidc/gorm"
	odic_httpx "github.com/oy3o/oidc/httpx"
)

type LoginHandler struct {
	oidcServer *oidc.Server
	userRepo   domain.UserRepository
	hasher     oidc.Hasher
}

func NewLoginHandler(server *oidc.Server, userRepo domain.UserRepository, hasher oidc.Hasher) *LoginHandler {
	return &LoginHandler{
		oidcServer: server,
		userRepo:   userRepo,
		hasher:     hasher,
	}
}

// ServeAuthorize 处理 GET /authorize
// 1. 验证 OIDC 请求参数
// 2. 检查用户 Session (SSO 核心)
// 3. 如果未登录，渲染登录页
// 4. 如果已登录，直接跳过登录页进入 ResponseAuthorized
func (h *LoginHandler) ServeAuthorize(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// 1. 解析并验证 OIDC 参数
	// 这一步会检查 client_id, redirect_uri, scope 等是否合法
	var req oidc.AuthorizeRequest
	if err := httpx.Bind(r, &req); err != nil {
		odic_httpx.Error(w, oidc.InvalidRequestError(err.Error()))
		return
	}

	client, err := h.oidcServer.RequestAuthorize(ctx, &req)
	if err != nil {
		odic_httpx.Error(w, err)
		return
	}

	// 2. 检查 Session (这里简化为检查 Cookie，生产环境应使用 Redis Session)
	userID, loggedIn := h.checkSession(r)

	// 3. 如果未登录，渲染登录页面
	if !loggedIn {
		h.renderLoginPage(w, r, client, &req)
		return
	}

	// 4. 如果已登录，执行授权响应 (生成 Auth Code 并重定向)
	// 注入已登录的用户 ID
	req.UserID = userID
	req.AuthTime = time.Now() // 实际应从 Session 获取登录时间

	redirectURL, err := h.oidcServer.ResponseAuthorized(ctx, &req)
	if err != nil {
		odic_httpx.Error(w, err)
		return
	}

	http.Redirect(w, r, redirectURL, http.StatusFound)
}

// HandleLogin 处理 POST /login 提交
func (h *LoginHandler) HandleLogin(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}

	username := r.FormValue("username")
	password := r.FormValue("password")

	// 恢复 OIDC 上下文参数 (从隐藏域或 URL Query)
	var authReq oidc.AuthorizeRequest
	if err := httpx.Bind(r, &authReq); err != nil {
		http.Error(w, "missing auth parameters", http.StatusBadRequest)
		return
	}

	// 1. 验证用户名密码
	// 注意：这里我们使用 OIDC 库的 UserAuthenticator 接口，也可以直接用 userRepo
	userID, err := h.userRepo.GetUser(ctx, username, password)
	if err != nil {
		// 登录失败，重新渲染页面并显示错误
		h.renderLoginPage(w, r, nil, &authReq) // client 可传 nil 或重新获取
		return
	}

	// 2. 设置 Session Cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "sso_session",
		Value:    userID.String(),
		Path:     "/",
		HttpOnly: true,
		Secure:   r.TLS != nil,
		Expires:  time.Now().Add(24 * time.Hour),
	})

	// 3. 完成 OIDC 流程
	authReq.UserID = userID.String()
	authReq.AuthTime = time.Now()

	redirectURL, err := h.oidcServer.ResponseAuthorized(ctx, &authReq)
	if err != nil {
		odic_httpx.Error(w, err)
		return
	}

	http.Redirect(w, r, redirectURL, http.StatusFound)
}

// checkSession 简易 Session 检查
func (h *LoginHandler) checkSession(r *http.Request) (string, bool) {
	c, err := r.Cookie("sso_session")
	if err != nil || c.Value == "" {
		return "", false
	}
	// TODO: 生产环境必须验证 Session 签名或从 Redis 查找
	return c.Value, true
}

// renderLoginPage 渲染简单的 HTML
func (h *LoginHandler) renderLoginPage(w http.ResponseWriter, r *http.Request, client oidc.RegisteredClient, req *oidc.AuthorizeRequest) {
	tmpl := `
<!DOCTYPE html>
<html>
<head>
    <title>Login - SSO</title>
    <style>
        body { font-family: sans-serif; display: flex; justify-content: center; align-items: center; height: 100vh; background: #f0f2f5; }
        .card { background: white; padding: 2rem; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); width: 100%; max-width: 400px; }
        input { width: 100%; padding: 10px; margin: 10px 0; border: 1px solid #ddd; border-radius: 4px; box-sizing: border-box; }
        button { width: 100%; padding: 10px; background: #0070f3; color: white; border: none; border-radius: 4px; cursor: pointer; }
        button:hover { background: #0051a2; }
    </style>
</head>
<body>
    <div class="card">
        <h2>Login to {{.ClientName}}</h2>
        <form method="POST" action="/login?{{.Query}}">
            <input type="text" name="username" placeholder="Username" required autofocus>
            <input type="password" name="password" placeholder="Password" required>
            <button type="submit">Sign In</button>
        </form>
    </div>
</body>
</html>`

	t, _ := template.New("login").Parse(tmpl)

	clientName := "Unknown Client"
	if client != nil {
		// 这里假设 RegisteredClient 有 GetName() 方法，或者通过断言
		if c, ok := client.(*odic_gorm.ClientModel); ok { // 假设 db 包有扩展
			clientName = c.Name
		} else {
			// fallback check interface
			// 实际项目中 RegisteredClient 接口应该包含 GetName
			clientName = "App"
		}
	}

	data := struct {
		ClientName string
		Query      string
	}{
		ClientName: clientName,
		Query:      r.URL.RawQuery, // 保留原始 OIDC 参数
	}

	w.Header().Set("Content-Type", "text/html")
	t.Execute(w, data)
}
