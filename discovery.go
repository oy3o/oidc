package oidc

import (
	"context"
	"crypto"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/oy3o/o11y"
	"github.com/oy3o/singleflight"
	"github.com/puzpuzpuz/xsync/v4"
)

const (
	// Response Types
	ResponseTypeCode = "code"

	// Grant Types
	GrantTypeAuthorizationCode = "authorization_code"
	GrantTypeRefreshToken      = "refresh_token"
	GrantTypeClientCredentials = "client_credentials"
	GrantTypePassword          = "password"
	GrantTypeDeviceCode        = "urn:ietf:params:oauth:grant-type:device_code"

	// Subject Types
	SubjectTypePublic = "public"

	// Auth Methods
	AuthMethodClientSecretBasic = "client_secret_basic"
	AuthMethodClientSecretPost  = "client_secret_post"

	// Scopes
	ScopeOpenID        = "openid"
	ScopeProfile       = "profile"
	ScopeEmail         = "email"
	ScopePhone         = "phone"
	ScopeOfflineAccess = "offline_access"
)

// Discovery 定义了完整的 OpenID Provider 元数据
// 参见: RFC 8414, OIDC Discovery 1.0
type Discovery struct {
	Issuer                             string `json:"issuer"`
	AuthorizationEndpoint              string `json:"authorization_endpoint"`
	TokenEndpoint                      string `json:"token_endpoint"`
	JWKSURI                            string `json:"jwks_uri"`
	UserInfoEndpoint                   string `json:"userinfo_endpoint,omitempty"`
	RevocationEndpoint                 string `json:"revocation_endpoint,omitempty"`
	IntrospectionEndpoint              string `json:"introspection_endpoint,omitempty"`
	EndSessionEndpoint                 string `json:"end_session_endpoint,omitempty"`
	RegistrationEndpoint               string `json:"registration_endpoint,omitempty"`
	DeviceAuthorizationEndpoint        string `json:"device_authorization_endpoint,omitempty"`
	PushedAuthorizationRequestEndpoint string `json:"pushed_authorization_request_endpoint,omitempty"` // RFC 9126

	// 关键能力标识
	ScopesSupported                   []string `json:"scopes_supported,omitempty"`
	ResponseTypesSupported            []string `json:"response_types_supported"`
	ResponseModesSupported            []string `json:"response_modes_supported,omitempty"`
	GrantTypesSupported               []string `json:"grant_types_supported,omitempty"`
	SubjectTypesSupported             []string `json:"subject_types_supported"`
	IDTokenSigningAlgValuesSupported  []string `json:"id_token_signing_alg_values_supported"`
	TokenEndpointAuthMethodsSupported []string `json:"token_endpoint_auth_methods_supported,omitempty"`
	ClaimsSupported                   []string `json:"claims_supported,omitempty"`

	// PKCE 支持
	CodeChallengeMethodsSupported []string `json:"code_challenge_methods_supported,omitempty"`
}

// Discover 从给定的 Issuer URL 获取 OIDC 配置信息。
// 它会自动追加 /.well-known/openid-configuration。
func Discover(ctx context.Context, issuer string, httpClient *http.Client) (*Discovery, error) {
	wellKnownPath := strings.TrimSuffix(issuer, "/") + "/.well-known/openid-configuration"

	if httpClient == nil {
		httpClient = http.DefaultClient
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, wellKnownPath, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create discovery request: %w", err)
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("discovery request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("discovery failed with status code %d", resp.StatusCode)
	}

	var config Discovery
	if err := DecodeJSON(resp.Body, &config); err != nil {
		return nil, fmt.Errorf("failed to decode discovery document: %w", err)
	}

	// 简单的校验：确保返回的 Issuer 与请求的一致
	if config.Issuer != issuer {
		return nil, fmt.Errorf("issuer mismatch (expected %s, got %s)", issuer, config.Issuer)
	}

	return &config, nil
}

// RemoteKeySetOption allows configuring RemoteKeySet
type RemoteKeySetOption func(*RemoteKeySet)

// WithCacheDuration sets the default cache duration
func WithCacheDuration(d time.Duration) RemoteKeySetOption {
	return func(r *RemoteKeySet) {
		r.cacheDuration = d
	}
}

// RemoteKeySet 实现了 KeySource 接口。
// 它能够从远程 JWKS URI 获取公钥，并支持 Stale-While-Revalidate 缓存机制。
type RemoteKeySet struct {
	jwksURI    string
	httpClient *http.Client
	ctx        context.Context

	cachedKeys    *xsync.Map[string, crypto.PublicKey]
	expiry        atomic.Value // 存储 time.Time，线程安全
	cacheDuration time.Duration

	// 用于防止缓存击穿 (singleflight)
	requestGroup *singleflight.Group[string, *struct{}]

	// 后台刷新控制
	refreshTicker *time.Ticker
	stopChan      chan struct{}
	stopOnce      sync.Once

	// 断路器状态
	failureCount       atomic.Int64
	lastFailureTime    atomic.Value // time.Time
	circuitBreakerOpen atomic.Bool
}

// NewRemoteKeySet 创建一个新的远程密钥集。
// ctx: 用于控制 HTTP 请求的生命周期。
// jwksURI: 远程 JWKS 地址。
func NewRemoteKeySet(ctx context.Context, jwksURI string, httpClient *http.Client, opts ...RemoteKeySetOption) *RemoteKeySet {
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	r := &RemoteKeySet{
		jwksURI:       jwksURI,
		httpClient:    httpClient,
		ctx:           ctx,
		cacheDuration: 5 * time.Minute, // 默认缓存 5 分钟
		cachedKeys:    xsync.NewMap[string, crypto.PublicKey](),
		requestGroup:  singleflight.NewGroup[string, *struct{}](),
		stopChan:      make(chan struct{}),
	}

	for _, opt := range opts {
		opt(r)
	}

	// 初始化 expiry 为零值
	r.expiry.Store(time.Time{})
	r.lastFailureTime.Store(time.Time{})

	// 启动后台刷新（Stale-While-Revalidate）
	go r.backgroundRefresh()

	return r
}

// GetKey 实现了 KeySource 接口。
// 使用 Stale-While-Revalidate 策略：缓存过期时立即返回旧值，并触发后台刷新。
func (r *RemoteKeySet) GetKey(ctx context.Context, kid string) (crypto.PublicKey, error) {
	// [断路器] 检查断路器状态
	if r.circuitBreakerOpen.Load() {
		// 检查是否可以尝试恢复
		lastFailure := r.lastFailureTime.Load().(time.Time)
		if time.Since(lastFailure) < 30*time.Second {
			// 断路器仍然打开，使用缓存（即使过期）
			if key, ok := r.cachedKeys.Load(kid); ok {
				return key, nil
			}
			return nil, ErrCircuitBreakerOpen
		}
		// 尝试恢复
		r.circuitBreakerOpen.Store(false)
		r.failureCount.Store(0)
	}

	// 1. 优先返回缓存（即使过期）
	key, ok := r.cachedKeys.Load(kid)
	expiry := r.expiry.Load().(time.Time)

	if ok {
		// 如果过期，触发后台刷新但仍返回旧值（Stale-While-Revalidate）
		if time.Now().After(expiry) {
			// 异步刷新，不阻塞
			go r.triggerRefresh(ctx)
		}
		return key, nil
	}

	// 2. 缓存未命中，同步获取（使用 singleflight 防止惊群）
	_, err, _ := r.requestGroup.Do(ctx, "fetch_jwks", func(ctx context.Context) (*struct{}, error) {
		// Double-check inside singleflight
		if _, ok := r.cachedKeys.Load(kid); ok {
			return nil, nil
		}

		jwks, ttl, err := r.fetchJWKS(ctx)
		if err != nil {
			return nil, err
		}

		r.updateCacheLocked(jwks, ttl)
		return nil, nil
	})

	if err != nil {
		return nil, err
	}

	// 3. 返回结果
	key, ok = r.cachedKeys.Load(kid)
	if !ok {
		return nil, fmt.Errorf("key %s not found in remote jwks", kid)
	}
	return key, nil
}

// fetchJWKS 只负责网络请求和解析，不负责锁
func (r *RemoteKeySet) fetchJWKS(ctx context.Context) (*JSONWebKeySet, time.Duration, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, r.jwksURI, nil)
	if err != nil {
		r.recordFailure()
		return nil, 0, err
	}

	resp, err := r.httpClient.Do(req)
	if err != nil {
		r.recordFailure()
		return nil, 0, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		r.recordFailure()
		return nil, 0, fmt.Errorf("jwks endpoint returned %d", resp.StatusCode)
	}

	// 解析 Cache-Control
	ttl := r.cacheDuration // 默认值
	cacheControl := resp.Header.Get("Cache-Control")
	if cacheControl != "" {
		for _, directive := range strings.Split(cacheControl, ",") {
			directive = strings.TrimSpace(directive)
			if strings.HasPrefix(directive, "max-age=") {
				if seconds, err := time.ParseDuration(strings.TrimPrefix(directive, "max-age=") + "s"); err == nil {
					if seconds > 0 {
						ttl = seconds
					}
				}
				break
			}
		}
	}

	var jwks JSONWebKeySet
	if err := DecodeJSON(resp.Body, &jwks); err != nil {
		r.recordFailure()
		return nil, 0, err
	}

	// 成功，重置失败计数
	r.failureCount.Store(0)
	r.circuitBreakerOpen.Store(false)

	return &jwks, ttl, nil
}

// updateCacheLocked 解析 JWKS 并更新 map
func (r *RemoteKeySet) updateCacheLocked(jwks *JSONWebKeySet, ttl time.Duration) {
	r.cachedKeys.Clear()
	for _, k := range jwks.Keys {
		var pubKey crypto.PublicKey
		var err error

		switch k.Kty {
		case "RSA":
			pubKey, err = ParseRSAPublicKeyFromJWK(&k)
		case "EC":
			pubKey, err = ParseECDSAPublicKeyFromJWK(&k)
		case "OKP":
			pubKey, err = ParseEd25519PublicKeyFromJWK(&k)
		default:
			continue
		}

		if err == nil && k.Kid != "" {
			r.cachedKeys.Store(k.Kid, pubKey)
		}
	}
	// 使用 atomic.Value 更新过期时间
	r.expiry.Store(time.Now().Add(ttl))
}

// backgroundRefresh 在后台异步刷新缓存，避免前台请求等待
// 实现 Stale-While-Revalidate 策略的核心
func (r *RemoteKeySet) backgroundRefresh() {
	// 提前 30 秒开始刷新，确保缓存始终有效
	refreshInterval := r.cacheDuration - 30*time.Second
	if refreshInterval <= 0 {
		refreshInterval = r.cacheDuration / 2 // 至少在一半时间后刷新
	}

	ticker := time.NewTicker(refreshInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			// 触发后台刷新
			r.doBackgroundRefresh()

		case <-r.stopChan:
			return
		case <-r.ctx.Done():
			return
		}
	}
}

// doBackgroundRefresh 执行一次后台刷新
func (r *RemoteKeySet) doBackgroundRefresh() {
	// 使用 o11y.Run 包装后台刷新逻辑
	err := o11y.Run(r.ctx, "OIDC.RefreshJWKS", func(ctx context.Context, state o11y.State) error {
		state.Log.Debug().Str("jwks_uri", r.jwksURI).Msg("Starting background JWKS refresh")

		jwks, ttl, err := r.fetchJWKS(ctx)
		if err != nil {
			// 刷新失败，保留旧缓存，不影响前台
			state.Log.Warn().Err(err).Msg("Background JWKS refresh failed, keeping stale cache")
			return err
		}

		r.updateCacheLocked(jwks, ttl)
		state.Log.Info().
			Int("key_count", len(jwks.Keys)).
			Dur("ttl", ttl).
			Msg("Background JWKS refresh completed successfully")
		return nil
	})
	// 如果 o11y.Run 本身返回错误（不太可能），记录
	if err != nil {
		_ = err // 刷新失败已在内部记录，这里静默处理
	}
}

// triggerRefresh 主动触发一次刷新（用于缓存过期时）
func (r *RemoteKeySet) triggerRefresh(ctx context.Context) {
	// 使用 singleflight 防止多次触发
	_, _, _ = r.requestGroup.Do(ctx, "trigger_refresh", func(ctx context.Context) (*struct{}, error) {
		jwks, ttl, err := r.fetchJWKS(ctx)
		if err != nil {
			// 刷新失败，保留旧缓存
			return nil, err
		}

		r.updateCacheLocked(jwks, ttl)
		return nil, nil
	})
}

// Stop 停止后台刷新
func (r *RemoteKeySet) Stop() {
	r.stopOnce.Do(func() {
		close(r.stopChan)
	})
}

// recordFailure 记录失败并可能打开断路器
func (r *RemoteKeySet) recordFailure() {
	r.lastFailureTime.Store(time.Now())
	count := r.failureCount.Add(1)

	// 连续失败 3 次，打开断路器
	const failureThreshold = 3
	if count >= failureThreshold {
		r.circuitBreakerOpen.Store(true)
	}
}
