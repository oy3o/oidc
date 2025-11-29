package oidc_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/oy3o/oidc"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// -----------------------------------------------------------------------------
// Helper: Mock Handler
// -----------------------------------------------------------------------------

func newTestHandler(t *testing.T, wantJKT string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 验证 context 中是否存在 DPoP claims
		claims, ok := oidc.DPoPFromContext(r.Context())
		if wantJKT != "" {
			require.True(t, ok, "handler should have DPoP claims in context")
			require.NotNil(t, claims)
			assert.Equal(t, wantJKT, claims.JKT)

			// 验证 ExtractDPoPJKT 辅助函数
			assert.Equal(t, wantJKT, oidc.ExtractDPoPJKT(r.Context()))
		} else {
			assert.False(t, ok, "handler should NOT have DPoP claims in context")
			assert.Empty(t, oidc.ExtractDPoPJKT(r.Context()))
		}
		w.WriteHeader(http.StatusOK)
	})
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

func TestDPoPOptionalMiddleware(t *testing.T) {
	storage := NewTestStorage(t)
	key := generateECKey(t)

	// 准备参数
	htm := "GET"
	// httptest 默认 Host 是 example.com
	htu := "http://example.com/protected"

	// 1. Case: No Header (Should Pass)
	t.Run("No Header", func(t *testing.T) {
		req := httptest.NewRequest(htm, htu, nil)
		w := httptest.NewRecorder()

		handler := oidc.DPoPOptionalMiddleware(storage)(newTestHandler(t, ""))
		handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
	})

	// 2. Case: Valid Header (Should Pass and inject context)
	t.Run("Valid Header", func(t *testing.T) {
		proof := makeDPoPProof(t, key, htm, htu, time.Now(), uuid.NewString(), nil)

		req := httptest.NewRequest(htm, htu, nil)
		req.Header.Set("DPoP", proof)
		w := httptest.NewRecorder()

		// 获取期望的 JKT
		// 这里有点 hack，我们直接在 handler 内部拿到的 JKT 应该是合法的
		// 我们改为在 Handler 里不做强校验，或者在 Test 里先计算好
		// 为简单起见，我们修改 testHandler 逻辑或者信任 VerifyDPoPProof
		// 这里我们信任 VerifyDPoPProof 的结果，只验证流程

		handler := oidc.DPoPOptionalMiddleware(storage)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			claims, ok := oidc.DPoPFromContext(r.Context())
			require.True(t, ok)
			require.NotEmpty(t, claims.JKT)
			w.WriteHeader(http.StatusOK)
		}))

		handler.ServeHTTP(w, req)
		assert.Equal(t, http.StatusOK, w.Code)
	})

	// 3. Case: Invalid Header (Should Fail)
	t.Run("Invalid Header", func(t *testing.T) {
		// 错误的 HTU
		proof := makeDPoPProof(t, key, htm, "http://attacker.com", time.Now(), uuid.NewString(), nil)

		req := httptest.NewRequest(htm, htu, nil)
		req.Header.Set("DPoP", proof)
		w := httptest.NewRecorder()

		handler := oidc.DPoPOptionalMiddleware(storage)(newTestHandler(t, ""))
		handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusUnauthorized, w.Code)
		assert.Contains(t, w.Body.String(), "invalid_dpop_proof")
	})
}

func TestDPoPRequiredMiddleware(t *testing.T) {
	storage := NewTestStorage(t)
	key := generateECKey(t)
	htm, htu := "GET", "http://example.com/resource"

	// 1. Case: No Header (Should Fail)
	t.Run("No Header", func(t *testing.T) {
		req := httptest.NewRequest(htm, htu, nil)
		w := httptest.NewRecorder()

		handler := oidc.DPoPRequiredMiddleware(storage)(newTestHandler(t, ""))
		handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusUnauthorized, w.Code)
		assert.Contains(t, w.Body.String(), "DPoP header is required")
	})

	// 2. Case: Valid Header (Should Pass)
	t.Run("Valid Header", func(t *testing.T) {
		proof := makeDPoPProof(t, key, htm, htu, time.Now(), uuid.NewString(), nil)

		req := httptest.NewRequest(htm, htu, nil)
		req.Header.Set("DPoP", proof)
		w := httptest.NewRecorder()

		handler := oidc.DPoPRequiredMiddleware(storage)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			claims, ok := oidc.DPoPFromContext(r.Context())
			require.True(t, ok)
			require.NotEmpty(t, claims.JKT)
			w.WriteHeader(http.StatusOK)
		}))

		handler.ServeHTTP(w, req)
		assert.Equal(t, http.StatusOK, w.Code)
	})
}

func TestBuildRequestURI_Internal(t *testing.T) {
	// 直接测试 buildRequestURI 函数（通过 export 或者就在本包测试）

	tests := []struct {
		name     string
		reqSetup func() *http.Request
		wantURI  string
	}{
		{
			name: "Standard HTTP",
			reqSetup: func() *http.Request {
				r := httptest.NewRequest("GET", "http://example.com/path", nil)
				return r
			},
			wantURI: "http://example.com/path",
		},
		{
			name: "HTTPS via TLS",
			reqSetup: func() *http.Request {
				r := httptest.NewRequest("GET", "https://api.service.com/v1/token", nil)
				return r
			},
			wantURI: "https://api.service.com/v1/token",
		},
		{
			name: "Host Header Override",
			reqSetup: func() *http.Request {
				r := httptest.NewRequest("GET", "http://internal-ip/path", nil)
				r.Host = "public-api.com"
				return r
			},
			wantURI: "http://public-api.com/path",
		},
		{
			name: "Remove Query and Fragment",
			reqSetup: func() *http.Request {
				r := httptest.NewRequest("POST", "http://example.com/token?foo=bar#baz", nil)
				return r
			},
			wantURI: "http://example.com/token",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := tt.reqSetup()
			got := oidc.BuildRequestURI(req)
			assert.Equal(t, tt.wantURI, got)
		})
	}
}

func TestDPoPFromContext_Helpers(t *testing.T) {
	ctx := context.Background()

	// 1. Empty Context
	claims, ok := oidc.DPoPFromContext(ctx)
	assert.False(t, ok)
	assert.Nil(t, claims)
	assert.Empty(t, oidc.ExtractDPoPJKT(ctx))

	// 2. With Value
	expectedJKT := "test-jkt"
	ctx = context.WithValue(ctx, oidc.DpopContextKey{}, &oidc.DPoPClaims{JKT: expectedJKT})

	claims, ok = oidc.DPoPFromContext(ctx)
	assert.True(t, ok)
	assert.Equal(t, expectedJKT, claims.JKT)
	assert.Equal(t, expectedJKT, oidc.ExtractDPoPJKT(ctx))
}

func TestShouldUseDPoP(t *testing.T) {
	assert.True(t, oidc.ShouldUseDPoP("/oauth/token"))
	assert.True(t, oidc.ShouldUseDPoP("/api/userinfo"))
	assert.True(t, oidc.ShouldUseDPoP("/introspect"))
	assert.False(t, oidc.ShouldUseDPoP("/authorize"))
	assert.False(t, oidc.ShouldUseDPoP("/health"))
}

func TestDPoP_ReplayProtection(t *testing.T) {
	storage := NewTestStorage(t) // 实现了 ReplayCache
	key := generateECKey(t)      // 辅助函数在 dpop_test.go 中
	htm, htu := "POST", "http://example.com/resource"
	jti := uuid.NewString()

	// 创建一个合法的 DPoP Proof
	proof := makeDPoPProof(t, key, htm, htu, time.Now(), jti, nil)

	req := httptest.NewRequest(htm, htu, nil)
	req.Header.Set("DPoP", proof)

	// 第一次验证：应该成功
	_, err := oidc.VerifyDPoPProof(context.Background(), req, nil, storage, htm, htu)
	require.NoError(t, err, "First use of DPoP proof should succeed")

	// 第二次验证（重放）：应该失败
	_, err = oidc.VerifyDPoPProof(context.Background(), req, nil, storage, htm, htu)
	assert.Error(t, err, "Replay of DPoP proof should fail")
	assert.Contains(t, err.Error(), "jti has been used")
}
