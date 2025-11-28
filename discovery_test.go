package oidc

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/bytedance/sonic"
)

// mockJWKSServer 创建一个 mock JWKS HTTP 服务器
func mockJWKSServer(t testing.TB, cacheDuration time.Duration) (*httptest.Server, *atomic.Int32) {
	requestCount := &atomic.Int32{}

	// 生成一个真实的 RSA 密钥（仅一次，用于所有请求）
	privateKey, err := NewKey(KEY_RSA)
	if err != nil {
		t.Fatalf("failed to generate test key: %v", err)
	}

	pubJWK, err := PublicKeyToJWK(privateKey.Public(), "test-key-1", "RS256")
	if err != nil {
		t.Fatalf("failed to convert public key to JWK: %v", err)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount.Add(1)

		// 返回 JWKS
		jwks := JSONWebKeySet{
			Keys: []JSONWebKey{pubJWK},
		}

		// 设置 Cache-Control
		if cacheDuration > 0 {
			seconds := int(cacheDuration.Seconds())
			w.Header().Set("Cache-Control", fmt.Sprintf("max-age=%d", seconds))
		}

		w.Header().Set("Content-Type", "application/json")
		sonic.ConfigDefault.NewEncoder(w).Encode(jwks)
	}))

	return server, requestCount
}

func TestRemoteKeySet_StaleWhileRevalidate(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping stale-while-revalidate test in short mode")
	}

	ctx := context.Background()

	// 创建 mock JWKS 服务器，缓存 3 秒
	server, requestCount := mockJWKSServer(t, 3*time.Second)
	defer server.Close()

	// 创建 RemoteKeySet, use short cache duration for testing
	rks := NewRemoteKeySet(ctx, server.URL, nil, WithCacheDuration(3*time.Second))
	defer rks.Stop()

	// 第一次请求，触发初始加载
	_, err := rks.GetKey(ctx, "test-key-1")
	if err != nil {
		t.Fatalf("initial GetKey failed: %v", err)
	}

	initialRequests := requestCount.Load()
	t.Logf("Initial HTTP requests: %d", initialRequests)

	// 等待缓存过期（3秒 + 容差）
	time.Sleep(3500 * time.Millisecond)

	// 记录请求开始时间
	start := time.Now()

	// 缓存过期后请求，应该立即返回旧值（Stale-While-Revalidate）
	_, err = rks.GetKey(ctx, "test-key-1")
	latency := time.Since(start)

	if err != nil {
		t.Fatalf("GetKey after expiry failed: %v", err)
	}

	// 验证延迟低于 10ms（返回旧缓存，未等待 HTTP）
	if latency > 10*time.Millisecond {
		t.Errorf("latency too high: %v, expected < 10ms (stale cache should be returned)", latency)
	}

	t.Logf("GetKey latency after expiry: %v (expected < 10ms)", latency)

	// 等待后台刷新完成
	time.Sleep(100 * time.Millisecond)

	// 验证后台已触发刷新
	newRequests := requestCount.Load()
	if newRequests <= initialRequests {
		t.Errorf("background refresh did not trigger, request count: %d (initial: %d)", newRequests, initialRequests)
	}

	t.Logf("Total HTTP requests after refresh: %d", newRequests)
}

func TestRemoteKeySet_ConcurrentGetKey(t *testing.T) {
	ctx := context.Background()

	// 生成真实密钥
	privateKey, _ := NewKey(KEY_RSA)
	pubJWK, _ := PublicKeyToJWK(privateKey.Public(), "test-key-1", "RS256")

	// 创建 mock 服务器，模拟 100ms 延迟
	requestCount := &atomic.Int32{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount.Add(1)
		time.Sleep(100 * time.Millisecond) // 模拟网络延迟

		jwks := JSONWebKeySet{
			Keys: []JSONWebKey{pubJWK},
		}

		w.Header().Set("Content-Type", "application/json")
		sonic.ConfigDefault.NewEncoder(w).Encode(jwks)
	}))
	defer server.Close()

	rks := NewRemoteKeySet(ctx, server.URL, nil)
	defer rks.Stop()

	// 1000 个并发请求
	const goroutines = 1000
	var wg sync.WaitGroup
	wg.Add(goroutines)

	errors := &atomic.Int32{}

	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			_, err := rks.GetKey(ctx, "test-key-1")
			if err != nil {
				errors.Add(1)
			}
		}()
	}

	wg.Wait()

	// 验证所有请求都成功
	if errors.Load() > 0 {
		t.Errorf("%d requests failed out of %d", errors.Load(), goroutines)
	}

	// 验证 singleflight 生效：只发起少量 HTTP 请求
	httpRequests := requestCount.Load()
	if httpRequests > 5 {
		t.Errorf("too many HTTP requests: %d, singleflight should limit to ~1-2", httpRequests)
	}

	t.Logf("Concurrent test succeeded: %d goroutines, %d HTTP requests", goroutines, httpRequests)
}

func TestRemoteKeySet_BackgroundRefresh(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping background refresh test in short mode")
	}

	cleanup := setupO11yForTest()
	defer cleanup()

	ctx := context.Background()

	server, requestCount := mockJWKSServer(t, 2*time.Second)
	defer server.Close()

	// Use short cache duration for testing
	rks := NewRemoteKeySet(ctx, server.URL, nil, WithCacheDuration(2*time.Second))
	defer rks.Stop()

	// 触发初始加载
	_, err := rks.GetKey(ctx, "test-key-1")
	if err != nil {
		t.Fatalf("initial GetKey failed: %v", err)
	}

	initialRequests := requestCount.Load()

	// 等待后台刷新触发（cacheDuration=2s, 刷新间隔=1s）
	// Ticker 第一个 tick 发生在创建后 1 秒
	// 等待 2.5 秒确保至少触发两次刷新
	time.Sleep(2500 * time.Millisecond)

	// 验证后台已自动刷新（应该至少有 2 次刷新）
	newRequests := requestCount.Load()
	if newRequests <= initialRequests {
		t.Errorf("background refresh did not occur, requests: %d (initial: %d)", newRequests, initialRequests)
	}

	t.Logf("Background refresh successful, requests: %d -> %d", initialRequests, newRequests)
}

func TestRemoteKeySet_RefreshFailureFallback(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping refresh failure test in short mode")
	}

	ctx := context.Background()

	// 生成真实密钥
	privateKey, _ := NewKey(KEY_RSA)
	pubJWK, _ := PublicKeyToJWK(privateKey.Public(), "test-key-1", "RS256")

	// 创建会失败的服务器
	failCount := &atomic.Int32{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		count := failCount.Add(1)

		// 前 2 次请求成功，之后失败
		if count > 2 {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		jwks := JSONWebKeySet{
			Keys: []JSONWebKey{pubJWK},
		}

		w.Header().Set("Cache-Control", "max-age=1")
		w.Header().Set("Content-Type", "application/json")
		sonic.ConfigDefault.NewEncoder(w).Encode(jwks)
	}))
	defer server.Close()

	rks := NewRemoteKeySet(ctx, server.URL, nil)
	defer rks.Stop()

	// 初始加载成功
	_, err := rks.GetKey(ctx, "test-key-1")
	if err != nil {
		t.Fatalf("initial GetKey failed: %v", err)
	}

	// 等待缓存过期 + 刷新失败
	time.Sleep(2 * time.Second)

	// 即使刷新失败，GetKey 仍应返回旧缓存（Stale-While-Revalidate）
	_, err = rks.GetKey(ctx, "test-key-1")
	if err != nil {
		t.Errorf("GetKey should return stale cache on refresh failure, got error: %v", err)
	}

	t.Logf("Refresh failure fallback successful, stale cache returned")
}

func TestRemoteKeySet_KeyNotFound(t *testing.T) {
	ctx := context.Background()

	server, _ := mockJWKSServer(t, 5*time.Minute)
	defer server.Close()

	rks := NewRemoteKeySet(ctx, server.URL, nil)
	defer rks.Stop()

	// 请求不存在的 KID
	_, err := rks.GetKey(ctx, "non-existent-key")
	if err == nil {
		t.Errorf("GetKey should fail for non-existent key")
	}

	t.Logf("Key not found error: %v", err)
}

// 基准测试：验证 Stale-While-Revalidate 的性能
func BenchmarkRemoteKeySet_GetKey_Cached(b *testing.B) {
	ctx := context.Background()

	server, _ := mockJWKSServer(b, 10*time.Minute)
	defer server.Close()

	rks := NewRemoteKeySet(ctx, server.URL, nil)
	defer rks.Stop()

	// 预热缓存
	_, _ = rks.GetKey(ctx, "test-key-1")

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, _ = rks.GetKey(ctx, "test-key-1")
	}
}

func BenchmarkRemoteKeySet_GetKey_Concurrent(b *testing.B) {
	ctx := context.Background()

	server, _ := mockJWKSServer(b, 10*time.Minute)
	defer server.Close()

	rks := NewRemoteKeySet(ctx, server.URL, nil)
	defer rks.Stop()

	// 预热缓存
	_, _ = rks.GetKey(ctx, "test-key-1")

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_, _ = rks.GetKey(ctx, "test-key-1")
		}
	})
}
