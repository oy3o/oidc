package oidc_test

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/oy3o/o11y"
	"github.com/oy3o/oidc"
)

// SetupO11yForTest 为测试初始化 o11y（禁用模式，避免日志输出）
func SetupO11yForTest() func() {
	cfg := o11y.Config{
		Enabled:              true,
		Service:              "oidc-test",
		Version:              "test",
		Environment:          "test",
		InstrumentationScope: "test",
		Log: o11y.LogConfig{
			Level:         "error", // 测试时只记录错误
			EnableConsole: false,
			EnableFile:    false,
		},
		Trace: o11y.TraceConfig{
			Enabled:  false, // 测试时禁用追踪
			Exporter: "none",
		},
		Metric: o11y.MetricConfig{
			Enabled: false, // 测试时禁用指标
		},
	}

	shutdown, _ := o11y.Init(cfg)
	return func() {
		shutdown(context.Background())
	}
}

func TestKeyRotationScheduler_RotateNow(t *testing.T) {
	cleanup := SetupO11yForTest()
	defer cleanup()

	ctx := context.Background()

	// 创建 MockStorage 和 KeyManager
	storage, _ := NewTestStorage(t)
	km := oidc.NewKeyManager(storage, 0)
	initialKID, err := km.Generate(ctx, oidc.KEY_RSA, true)
	if err != nil {
		t.Fatalf("failed to generate initial key: %v", err)
	}

	// 创建调度器
	config := oidc.KeyRotationConfig{
		RotationInterval: 1 * time.Minute,
		GracePeriod:      10 * time.Second,
		KeyType:          oidc.KEY_RSA,
		EnableAutoRotate: false, // 手动测试，不启用自动轮换
	}
	scheduler := oidc.NewKeyRotationScheduler(km, storage, config)

	// 触发轮换
	if err := scheduler.RotateNow(ctx); err != nil {
		t.Fatalf("RotateNow failed: %v", err)
	}

	// 验证新密钥已生成
	newKID := scheduler.GetCurrentKeyID()
	if newKID == initialKID {
		t.Errorf("key was not rotated, still using initial key")
	}

	// 验证旧密钥在宽限期内仍可验证
	_, err = km.GetKey(ctx, initialKID)
	if err != nil {
		t.Errorf("old key should still be available during grace period: %v", err)
	}

	// 验证新密钥是当前签名密钥
	signingKID, _, err := km.GetSigningKey(ctx)
	if err != nil {
		t.Fatalf("failed to get signing key: %v", err)
	}
	if signingKID != newKID {
		t.Errorf("signing key ID = %s, want %s", signingKID, newKID)
	}

	// 验证待删除列表中包含旧密钥
	pending := scheduler.GetPendingDeletes()
	if _, exists := pending[initialKID]; !exists {
		t.Errorf("old key should be in pending deletes")
	}
}

func TestKeyRotationScheduler_ConcurrentRotate(t *testing.T) {
	ctx := context.Background()

	storage, _ := NewTestStorage(t)
	km := oidc.NewKeyManager(storage, 0)
	config := oidc.KeyRotationConfig{
		RotationInterval: 1 * time.Minute,
		GracePeriod:      5 * time.Second,
		KeyType:          oidc.KEY_RSA,
		EnableAutoRotate: false,
	}
	scheduler := oidc.NewKeyRotationScheduler(km, storage, config)

	// 启动调度器（生成初始密钥）
	if err := scheduler.Start(ctx); err != nil {
		t.Fatalf("failed to start scheduler: %v", err)
	}
	defer scheduler.Stop()

	// 记录轮换次数
	var rotationCount atomic.Int32

	// 100 个 goroutine 同时调用 RotateNow
	const goroutines = 100
	var wg sync.WaitGroup
	wg.Add(goroutines)

	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			if err := scheduler.RotateNow(ctx); err == nil {
				rotationCount.Add(1)
			}
		}()
	}

	wg.Wait()

	// 由于有 mutex 保护，应该只有部分轮换成功（取决于执行顺序）
	// 但至少应该有轮换发生
	if rotationCount.Load() == 0 {
		t.Errorf("no rotations succeeded, expected at least 1")
	}

	t.Logf("Concurrent rotations succeeded: %d/%d", rotationCount.Load(), goroutines)

	// 验证 KeyManager 中的密钥数量合理
	// 应该是：初始密钥 + 成功轮换的新密钥（旧的还在宽限期）
	allKeys, err := km.ListKeys(ctx)
	if err != nil {
		t.Fatalf("failed to list keys: %v", err)
	}
	t.Logf("Total keys in manager: %d", len(allKeys))
}

func TestKeyRotationScheduler_AutoRotation(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping auto-rotation test in short mode")
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	storage, _ := NewTestStorage(t)
	km := oidc.NewKeyManager(storage, 0)
	config := oidc.KeyRotationConfig{
		RotationInterval: 2 * time.Second, // 快速轮换用于测试
		GracePeriod:      1 * time.Second,
		KeyType:          oidc.KEY_ECDSA,
		EnableAutoRotate: true,
	}
	scheduler := oidc.NewKeyRotationScheduler(km, storage, config)

	// 启动自动轮换
	if err := scheduler.Start(ctx); err != nil {
		t.Fatalf("failed to start scheduler: %v", err)
	}
	defer scheduler.Stop()

	initialKID := scheduler.GetCurrentKeyID()

	// 等待第一次自动轮换（2秒间隔 + 容差）
	time.Sleep(2500 * time.Millisecond)

	newKID := scheduler.GetCurrentKeyID()
	if newKID == initialKID {
		t.Errorf("auto rotation did not occur within expected time")
	}

	t.Logf("Auto rotation successful: %s -> %s", initialKID, newKID)
}

func TestKeyRotationScheduler_GracePeriodCleanup(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping cleanup test in short mode")
	}

	ctx := context.Background()

	storage, _ := NewTestStorage(t)
	km := oidc.NewKeyManager(storage, 0)
	config := oidc.KeyRotationConfig{
		RotationInterval: 1 * time.Minute,
		GracePeriod:      2 * time.Second, // 短宽限期用于测试
		CleanupInterval:  1 * time.Second, // 快节奏清理
		KeyType:          oidc.KEY_RSA,
		EnableAutoRotate: false,
	}
	scheduler := oidc.NewKeyRotationScheduler(km, storage, config)

	// 启动调度器
	if err := scheduler.Start(ctx); err != nil {
		t.Fatalf("failed to start scheduler: %v", err)
	}
	defer scheduler.Stop()

	initialKID := scheduler.GetCurrentKeyID()

	// 触发轮换
	if err := scheduler.RotateNow(ctx); err != nil {
		t.Fatalf("RotateNow failed: %v", err)
	}

	// 验证旧密钥存在
	_, err := km.GetKey(ctx, initialKID)
	if err != nil {
		t.Errorf("old key should exist before grace period: %v", err)
	}

	// 等待宽限期结束(2s) + 清理间隔(1s) + 容差
	time.Sleep(3500 * time.Millisecond)

	// 验证旧密钥已被删除
	_, err = km.GetKey(ctx, initialKID)
	if err != oidc.ErrKeyNotFound {
		t.Errorf("old key should be deleted after grace period, got error: %v", err)
	}

	t.Logf("Grace period cleanup successful, old key %s removed", initialKID)
}

func TestKeyRotationScheduler_ZeroGracePeriod(t *testing.T) {
	ctx := context.Background()

	storage, _ := NewTestStorage(t)
	km := oidc.NewKeyManager(storage, 0)
	config := oidc.KeyRotationConfig{
		RotationInterval: 1 * time.Minute,
		GracePeriod:      0, // 无宽限期，立即删除
		KeyType:          oidc.KEY_Ed25519,
		EnableAutoRotate: false,
	}
	scheduler := oidc.NewKeyRotationScheduler(km, storage, config)

	if err := scheduler.Start(ctx); err != nil {
		t.Fatalf("failed to start scheduler: %v", err)
	}
	defer scheduler.Stop()

	initialKID := scheduler.GetCurrentKeyID()

	// 触发轮换
	if err := scheduler.RotateNow(ctx); err != nil {
		t.Fatalf("RotateNow failed: %v", err)
	}

	// 验证旧密钥立即被删除
	_, err := km.GetKey(ctx, initialKID)
	if err != oidc.ErrKeyNotFound {
		t.Errorf("old key should be immediately deleted with zero grace period, got error: %v", err)
	}

	// 验证没有待删除项
	pending := scheduler.GetPendingDeletes()
	if len(pending) != 0 {
		t.Errorf("pending deletes should be empty, got %d items", len(pending))
	}
}
