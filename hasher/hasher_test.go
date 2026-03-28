//go:build test

package hasher

import (
	"context"
	"testing"
	"time"
)

func TestBcryptHasher(t *testing.T) {
	ctx := context.Background()
	// 使用默认 Cost + 1 (11)，确保防御性逻辑生效
	h := NewBcryptHasher(11)
	password := []byte("my_secure_soul")

	t.Run("Functional_Flow", func(t *testing.T) {
		hashed, err := h.Hash(ctx, password)
		if err != nil {
			t.Fatalf("Bcrypt Hash failed: %v", err)
		}

		// 验证正确性
		if err := h.Compare(ctx, hashed, password); err != nil {
			t.Errorf("Bcrypt Compare failed: %v", err)
		}
	})

	t.Run("Dummy_Simulacrum", func(t *testing.T) {
		// 记录真实比较的耗时
		hashed, _ := h.Hash(ctx, password)
		startReal := time.Now()
		_ = h.Compare(ctx, hashed, []byte("wrong_one"))
		realDuration := time.Since(startReal)

		// 记录 Dummy 比较的耗时
		startDummy := time.Now()
		err := h.DummyCompare(ctx)
		dummyDuration := time.Since(startDummy)

		if err == nil {
			t.Error("DummyCompare must always return an error")
		}

		// 计算耗时差异，两者应该在同一个数量级
		// 允许 30% 的波动误差
		threshold := realDuration / 10 * 9 // 至少达到 90% 的真实耗时
		if dummyDuration < threshold {
			t.Errorf("Bcrypt DummyCompare is too fast (%v), real was %v. Potential timing leak!", dummyDuration, realDuration)
		}
		t.Logf("Real Compare: %v, Dummy Compare: %v, Diff: %v", realDuration, dummyDuration, realDuration-dummyDuration)
	})
}

func TestArgon2Hasher(t *testing.T) {
	ctx := context.Background()
	// 使用较低的参数以加快单元测试速度，生产环境请务必调高
	h := NewArgon2Hasher(16*1024, 1, 2, 32, 16)
	password := []byte("master_oy3o_secret")

	t.Run("Functional_Flow", func(t *testing.T) {
		// 1. 测试 Hash 生成
		hashed, err := h.Hash(ctx, password)
		if err != nil {
			t.Fatalf("Hash failed: %v", err)
		}

		// 2. 测试正确的密码比较
		err = h.Compare(ctx, hashed, password)
		if err != nil {
			t.Errorf("Compare should succeed for correct password: %v", err)
		}

		// 3. 测试错误的密码比较
		err = h.Compare(ctx, hashed, []byte("wrong_password"))
		if err == nil {
			t.Error("Compare should fail for wrong password")
		}
	})

	t.Run("Timing_Defense", func(t *testing.T) {
		// 1. 先拿一次真实计算作为标线
		hashed, _ := h.Hash(ctx, password)
		startReal := time.Now()
		_ = h.Compare(ctx, hashed, []byte("wrong"))
		realDuration := time.Since(startReal)

		// 2. 执行 DummyCompare
		start := time.Now()
		_ = h.DummyCompare(ctx)
		elapsed := time.Since(start)

		// 确保 误差在合理范围内
		threshold := realDuration / 10 * 9
		if elapsed < threshold {
			t.Errorf("Argon2 DummyCompare is too fast (%v), real was %v. Potential timing leak!", elapsed, realDuration)
		}
		t.Logf("Argon2 Real: %v, Dummy: %v", realDuration, elapsed)
	})
}
