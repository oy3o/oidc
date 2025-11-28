package oidc

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// setupKeyManagerTest 初始化 KeyManager 测试环境
func setupKeyManagerTest(t *testing.T) *KeyManager {
	storage := NewMockStorage()
	km := NewKeyManager(storage)
	// 缩短缓存时间以便测试缓存过期
	km.cacheTTL = 100 * time.Millisecond
	return km
}

func TestKeyManager_Generate_AllTypes(t *testing.T) {
	km := setupKeyManagerTest(t)
	ctx := context.Background()

	tests := []struct {
		name    string
		kty     KeyType
		wantErr bool
	}{
		{"RSA", KEY_RSA, false},
		{"ECDSA", KEY_ECDSA, false},
		{"Ed25519", KEY_Ed25519, false},
		{"Unknown", KeyType("UNKNOWN"), true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			kid, err := km.Generate(ctx, tt.kty, true)
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.NotEmpty(t, kid)

			// 验证获取
			key, err := km.GetKeyInternal(ctx, kid)
			require.NoError(t, err)
			assert.NotNil(t, key)

			// 验证具体的 Key 类型
			switch tt.kty {
			case KEY_RSA:
				_, ok := key.(*rsa.PrivateKey)
				assert.True(t, ok, "should be RSA key")
			case KEY_ECDSA:
				_, ok := key.(*ecdsa.PrivateKey)
				assert.True(t, ok, "should be ECDSA key")
			case KEY_Ed25519:
				_, ok := key.(ed25519.PrivateKey)
				assert.True(t, ok, "should be Ed25519 key")
			}
		})
	}
}

func TestKeyManager_Add_Manual(t *testing.T) {
	km := setupKeyManagerTest(t)
	ctx := context.Background()

	// 1. 手动生成 RSA Key
	rawKey, err := NewKey(KEY_RSA)
	require.NoError(t, err)

	// 2. 添加到 Manager
	kid, err := km.Add(ctx, rawKey)
	require.NoError(t, err)
	assert.NotEmpty(t, kid)

	// 3. 验证可以获取
	gotKey, err := km.GetKeyInternal(ctx, kid)
	require.NoError(t, err)
	assert.Equal(t, rawKey, gotKey)

	// 4. 验证这是第一个 Key，是否自动设为签名 Key (取决于 Add 的实现细节，当前实现会尝试设为签名 Key 如果没有的话)
	signingKid, err := km.GetSigningKeyID(ctx)
	require.NoError(t, err)
	assert.Equal(t, kid, signingKid)
}

func TestKeyManager_SigningKeySelection(t *testing.T) {
	km := setupKeyManagerTest(t)
	ctx := context.Background()

	// 1. 初始状态：无签名 Key
	_, err := km.GetSigningKeyID(ctx)
	assert.ErrorIs(t, err, ErrKeyNotFound)

	// 2. 生成 Key A (设为签名)
	kidA, err := km.Generate(ctx, KEY_RSA, true)
	require.NoError(t, err)

	curr, err := km.GetSigningKeyID(ctx)
	require.NoError(t, err)
	assert.Equal(t, kidA, curr)

	// 3. 生成 Key B (不设为签名)
	kidB, err := km.Generate(ctx, KEY_RSA, false)
	require.NoError(t, err)

	curr, err = km.GetSigningKeyID(ctx)
	assert.Equal(t, kidA, curr, "Generating new key without flag should not change signing key")

	// 4. 手动切换到 Key B
	err = km.SetSigningKeyID(ctx, kidB)
	require.NoError(t, err)

	curr, err = km.GetSigningKeyID(ctx)
	assert.Equal(t, kidB, curr)

	// 5. 尝试切换到不存在的 Key
	err = km.SetSigningKeyID(ctx, "non-existent")
	assert.ErrorIs(t, err, ErrKeyNotFound)
}

func TestKeyManager_SigningKey_Cache(t *testing.T) {
	km := setupKeyManagerTest(t)
	ctx := context.Background()

	// 1. 生成 Key A
	kidA, _ := km.Generate(ctx, KEY_RSA, true)

	// 2. 第一次获取 (Cache Miss -> DB)
	curr, _ := km.GetSigningKeyID(ctx)
	assert.Equal(t, kidA, curr)

	// 3. 直接修改 DB (模拟分布式环境下其他实例修改了配置)
	kidB := "manual-key-b"
	// 手动往 storage 塞一个 Key B
	rawKeyB, _ := NewKey(KEY_RSA)
	PublicKeyToJWK(rawKeyB.Public(), kidB, "RS256") // 简化，这里只为了让 SetSigningKeyID 通过检查
	// 由于 KeyManager.SetSigningKeyID 会检查 key 是否存在，我们需要 hack storage 或者用 km.Add
	kidB, _ = km.Add(ctx, rawKeyB)

	// 绕过 km 缓存，直接操作 storage 修改 signing key ID
	km.storage.SaveSigningKeyID(ctx, kidB)

	// 4. 立即获取 (Cache Hit -> Still A)
	curr, _ = km.GetSigningKeyID(ctx)
	assert.Equal(t, kidA, curr, "Should return cached key A")

	// 5. 等待缓存过期
	time.Sleep(150 * time.Millisecond)

	// 6. 再次获取 (Cache Expired -> DB -> B)
	curr, _ = km.GetSigningKeyID(ctx)
	assert.Equal(t, kidB, curr, "Should return new key B after cache expiry")
}

func TestKeyManager_ExportJWKS(t *testing.T) {
	km := setupKeyManagerTest(t)
	ctx := context.Background()

	// 1. 生成 RSA 和 EC Key
	rsaKid, _ := km.Generate(ctx, KEY_RSA, true)
	ecKid, _ := km.Generate(ctx, KEY_ECDSA, false)

	// 2. 导出 JWKS
	jwks, err := km.ExportJWKS(ctx)
	require.NoError(t, err)
	assert.Len(t, jwks.Keys, 2)

	// 3. 验证内容
	foundRSA := false
	foundEC := false

	for _, k := range jwks.Keys {
		assert.Equal(t, "sig", k.Use)

		switch k.Kid {
		case rsaKid:
			foundRSA = true
			assert.Equal(t, "RSA", k.Kty)
			assert.Equal(t, "RS256", k.Alg) // 默认算法
			assert.NotEmpty(t, k.N)
			assert.NotEmpty(t, k.E)
		case ecKid:
			foundEC = true
			assert.Equal(t, "EC", k.Kty)
			assert.Equal(t, "ES256", k.Alg) // P-256 默认
			assert.Equal(t, "P-256", k.Crv)
			assert.NotEmpty(t, k.X)
			assert.NotEmpty(t, k.Y)
		}
	}

	assert.True(t, foundRSA, "JWKS should contain RSA key")
	assert.True(t, foundEC, "JWKS should contain EC key")
}

func TestKeyManager_RemoveKey(t *testing.T) {
	km := setupKeyManagerTest(t)
	ctx := context.Background()

	kidA, _ := km.Generate(ctx, KEY_RSA, true)
	kidB, _ := km.Generate(ctx, KEY_RSA, false)

	// 1. 尝试删除签名 Key (应失败)
	err := km.RemoveKey(ctx, kidA)
	assert.ErrorIs(t, err, ErrCannotRemoveSigningKey)

	// 2. 删除非签名 Key (应成功)
	err = km.RemoveKey(ctx, kidB)
	assert.NoError(t, err)

	// 3. 验证已删除
	_, err = km.GetKeyInternal(ctx, kidB)
	assert.ErrorIs(t, err, ErrKeyNotFound)

	// 4. 验证从 List 中消失
	ids, _ := km.ListKeys(ctx)
	assert.NotContains(t, ids, kidB)
	assert.Contains(t, ids, kidA)
}

func TestKeyManager_GetKey_Default(t *testing.T) {
	km := setupKeyManagerTest(t)
	ctx := context.Background()

	kid, _ := km.Generate(ctx, KEY_RSA, true)

	// 1. 指定 KID
	key1, err := km.GetKey(ctx, kid)
	require.NoError(t, err)
	assert.NotNil(t, key1)

	// 2. 不指定 KID (空字符串) -> 应该返回当前签名 Key
	key2, err := km.GetKey(ctx, "")
	require.NoError(t, err)
	assert.Equal(t, key1, key2)
}

func TestValidateKeySecurity(t *testing.T) {
	// 1. Valid RSA 2048
	// We'll use NewKey helper from key.go
	rsa2048Key, _ := NewKey(KEY_RSA)
	assert.NoError(t, ValidateKeySecurity(rsa2048Key))

	// 2. Invalid RSA 1024
	rsa1024, _ := rsa.GenerateKey(rand.Reader, 1024) // Just for test structure, assuming we have a reader wrapper
	// Go's rsa.GenerateKey needs io.Reader.
	// Let's manually construct a small key if needed, or trust rsa.GenerateKey
	// To strictly test `ValidateKeySecurity` failure on small keys:
	assert.ErrorIs(t, ValidateKeySecurity(rsa1024), ErrRSAKeyTooSmall)

	// 3. Valid ECDSA
	ecKey, _ := NewKey(KEY_ECDSA)
	assert.NoError(t, ValidateKeySecurity(ecKey))

	// 4. Valid Ed25519
	edKey, _ := NewKey(KEY_Ed25519)
	assert.NoError(t, ValidateKeySecurity(edKey))
}
