package oidc

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"fmt"
	"sort"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/puzpuzpuz/xsync/v4"
)

const (
	// DefaultKeyCacheTTL 是本地缓存签名 Key ID 的默认有效期
	// 在分布式环境中，这决定了轮换后其他实例感知到的最大延迟
	DefaultKeyCacheTTL = 30 * time.Second
)

// KeyManager 负责管理服务端的私钥集合。
// 它支持密钥轮换、JWKS 导出以及查找当前签名密钥。
// 现在的实现是无状态的（依赖 KeyStorage），但保留了本地缓存以提高性能。
type KeyManager struct {
	storage KeyStorage
	// keys 缓存: kid -> Key (私钥)
	keys *xsync.Map[string, Key]
	// signingKeyID 缓存
	signingKeyID          *xsync.Map[string, string] // key="current" -> kid
	signingKeyIDFetchedAt *xsync.Map[string, time.Time]
	cacheTTL              time.Duration
}

// NewKeyManager 创建密钥管理器
func NewKeyManager(storage KeyStorage, cacheTTL time.Duration) *KeyManager {
	if cacheTTL <= 0 {
		cacheTTL = DefaultKeyCacheTTL
	}
	return &KeyManager{
		storage:               storage,
		keys:                  xsync.NewMap[string, Key](),
		signingKeyID:          xsync.NewMap[string, string](),
		signingKeyIDFetchedAt: xsync.NewMap[string, time.Time](),
		cacheTTL:              cacheTTL,
	}
}

// Add 从外部添加一个已有的私钥。
// 如果 key 没有 ID，会自动计算 Thumbprint 作为 ID。
// 返回计算出的 kid。
func (km *KeyManager) Add(ctx context.Context, key Key) (string, error) {
	// 验证输入
	if key == nil {
		return "", ErrKeyNil
	}

	// 1. 转换为 JWK
	jKey, err := jwk.FromRaw(key)
	if err != nil {
		return "", fmt.Errorf("failed to create JWK from raw key: %w", err)
	}

	// 2. 确保有 KID
	if jKey.KeyID() == "" {
		if err := jwk.AssignKeyID(jKey); err != nil {
			return "", fmt.Errorf("failed to assign key ID: %w", err)
		}
	}
	kid := jKey.KeyID()

	// 3. 验证密钥安全性
	if err := ValidateKeySecurity(key); err != nil {
		return "", err
	}

	// 4. 存储到持久层
	if err := km.storage.Save(ctx, jKey); err != nil {
		return "", fmt.Errorf("failed to save key to storage: %w", err)
	}

	// 5. 更新本地缓存
	km.keys.Store(kid, key)

	// 6. 如果这是第一个 key 且没有签名 key，尝试设为签名 key
	// 注意：并发环境下这可能不准确，但作为初始化便利性是可以的
	current, _ := km.GetSigningKeyID(ctx)
	if current == "" {
		_ = km.SetSigningKeyID(ctx, kid)
	}

	return kid, nil
}

// Generate 生成一个新的密钥对，添加到管理器中，并选择是否立即将其设为签名密钥。
func (km *KeyManager) Generate(ctx context.Context, kty KeyType, setAsSigning bool) (string, error) {
	// 1. 生成新私钥
	newKey, err := NewKey(kty)
	if err != nil {
		return "", err
	}

	// 2. 添加到管理器
	kid, err := km.Add(ctx, newKey)
	if err != nil {
		return "", err
	}

	// 3. 如果需要，设为签名 Key
	if setAsSigning {
		if err := km.SetSigningKeyID(ctx, kid); err != nil {
			return "", err
		}
	}

	return kid, nil
}

// SetSigningKeyID 指定哪个 kid 用于签名。
func (km *KeyManager) SetSigningKeyID(ctx context.Context, kid string) error {
	// 1. 确保存储中有这个 key
	// 先查缓存
	if _, ok := km.keys.Load(kid); !ok {
		// 再查存储
		if _, err := km.storage.Get(ctx, kid); err != nil {
			return ErrKeyNotFound
		}
	}

	// 2. 更新存储中的签名 ID
	if err := km.storage.SaveSigningKeyID(ctx, kid); err != nil {
		return fmt.Errorf("failed to save signing key ID: %w", err)
	}

	// 3. 更新本地缓存
	km.signingKeyID.Store("current", kid)
	km.signingKeyIDFetchedAt.Store("current", time.Now())
	return nil
}

// GetSigningKeyID 获取当前签名密钥 ID
func (km *KeyManager) GetSigningKeyID(ctx context.Context) (string, error) {
	// 1. 查缓存
	if kid, ok := km.signingKeyID.Load("current"); ok {
		// 检查缓存是否过期
		if fetchedAt, ok := km.signingKeyIDFetchedAt.Load("current"); ok {
			if time.Since(fetchedAt) < km.cacheTTL {
				return kid, nil
			}
		}
	}

	// 2. 查存储
	kid, err := km.storage.GetSigningKeyID(ctx)
	if err != nil {
		return "", err
	}

	// 3. 更新缓存
	km.signingKeyID.Store("current", kid)
	km.signingKeyIDFetchedAt.Store("current", time.Now())
	return kid, nil
}

// GetSigningKey 获取当前用于签名的私钥和 kid。
func (km *KeyManager) GetSigningKey(ctx context.Context) (string, Key, error) {
	kid, err := km.GetSigningKeyID(ctx)
	if err != nil {
		return "", nil, ErrNoSigningKey
	}

	key, err := km.GetKeyInternal(ctx, kid)
	if err != nil {
		return "", nil, err
	}

	return kid, key, nil
}

// GetKey 实现 KeySource 接口。
func (km *KeyManager) GetKey(ctx context.Context, kid string) (crypto.PublicKey, error) {
	// 如果 kid 为空且只有一个 key (兼容性逻辑，但在分布式下很难准确判断“只有一个”，这里简化为必须提供 kid)
	if kid == "" {
		// 尝试获取当前签名 key 作为默认
		signingKid, err := km.GetSigningKeyID(ctx)
		if err == nil {
			kid = signingKid
		} else {
			// 如果连签名 key 都没有，那就真的没办法了
			// 或者我们可以 List 所有 key 取第一个？这在分布式下不太确定。
			// 暂时返回错误。
			return nil, ErrKeyNotFound
		}
	}

	key, err := km.GetKeyInternal(ctx, kid)
	if err != nil {
		return nil, err
	}

	return key.Public(), nil
}

// GetKeyInternal 获取私钥 (Key 接口)
func (km *KeyManager) GetKeyInternal(ctx context.Context, kid string) (Key, error) {
	// 1. 查缓存
	if key, ok := km.keys.Load(kid); ok {
		return key, nil
	}

	// 2. 查存储
	jKey, err := km.storage.Get(ctx, kid)
	if err != nil {
		return nil, err
	}

	// 3. 转换为 Key 接口
	var rawKey interface{}
	if err := jKey.Raw(&rawKey); err != nil {
		return nil, fmt.Errorf("failed to get raw key: %w", err)
	}

	key, ok := rawKey.(Key)
	if !ok {
		return nil, fmt.Errorf("stored key does not implement Key interface")
	}

	// 4. 更新缓存
	km.keys.Store(kid, key)
	return key, nil
}

// ExportJWKS 导出所有公钥为 JWKS 结构。
func (km *KeyManager) ExportJWKS(ctx context.Context) (*JSONWebKeySet, error) {
	// 从存储获取所有 Key，以保证一致性
	jKeys, err := km.storage.List(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to list keys: %w", err)
	}

	var jwks JSONWebKeySet
	jwks.Keys = make([]JSONWebKey, 0, len(jKeys))

	// 排序以保证确定性
	sort.Slice(jKeys, func(i, j int) bool {
		return jKeys[i].KeyID() < jKeys[j].KeyID()
	})

	for _, jKey := range jKeys {
		var rawKey interface{}
		if err := jKey.Raw(&rawKey); err != nil {
			continue
		}

		key, ok := rawKey.(Key)
		if !ok {
			continue
		}

		// 根据密钥类型推断算法
		method := GetSigningMethod(key)
		if method == nil {
			continue
		}
		alg := method.Alg()

		// 转换为 oidc.JSONWebKey
		jwkObj, err := PublicKeyToJWK(key.Public(), jKey.KeyID(), alg)
		if err != nil {
			continue
		}
		jwks.Keys = append(jwks.Keys, jwkObj)
	}

	return &jwks, nil
}

// RemoveKey 删除指定的密钥。
func (km *KeyManager) RemoveKey(ctx context.Context, kid string) error {
	current, _ := km.GetSigningKeyID(ctx)
	if kid == current {
		return ErrCannotRemoveSigningKey
	}

	// 删除存储
	if err := km.storage.Delete(ctx, kid); err != nil {
		return err
	}

	// 删除缓存
	km.keys.Delete(kid)
	return nil
}

// ListKeys 返回所有密钥的 KID 列表
func (km *KeyManager) ListKeys(ctx context.Context) ([]string, error) {
	jKeys, err := km.storage.List(ctx)
	if err != nil {
		return nil, err
	}

	ids := make([]string, len(jKeys))
	for i, k := range jKeys {
		ids[i] = k.KeyID()
	}
	return ids, nil
}

// ValidateKeySecurity 验证密钥安全性
func ValidateKeySecurity(key Key) error {
	switch pk := key.(type) {
	case *rsa.PrivateKey:
		if pk.N == nil || pk.E == 0 {
			return ErrInvalidRSAKey
		}
		if pk.N.BitLen() < 2048 {
			return ErrRSAKeyTooSmall
		}
	case *ecdsa.PrivateKey:
		switch pk.Curve {
		case elliptic.P256(), elliptic.P384(), elliptic.P521():
			// OK
		default:
			return ErrUnsupportedECDSACurve
		}
	case ed25519.PrivateKey:
		if len(pk) != ed25519.PrivateKeySize {
			return ErrInvalidEd25519KeySize
		}
	default:
		return ErrUnsupportedPrivateKeyType
	}
	return nil
}
