package oidc

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/pem"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/golang-jwt/jwt/v5"
	"go.step.sm/crypto/pemutil"
)

type KeyType string

const (
	KEY_RSA     KeyType = "RSA"
	KEY_ECDSA   KeyType = "ECDSA"
	KEY_Ed25519 KeyType = "Ed25519"

	KEY_Default = KEY_RSA
)

// Key 接口定义了一个可用于签名的私钥所需的方法。
type Key interface {
	crypto.PrivateKey
	Public() crypto.PublicKey
	Equal(x crypto.PrivateKey) bool
	Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error)
}

// GetSigningMethod 根据私钥类型返回对应的 JWT 签名方法
func GetSigningMethod(key crypto.PrivateKey) jwt.SigningMethod {
	switch pk := key.(type) {
	case *rsa.PrivateKey:
		return jwt.SigningMethodRS256
	case *ecdsa.PrivateKey:
		switch pk.Curve {
		case elliptic.P256():
			return jwt.SigningMethodES256
		case elliptic.P384():
			return jwt.SigningMethodES384
		case elliptic.P521():
			return jwt.SigningMethodES512
		}
	case ed25519.PrivateKey:
		return jwt.SigningMethodEdDSA
	}
	return nil
}

// LoadOrGenerateKey 尝试从指定路径加载私钥。
// 如果文件存在，则加载它；如果不存在，则生成一个新密钥并保存。
func LoadOrGenerateKey(path string, keyType KeyType, password []byte) (Key, error) {
	if _, err := os.Stat(path); err == nil {
		return LoadKey(path, password)
	} else if !os.IsNotExist(err) {
		return nil, fmt.Errorf("failed to stat key file %s: %w", path, err)
	}

	key, err := NewKey(keyType)
	if err != nil {
		return nil, err
	}

	return key, SaveKey(path, key, password)
}

// LoadKey 从指定路径加载一个 PEM 编码的私钥。
// 它使用 pemutil 库来支持加密和未加密的密钥。
func LoadKey(path string, password []byte) (Key, error) {
	var opts []pemutil.Options
	if len(password) > 0 {
		opts = append(opts, pemutil.WithPassword(password))
	}

	// 读取PEM文件内容
	pemBytes, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to load key file %s: %w", path, err)
	}

	// pemutil.Parse 将自动处理加密和未加密的 PEM 数据
	privKey, err := pemutil.Parse(pemBytes, opts...)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key from %s: %w", path, err)
	}

	// 将解析出的密钥转换为我们定义的 Key 接口类型
	key, ok := privKey.(Key)
	if !ok {
		return nil, fmt.Errorf("parsed key from %s does not implement the Key interface", path)
	}

	return key, nil
}

// NewKey 根据指定的类型生成一个新的私钥
func NewKey(keyType KeyType) (key Key, err error) {
	switch keyType {
	case KEY_RSA:
		key, err = rsa.GenerateKey(rand.Reader, 2048)
	case KEY_ECDSA:
		key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case KEY_Ed25519:
		_, key, err = ed25519.GenerateKey(rand.Reader)
	default:
		return nil, fmt.Errorf("unsupported key type: %s", keyType)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to generate %s key: %w", keyType, err)
	}
	return
}

// SaveKey 生成一个指定类型的新私钥，并将其以 PEM 格式保存到路径。
// 如果提供了密码，私钥将被安全地加密。
func SaveKey(path string, key Key, password []byte) error {
	// 使用 pemutil 来编码和加密密钥
	var opts []pemutil.Options
	if len(password) > 0 {
		opts = append(opts, pemutil.WithPassword(password))
	}

	// pemutil.Serialize 会处理 PKCS#8 封送, 默认使用 AES-256-GCM 进行加密
	block, err := pemutil.Serialize(key, opts...)
	if err != nil {
		return fmt.Errorf("failed to serialize private key: %w", err)
	}

	// 将 PEM 字节保存到文件
	data := pem.EncodeToMemory(block)
	dir := filepath.Dir(path)

	// 确保目录存在，权限为 rwxr-xr-x
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("failed to create directory %s: %w", dir, err)
	}
	// 写入文件，权限为 rw-------，只有所有者可读写
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return fmt.Errorf("failed to write key to %s: %w", path, err)
	}

	return nil
}
