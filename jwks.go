package oidc

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"math/big"
)

// JSONWebKeySet 表示 JWKS 端点返回的顶级 JSON 结构。
type JSONWebKeySet struct {
	Keys []JSONWebKey `json:"keys"`
}

// JSONWebKey 表示单个 JWK 的结构。
type JSONWebKey struct {
	Kty string `json:"kty"`           // Key Type (RSA, EC, OKP)
	Kid string `json:"kid,omitempty"` // Key ID
	Use string `json:"use,omitempty"` // Public Key Use (sig, enc)
	Alg string `json:"alg,omitempty"` // Algorithm (RS256, ES256, EdDSA...)

	// RSA 字段
	N string `json:"n,omitempty"` // Modulus (Base64URL)
	E string `json:"e,omitempty"` // Exponent (Base64URL)

	// ECDSA / Ed25519 字段
	Crv string `json:"crv,omitempty"` // Curve (P-256, P-384, P-521, Ed25519)
	X   string `json:"x,omitempty"`   // X Coordinate (Base64URL)
	Y   string `json:"y,omitempty"`   // Y Coordinate (Base64URL), Ed25519 不需要此字段
}

// PublicKeyToJWK 将标准库的 crypto.PublicKey 转换为 JWK 结构体。
func PublicKeyToJWK(pub crypto.PublicKey, kid, alg string) (JSONWebKey, error) {
	jwk := JSONWebKey{
		Kid: kid,
		Use: "sig", // 默认为签名用途
		Alg: alg,
	}

	switch k := pub.(type) {
	case *rsa.PublicKey:
		jwk.Kty = "RSA"
		if jwk.Alg == "" {
			jwk.Alg = "RS256"
		}
		jwk.N = base64.RawURLEncoding.EncodeToString(k.N.Bytes())
		jwk.E = base64.RawURLEncoding.EncodeToString(big.NewInt(int64(k.E)).Bytes())

	case *ecdsa.PublicKey:
		jwk.Kty = "EC"
		if jwk.Alg == "" {
			jwk.Alg = "ES256"
		}
		params := k.Params()
		jwk.Crv = params.Name
		if jwk.Crv == "" {
			// fallback mapping if Name is empty
			switch params.BitSize {
			case 256:
				jwk.Crv = "P-256"
			case 384:
				jwk.Crv = "P-384"
			case 521:
				jwk.Crv = "P-521"
			}
		}
		jwk.X = base64.RawURLEncoding.EncodeToString(k.X.Bytes())
		jwk.Y = base64.RawURLEncoding.EncodeToString(k.Y.Bytes())

	case ed25519.PublicKey:
		jwk.Kty = "OKP" // Octet Key Pair
		if jwk.Alg == "" {
			jwk.Alg = "EdDSA"
		}
		jwk.Crv = "Ed25519"
		jwk.X = base64.RawURLEncoding.EncodeToString(k)
		// Ed25519 没有 Y 坐标

	default:
		return JSONWebKey{}, ErrUnsupportedJWKPublicKeyType
	}

	// 如果没有提供 kid，计算指纹作为 kid
	if jwk.Kid == "" {
		thumbprint, err := jwk.Thumbprint()
		if err == nil {
			jwk.Kid = thumbprint
		}
	}

	return jwk, nil
}

// Thumbprint 根据 RFC 7638 计算 JWK Thumbprint (SHA-256)
// 常用于生成 kid
func (jwk *JSONWebKey) Thumbprint() (string, error) {
	// 必须按照字母顺序构造 JSON，这里手动构造以保证顺序和字段准确性
	var canonicalJSON string

	switch jwk.Kty {
	case "RSA":
		canonicalJSON = fmt.Sprintf(`{"e":"%s","kty":"RSA","n":"%s"}`, jwk.E, jwk.N)
	case "EC":
		canonicalJSON = fmt.Sprintf(`{"crv":"%s","kty":"EC","x":"%s","y":"%s"}`, jwk.Crv, jwk.X, jwk.Y)
	case "OKP":
		canonicalJSON = fmt.Sprintf(`{"crv":"%s","kty":"OKP","x":"%s"}`, jwk.Crv, jwk.X)
	default:
		return "", ErrUnsupportedKtyForThumbprint
	}

	hash := sha256.Sum256([]byte(canonicalJSON))
	return base64.RawURLEncoding.EncodeToString(hash[:]), nil
}

// ParseECDSAPublicKeyFromJWK 是一个辅助函数，用于将 JWK 转换回 *ecdsa.PublicKey (主要用于 Client 端验证)。
func ParseECDSAPublicKeyFromJWK(jwk *JSONWebKey) (*ecdsa.PublicKey, error) {
	if jwk.Kty != "EC" {
		return nil, ErrKeyNotEC
	}

	var curve elliptic.Curve
	switch jwk.Crv {
	case "P-256":
		curve = elliptic.P256()
	case "P-384":
		curve = elliptic.P384()
	case "P-521":
		curve = elliptic.P521()
	default:
		return nil, ErrUnsupportedCurve
	}

	xBytes, err := base64.RawURLEncoding.DecodeString(jwk.X)
	if err != nil {
		return nil, err
	}
	yBytes, err := base64.RawURLEncoding.DecodeString(jwk.Y)
	if err != nil {
		return nil, err
	}

	x := new(big.Int).SetBytes(xBytes)
	y := new(big.Int).SetBytes(yBytes)

	return &ecdsa.PublicKey{Curve: curve, X: x, Y: y}, nil
}

// ParseRSAPublicKeyFromJWK 是一个辅助函数，用于将 JWK 转换回 *rsa.PublicKey。
func ParseRSAPublicKeyFromJWK(jwk *JSONWebKey) (*rsa.PublicKey, error) {
	if jwk.Kty != "RSA" {
		return nil, ErrKeyNotRSA
	}

	nBytes, err := base64.RawURLEncoding.DecodeString(jwk.N)
	if err != nil {
		return nil, err
	}
	eBytes, err := base64.RawURLEncoding.DecodeString(jwk.E)
	if err != nil {
		return nil, err
	}

	n := new(big.Int).SetBytes(nBytes)
	e := new(big.Int).SetBytes(eBytes).Int64()

	return &rsa.PublicKey{N: n, E: int(e)}, nil
}

// ParseEd25519PublicKeyFromJWK 解析 Ed25519 JWK
func ParseEd25519PublicKeyFromJWK(jwk *JSONWebKey) (ed25519.PublicKey, error) {
	if jwk.Kty != "OKP" || jwk.Crv != "Ed25519" {
		return nil, ErrKeyNotEd25519
	}
	xBytes, err := base64.RawURLEncoding.DecodeString(jwk.X)
	if err != nil {
		return nil, err
	}
	if len(xBytes) != ed25519.PublicKeySize {
		return nil, ErrInvalidEd25519PublicKeySize
	}
	return ed25519.PublicKey(xBytes), nil
}
