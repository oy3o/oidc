package oidc

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"regexp"
)

const (
	// CodeChallengeMethodS256 是推荐的 PKCE 转换方法
	CodeChallengeMethodS256 = "S256"
	// CodeChallengeMethodPlain 是不推荐的方法，仅用于兼容性
	CodeChallengeMethodPlain = "plain"
)

// verifierRegex 用于验证 Code Verifier 是否符合 RFC 7636 要求的字符集
// unreserved = ALPHA / DIGIT / "-" / "." / "_" / "~"
var verifierRegex = regexp.MustCompile(`^[A-Za-z0-9\-\._~]+$`)

// GeneratePKCEVerifier 生成一个符合 RFC 7636 标准的高熵随机字符串。
// 长度默认为 43 字符（32 字节熵）。
func GeneratePKCEVerifier() (string, error) {
	// RFC 建议使用 32 字节的随机序列，然后进行 base64url 编码
	var data [32]byte
	if _, err := rand.Read(data[:]); err != nil {
		return "", ErrPKCERandomnessGenerationFailed
	}
	// RawURLEncoding 是无填充的 Base64URL
	return base64.RawURLEncoding.EncodeToString(data[:]), nil
}

// ComputePKCEChallenge 根据给定的 Verifier 和 Method 计算 Challenge。
// 目前主要支持 S256。
func ComputePKCEChallenge(method, verifier string) (string, error) {
	if verifier == "" {
		return "", ErrPKCEVerifierEmpty
	}

	switch method {
	case CodeChallengeMethodS256:
		s := sha256.Sum256([]byte(verifier))
		return base64.RawURLEncoding.EncodeToString(s[:]), nil
	case CodeChallengeMethodPlain:
		return verifier, nil
	default:
		return "", ErrUnsupportedPKCEChallengeMethod
	}
}

// VerifyPKCE 验证前端传来的 Verifier 是否与存储的 Challenge 匹配。
func VerifyPKCE(challenge, method, verifier string) error {
	// 1. 基础格式检查
	if len(verifier) < 43 || len(verifier) > 128 {
		return ErrPKCEVerifierInvalidLength
	}
	if !verifierRegex.MatchString(verifier) {
		return ErrPKCEVerifierInvalidChars
	}

	// 2. 计算预期值
	expected, err := ComputePKCEChallenge(method, verifier)
	if err != nil {
		return err
	}

	// 3. 比较, 使用常量时间比较以防止时序攻击
	if subtle.ConstantTimeCompare([]byte(challenge), []byte(expected)) != 1 {
		return ErrPKCEVerificationFailed
	}

	return nil
}
