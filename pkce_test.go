package oidc

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// -----------------------------------------------------------------------------
// RFC 7636 Test Vectors
// -----------------------------------------------------------------------------
// Verifier and Challenge taken from RFC 7636 Appendix B.
// https://datatracker.ietf.org/doc/html/rfc7636#appendix-B
const (
	rfcVerifier  = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	rfcChallenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
)

func TestGeneratePKCEVerifier(t *testing.T) {
	// 1. 生成 Verifier
	verifier, err := GeneratePKCEVerifier()
	require.NoError(t, err)

	// 2. 验证长度 (32字节 entropy -> base64url 约 43 字符)
	// RFC 7636 Section 4.1: min 43, max 128
	assert.GreaterOrEqual(t, len(verifier), 43)
	assert.LessOrEqual(t, len(verifier), 128)

	// 3. 验证字符集 (Unreserved characters: [A-Z] / [a-z] / [0-9] / "-" / "." / "_" / "~")
	// 使用 pkce.go 内部定义的正则 (需要在 pkce.go 导出 verifierRegex 或者在测试中重新定义)
	// 这里直接调用 VerifyPKCE 进行间接验证，或者重新测试正则
	assert.Regexp(t, `^[A-Za-z0-9\-\._~]+$`, verifier)
}

func TestComputePKCEChallenge_S256(t *testing.T) {
	// 使用 RFC 标准向量验证 SHA256 逻辑
	challenge, err := ComputePKCEChallenge(CodeChallengeMethodS256, rfcVerifier)
	require.NoError(t, err)
	assert.Equal(t, rfcChallenge, challenge)
}

func TestComputePKCEChallenge_Plain(t *testing.T) {
	// Plain 模式下 challenge == verifier
	challenge, err := ComputePKCEChallenge(CodeChallengeMethodPlain, rfcVerifier)
	require.NoError(t, err)
	assert.Equal(t, rfcVerifier, challenge)
}

func TestComputePKCEChallenge_Errors(t *testing.T) {
	// 空 Verifier
	_, err := ComputePKCEChallenge(CodeChallengeMethodS256, "")
	assert.ErrorIs(t, err, ErrPKCEVerifierEmpty)

	// 不支持的方法
	_, err = ComputePKCEChallenge("MD5", rfcVerifier)
	assert.ErrorIs(t, err, ErrUnsupportedPKCEChallengeMethod)
}

func TestVerifyPKCE_Success(t *testing.T) {
	// S256 成功
	err := VerifyPKCE(rfcChallenge, CodeChallengeMethodS256, rfcVerifier)
	assert.NoError(t, err)

	// Plain 成功
	err = VerifyPKCE(rfcVerifier, CodeChallengeMethodPlain, rfcVerifier)
	assert.NoError(t, err)
}

func TestVerifyPKCE_Failure(t *testing.T) {
	// S256 不匹配
	err := VerifyPKCE(rfcChallenge, CodeChallengeMethodS256, "wrong-verifier-but-valid-format-xxxxxxxxxxxxxxx")
	assert.ErrorIs(t, err, ErrPKCEVerificationFailed)

	// Plain 不匹配
	err = VerifyPKCE("expected", CodeChallengeMethodPlain, "actual-verifier-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx")
	assert.ErrorIs(t, err, ErrPKCEVerificationFailed)
}

func TestVerifyPKCE_FormatValidation(t *testing.T) {
	challenge := "irrelevant"
	method := CodeChallengeMethodS256

	tests := []struct {
		name     string
		verifier string
		wantErr  error
	}{
		{
			name:     "Too Short (< 43)",
			verifier: "short",
			wantErr:  ErrPKCEVerifierInvalidLength,
		},
		{
			name:     "Too Short Boundary (42)",
			verifier: strings.Repeat("a", 42),
			wantErr:  ErrPKCEVerifierInvalidLength,
		},
		{
			name:     "Too Long (> 128)",
			verifier: strings.Repeat("a", 129),
			wantErr:  ErrPKCEVerifierInvalidLength,
		},
		{
			name:     "Invalid Characters (Space)",
			verifier: "invalid verifier with spaces xxxxxxxxxxxxxxxxxx",
			wantErr:  ErrPKCEVerifierInvalidChars,
		},
		{
			name:     "Invalid Characters (Symbol)",
			verifier: "invalid-verifier-with-$-symbol-xxxxxxxxxxxxxxx",
			wantErr:  ErrPKCEVerifierInvalidChars,
		},
		{
			name:     "Valid Boundary (43)",
			verifier: strings.Repeat("a", 43),
			wantErr:  ErrPKCEVerificationFailed, // 格式通过，内容校验失败
		},
		{
			name:     "Valid Boundary (128)",
			verifier: strings.Repeat("a", 128),
			wantErr:  ErrPKCEVerificationFailed, // 格式通过，内容校验失败
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := VerifyPKCE(challenge, method, tt.verifier)
			assert.ErrorIs(t, err, tt.wantErr)
		})
	}
}

func TestVerifyPKCE_UnsupportedMethod(t *testing.T) {
	err := VerifyPKCE(rfcChallenge, "UNKNOWN", rfcVerifier)
	assert.ErrorIs(t, err, ErrUnsupportedPKCEChallengeMethod)
}
