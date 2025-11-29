package oidc_test

import (
	"context"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/oy3o/oidc"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestUserInfo_ScopeFiltering(t *testing.T) {
	server, storage, _ := setupSessionTest(t) // 复用 session_test.go 的 setup
	ctx := context.Background()
	userID := oidc.BinaryUUID(uuid.New())

	name := "Test User"
	email := "test@example.com"
	storage.CreateUserInfo(ctx, &oidc.UserInfo{
		Subject: userID.String(),
		Name:    &name,
		Email:   &email,
	})

	// 辅助函数：生成 Token 并调用 UserInfo
	getUserInfoWithScope := func(scope string) *oidc.UserInfo {
		// 伪造一个带有特定 scope 的 Access Token
		// 注意：这里直接生成 Access Token，跳过完整的 Issue 流程
		claims := &oidc.AccessTokenClaims{
			RegisteredClaims: jwt.RegisteredClaims{
				Issuer:    server.Issuer().Issuer(),
				Subject:   userID.String(),
				Audience:  []string{"client-id"},
				ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
			},
			Scope:           scope,
			AuthorizedParty: "client-id",
		}

		// 调用 GetUserInfo
		info, err := server.GetUserInfo(ctx, claims)
		require.NoError(t, err)
		return info
	}

	// Case 1: 只有 openid -> 只返回 sub
	info1 := getUserInfoWithScope("openid")
	assert.Equal(t, userID.String(), info1.Subject)
	assert.Nil(t, info1.Name)
	assert.Nil(t, info1.Email)

	// Case 2: openid profile -> 返回 sub + name
	info2 := getUserInfoWithScope("openid profile")
	assert.Equal(t, userID.String(), info2.Subject)
	assert.NotNil(t, info2.Name)
	assert.Equal(t, "Test User", *info2.Name)
	assert.Nil(t, info2.Email) // 没有 email scope

	// Case 3: openid email -> 返回 sub + email
	info3 := getUserInfoWithScope("openid email")
	assert.Equal(t, userID.String(), info3.Subject)
	assert.Nil(t, info3.Name) // 没有 profile scope
	assert.NotNil(t, info3.Email)
	assert.Equal(t, "test@example.com", *info3.Email)
}
