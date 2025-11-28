package oidc_test

import (
	"testing"

	"github.com/oy3o/oidc"
	"github.com/stretchr/testify/assert"
)

func TestValidateScopes_ExactMatch(t *testing.T) {
	allowed := "openid profile email"
	requested := "openid profile"

	err := oidc.ValidateScopes(allowed, requested)
	assert.NoError(t, err)
}

func TestValidateScopes_Wildcard(t *testing.T) {
	allowed := "openid scope:read:* scope:write:users"
	requested := "openid scope:read:users scope:read:orders"

	err := oidc.ValidateScopes(allowed, requested)
	assert.NoError(t, err)
}

func TestValidateScopes_WildcardMismatch(t *testing.T) {
	allowed := "openid scope:read:*"
	requested := "openid scope:write:users"

	err := oidc.ValidateScopes(allowed, requested)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "scope:write:users")
}

func TestValidateScopes_AllWildcard(t *testing.T) {
	allowed := "*"
	requested := "openid profile email any:scope:here"

	err := oidc.ValidateScopes(allowed, requested)
	assert.NoError(t, err)
}

func TestValidateScopes_Empty(t *testing.T) {
	allowed := "openid profile"
	requested := ""

	err := oidc.ValidateScopes(allowed, requested)
	assert.NoError(t, err)
}
