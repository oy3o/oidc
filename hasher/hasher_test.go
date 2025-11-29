//go:build test

package hasher

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBcryptHasher(t *testing.T) {
	hasher := NewBcryptHasher(11)
	password := []byte("my-very-secret-password-123")
	ctx := context.Background()
	hashed, err := hasher.Hash(ctx, password)
	require.NoError(t, err)
	require.NotEmpty(t, hashed)

	// Test successful comparison
	err = hasher.Compare(ctx, hashed, password)
	assert.NoError(t, err, "Correct password should match")

	// Test failed comparison
	err = hasher.Compare(ctx, hashed, []byte("wrong-password"))
	assert.Error(t, err, "Incorrect password should not match")
}

func TestArgon2Hasher(t *testing.T) {
	hasher := NewArgon2Hasher(0, 0, 0, 0, 0)
	password := []byte("my-very-secret-password-123")
	ctx := context.Background()
	hashed, err := hasher.Hash(ctx, password)
	require.NoError(t, err)
	require.NotEmpty(t, hashed)

	// Test successful comparison
	err = hasher.Compare(ctx, hashed, password)
	assert.NoError(t, err, "Correct password should match")

	// Test failed comparison
	err = hasher.Compare(ctx, hashed, []byte("wrong-password"))
	assert.Error(t, err, "Incorrect password should not match")
}
