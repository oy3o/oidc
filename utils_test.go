package oidc

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

func TestParseUUID(t *testing.T) {
	validUUID := uuid.New().String()
	invalidUUID := "not-a-uuid"

	t.Run("Valid UUID", func(t *testing.T) {
		id, err := ParseUUID(validUUID)
		assert.NoError(t, err)
		assert.Equal(t, validUUID, id.String())
	})

	t.Run("Invalid UUID", func(t *testing.T) {
		_, err := ParseUUID(invalidUUID)
		assert.Error(t, err)
	})

	t.Run("Empty UUID", func(t *testing.T) {
		_, err := ParseUUID("")
		assert.Error(t, err)
	})
}

func TestRandomString(t *testing.T) {
	lengths := []int{16, 32, 64}

	for _, n := range lengths {
		s, err := RandomString(n)
		assert.NoError(t, err)
		assert.NotEmpty(t, s)
	}

	t.Run("Different calls produce different strings", func(t *testing.T) {
		s1, _ := RandomString(32)
		s2, _ := RandomString(32)
		assert.NotEqual(t, s1, s2)
	})
}

func TestDecodeJSON(t *testing.T) {
	t.Run("Large integers with UseNumber", func(t *testing.T) {
		// 2^53 + 1 is the first integer that cannot be represented exactly as float64
		input := `{"large_int": 9007199254740993}`
		var result map[string]any
		err := DecodeJSON(strings.NewReader(input), &result)
		assert.NoError(t, err)

		val, ok := result["large_int"].(json.Number)
		assert.True(t, ok, "expected json.Number, got %T", result["large_int"])
		assert.Equal(t, "9007199254740993", val.String())
	})

	t.Run("Normal JSON", func(t *testing.T) {
		input := `{"foo": "bar", "num": 123}`
		var result struct {
			Foo string `json:"foo"`
			Num int    `json:"num"`
		}
		err := DecodeJSON(strings.NewReader(input), &result)
		assert.NoError(t, err)
		assert.Equal(t, "bar", result.Foo)
		assert.Equal(t, 123, result.Num)
	})

	t.Run("Invalid JSON", func(t *testing.T) {
		input := `{"foo":`
		var result map[string]any
		err := DecodeJSON(strings.NewReader(input), &result)
		assert.Error(t, err)
	})
}
