package httpx

import "errors"

// httpx errors
var (
	ErrIdentityNotFound     = errors.New("identity not found in context")
	ErrIdentityTypeMismatch = errors.New("identity type mismatch")
)
