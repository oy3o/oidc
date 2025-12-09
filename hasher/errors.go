package hasher

import "errors"

// hasher errors
var (
	ErrPasswordMismatch    = errors.New("password hash does not match")
	ErrInvalidHashFormat   = errors.New("invalid argon2id hash format")
	ErrIncompatibleVersion = errors.New("incompatible argon2 version")
)
