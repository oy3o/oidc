package cache

import "errors"

// cache errors
var (
	ErrAuthCodeExpired    = errors.New("auth code already expired")
	ErrDeviceCodeExpired  = errors.New("device code expired")
	ErrInvalidDataType    = errors.New("invalid data type in redis")
	ErrPARSessionExpired  = errors.New("PAR session expired")
	ErrPARSessionNotFound = errors.New("PAR session not found or expired")
)
