package persist

import "errors"

// persist errors
var (
	ErrUserNotFound                     = errors.New("user not found")
	ErrCredentialNotFound               = errors.New("credential not found")
	ErrIdentifierExists                 = errors.New("identifier already exists")
	ErrConfidentialClientSecretRequired = errors.New("confidential client requires a hashed secret")
)
