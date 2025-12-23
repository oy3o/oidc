package persist

import (
	"context"

	"github.com/oy3o/oidc"
)

// UserManager 处理核心用户实体的生命周期
type UserManager interface {
	// UserCreate 创建完整用户聚合根（包含凭证和资料）
	UserCreate(ctx context.Context, user *User, credentials []*Credential, profile *Profile) error
	UserDelete(ctx context.Context, id oidc.BinaryUUID) error
	UserGetByID(ctx context.Context, id oidc.BinaryUUID) (*User, error)
	UserUpdateStatus(ctx context.Context, id oidc.BinaryUUID, status UserStatus) error
	UserList(ctx context.Context, limit, offset int, query string) ([]*Profile, int64, error)
	UserGetInfoByID(ctx context.Context, userID oidc.BinaryUUID, scopes []string) (*oidc.UserInfo, error)
}

// CredentialManager 处理具体的认证凭据（如密码、WebAuthn 凭证等）
// 注意：这通常用于用户管理后台，而非登录流程
type CredentialManager interface {
	CredentialCreate(ctx context.Context, cred *Credential) error
	CredentialUpdate(ctx context.Context, cred *Credential) error
	CredentialDeleteByID(ctx context.Context, credID uint64) error
	CredentialGetByIdentifier(ctx context.Context, idenType IdenType, identifier string) (*Credential, error)
}

// ProfileManager 处理用户扩展资料
type ProfileManager interface {
	ProfileGetByUserID(ctx context.Context, userID oidc.BinaryUUID) (*Profile, error)
	ProfileUpdate(ctx context.Context, profile *Profile) error
	ProfileMarkVerified(ctx context.Context, userID oidc.BinaryUUID, identifier string) error
}

// ---------------------------------------------------------
// 聚合接口定义 (服务层依赖)
// ---------------------------------------------------------

// UserExtend 包含完整的用户管理能力。
type UserExtend interface {
	UserManager
	ProfileManager
	CredentialManager
}
