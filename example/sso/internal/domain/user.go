package domain

import (
	"context"
	"time"

	"github.com/oy3o/oidc"
)

// Role 定义用户角色
type Role string

const (
	RoleUser  Role = "user"
	RoleAdmin Role = "admin"
)

// User 核心用户实体
type User struct {
	ID           string
	Username     string
	PasswordHash string
	Role         Role
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

// IsAdmin 检查是否为管理员
func (u *User) IsAdmin() bool {
	return u.Role == RoleAdmin
}

// UserRepository 用户仓储接口
type UserRepository interface {
	// Create 创建新用户
	CreateUser(ctx context.Context, user *User) error
	// FindByUsername 根据用户名查找用户
	FindUserByUsername(ctx context.Context, username string) (*User, error)

	// oidc 接口要求
	GetUser(ctx context.Context, username, password string) (oidc.BinaryUUID, error)
	GetUserInfo(ctx context.Context, id oidc.BinaryUUID, scopes []string) (*oidc.UserInfo, error)
}
