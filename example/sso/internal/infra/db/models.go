package db

import (
	"time"

	"sso/internal/domain"
)

// UserGorm GORM 映射模型
type UserGorm struct {
	ID           string    `gorm:"primaryKey;type:varchar(36)"`
	Username     string    `gorm:"uniqueIndex;size:255;not null"`
	PasswordHash string    `gorm:"type:text;not null"`
	Role         string    `gorm:"size:20;default:'user'"`
	CreatedAt    time.Time `gorm:"autoCreateTime"`
	UpdatedAt    time.Time `gorm:"autoUpdateTime"`
}

// TableName 自定义表名
func (UserGorm) TableName() string {
	return "users"
}

// ToDomain 转换为领域实体
func (u *UserGorm) ToDomain() *domain.User {
	return &domain.User{
		ID:           u.ID,
		Username:     u.Username,
		PasswordHash: u.PasswordHash,
		Role:         domain.Role(u.Role),
		CreatedAt:    u.CreatedAt,
		UpdatedAt:    u.UpdatedAt,
	}
}

// FromDomainUser 从领域实体转换
func FromDomainUser(u *domain.User) *UserGorm {
	return &UserGorm{
		ID:           u.ID,
		Username:     u.Username,
		PasswordHash: u.PasswordHash,
		Role:         string(u.Role),
	}
}
