package db

import (
	"context"
	"errors"

	"sso/internal/domain"

	"github.com/oy3o/oidc"
	"gorm.io/gorm"
)

type UserRepository struct {
	db     *gorm.DB
	hasher oidc.Hasher
}

func NewUserRepository(db *gorm.DB, hasher oidc.Hasher) *UserRepository {
	return &UserRepository{
		db:     db,
		hasher: hasher,
	}
}

// --- Domain Interface Implementation ---

func (r *UserRepository) Create(ctx context.Context, user *domain.User) error {
	model := FromDomainUser(user)
	return r.db.WithContext(ctx).Create(model).Error
}

func (r *UserRepository) FindByUsername(ctx context.Context, username string) (*domain.User, error) {
	var model UserGorm
	if err := r.db.WithContext(ctx).Where("username = ?", username).First(&model).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil // domain层通常期望 nil, nil 或特定的 ErrNotFound
		}
		return nil, err
	}
	return model.ToDomain(), nil
}

func (r *UserRepository) FindByID(ctx context.Context, id string) (*domain.User, error) {
	var model UserGorm
	if err := r.db.WithContext(ctx).First(&model, "id = ?", id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, err
	}
	return model.ToDomain(), nil
}

// --- OIDC Interface Implementation (Partial) ---

// VerifyPassword 是 OIDC GetUser 的核心逻辑
func (r *UserRepository) VerifyPassword(ctx context.Context, username, password string) (string, error) {
	user, err := r.FindByUsername(ctx, username)
	if err != nil {
		return "", err
	}
	if user == nil {
		return "", oidc.ErrUserNotFound
	}

	// 使用 oidc.Hasher 验证密码
	if err := r.hasher.Compare(ctx, []byte(user.PasswordHash), []byte(password)); err != nil {
		return "", oidc.ErrUserNotFound // 即使密码错误也返回 NotFound 防止枚举
	}

	return user.ID, nil
}
