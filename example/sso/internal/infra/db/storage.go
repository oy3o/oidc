package db

import (
	"context"
	"errors"
	"fmt"

	"sso/internal/domain"

	"github.com/google/uuid"
	"github.com/oy3o/oidc"
	oidc_gorm "github.com/oy3o/oidc/gorm"
	"gorm.io/gorm"
)

// Storage 聚合存储：OIDC 标准存储 + 业务用户存储
type Storage struct {
	*oidc_gorm.GormStorage // 继承标准 OIDC 表的实现 (Clients, Tokens, etc.)
	db                     *gorm.DB
	hasher                 oidc.Hasher
}

var _ domain.UserRepository = (*Storage)(nil)

func NewStorage(db *gorm.DB, hasher oidc.Hasher) (*Storage, error) {
	// 1. 初始化标准 OIDC 存储 (自动迁移 OIDC 表)
	base := oidc_gorm.NewGormStorage(db, hasher, true)

	// 2. 迁移自定义用户表
	if err := db.AutoMigrate(&UserGorm{}); err != nil {
		return nil, err
	}

	return &Storage{
		GormStorage: base,
		db:          db,
		hasher:      hasher,
	}, nil
}

// CreateUser 创建用户 (业务方法)
func (s *Storage) CreateUser(ctx context.Context, user *domain.User) error {
	model := &UserGorm{
		ID:           user.ID,
		Username:     user.Username,
		PasswordHash: user.PasswordHash,
		Role:         string(user.Role),
	}
	return s.db.WithContext(ctx).Create(model).Error
}

// FindUserByUsername 查找用户 (业务方法)
func (s *Storage) FindUserByUsername(ctx context.Context, username string) (*domain.User, error) {
	var model UserGorm
	if err := s.db.WithContext(ctx).Where("username = ?", username).First(&model).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, err
	}
	return model.ToDomain(), nil
}

// --- 实现 oidc.UserAuthenticator 接口 ---
// 供 OIDC Server 在 Password Grant 模式下验证用户
func (s *Storage) GetUser(ctx context.Context, username, password string) (oidc.BinaryUUID, error) {
	user, err := s.FindUserByUsername(ctx, username)
	if err != nil {
		return oidc.BinaryUUID{}, err
	}
	if user == nil {
		return oidc.BinaryUUID{}, oidc.ErrUserNotFound
	}

	// 验证密码
	if err := s.hasher.Compare(ctx, []byte(user.PasswordHash), []byte(password)); err != nil {
		return oidc.BinaryUUID{}, oidc.ErrUserNotFound
	}

	// 转换 ID
	uid, err := uuid.Parse(user.ID)
	if err != nil {
		return oidc.BinaryUUID{}, fmt.Errorf("invalid user id format: %w", err)
	}
	return oidc.BinaryUUID(uid), nil
}

// --- 实现 oidc.UserInfoGetter 接口 ---
// 供 OIDC Server 生成 ID Token 或响应 /userinfo 请求
func (s *Storage) GetUserInfo(ctx context.Context, id oidc.BinaryUUID, scopes []string) (*oidc.UserInfo, error) {
	var model UserGorm
	if err := s.db.WithContext(ctx).First(&model, "id = ?", id.String()).Error; err != nil {
		return nil, oidc.ErrUserNotFound
	}

	// 构造标准 UserInfo
	info := &oidc.UserInfo{
		Subject:           model.ID,
		PreferredUsername: &model.Username,
		UpdatedAt:         model.UpdatedAt.Unix(),
	}

	// 简单的 Scope 控制 (实际项目中应更精细)
	name := model.Username
	info.Name = &name
	// 如果表里有 email/phone，可以在这里根据 scopes 填充

	return info, nil
}
