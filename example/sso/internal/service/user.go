package service

import (
	"context"
	"fmt"
	"time"

	"sso/internal/domain"
	"sso/internal/infra/db"

	"github.com/google/uuid"
	"github.com/oy3o/oidc"
)

type UserService struct {
	storage *db.Storage
	hasher  oidc.Hasher
}

func NewUserService(storage *db.Storage, hasher oidc.Hasher) *UserService {
	return &UserService{storage: storage, hasher: hasher}
}

func (s *UserService) Register(ctx context.Context, username, password string) (*domain.User, error) {
	// 1. Check exist
	exist, err := s.storage.FindUserByUsername(ctx, username)
	if err != nil {
		return nil, err
	}
	if exist != nil {
		return nil, fmt.Errorf("username exists")
	}

	// 2. Hash password
	hashed, err := s.hasher.Hash(ctx, []byte(password))
	if err != nil {
		return nil, err
	}

	// 3. Create
	user := &domain.User{
		ID:           uuid.New().String(),
		Username:     username,
		PasswordHash: string(hashed),
		Role:         domain.RoleUser,
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}

	if err := s.storage.CreateUser(ctx, user); err != nil {
		return nil, err
	}
	return user, nil
}
