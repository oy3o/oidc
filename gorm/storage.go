package gorm

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/bytedance/sonic"
	"github.com/google/uuid"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/oy3o/oidc"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

type GormStorage struct {
	db     *gorm.DB
	hasher oidc.Hasher
}

var _ oidc.Persistence = (*GormStorage)(nil)

// NewGormStorage 创建实例并自动迁移 schema
// 需要传入 hasher 用于用户密码验证和 Client Secret 验证
func NewGormStorage(db *gorm.DB, hasher oidc.Hasher, autoMigrate bool) *GormStorage {
	// 自动迁移表结构
	if autoMigrate {
		_ = db.AutoMigrate(
			&ClientModel{},
			&AuthCodeModel{},
			&RefreshTokenModel{},
			&BlacklistModel{},
			&DeviceCodeModel{},
			&UserModel{},
			&PARModel{},
			&KeyModel{},
			&LockModel{},
		)
	}
	return &GormStorage{
		db:     db,
		hasher: hasher,
	}
}

// --- ClientStorage Implementation ---

func (s *GormStorage) GetClient(ctx context.Context, clientID oidc.BinaryUUID) (oidc.RegisteredClient, error) {
	var model ClientModel
	if err := s.db.WithContext(ctx).First(&model, "id = ?", clientID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, oidc.ErrClientNotFound
		}
		return nil, err
	}
	return &model, nil
}

func (s *GormStorage) CreateClient(ctx context.Context, metadata oidc.ClientMetadata) (oidc.RegisteredClient, error) {
	// [安全] Service 层应该负责确保 Secret 已被正确哈希
	if metadata.IsConfidential {
		if len(metadata.Secret) == 0 {
			return nil, fmt.Errorf("confidential client requires a hashed secret")
		}
	}

	model := ClientModel{
		ID:                      metadata.ID,
		OwnerID:                 metadata.OwnerID,
		Secret:                  string(metadata.Secret), // 已确认是哈希后的
		RedirectURIs:            metadata.RedirectURIs,
		GrantTypes:              metadata.GrantTypes,
		Scope:                   metadata.Scope,
		Name:                    metadata.Name,
		LogoURI:                 metadata.LogoURI,
		TokenEndpointAuthMethod: metadata.TokenEndpointAuthMethod,
		IsConfidentialClient:    metadata.IsConfidential,
		CreatedAt:               metadata.CreatedAt,
		UpdatedAt:               time.Now(),
	}

	if err := s.db.WithContext(ctx).Create(&model).Error; err != nil {
		return nil, err
	}
	return &model, nil
}

func (s *GormStorage) UpdateClient(ctx context.Context, clientID oidc.BinaryUUID, metadata oidc.ClientMetadata) (oidc.RegisteredClient, error) {
	var model ClientModel
	if err := s.db.WithContext(ctx).First(&model, "id = ?", clientID).Error; err != nil {
		return nil, oidc.ErrClientNotFound
	}

	// 更新字段
	model.RedirectURIs = metadata.RedirectURIs
	model.GrantTypes = metadata.GrantTypes
	model.Scope = metadata.Scope
	model.Name = metadata.Name
	model.LogoURI = metadata.LogoURI
	model.TokenEndpointAuthMethod = metadata.TokenEndpointAuthMethod
	model.IsConfidentialClient = metadata.IsConfidential
	model.UpdatedAt = time.Now()

	// 只有当 Secret 确实更改时才更新 (通常 update metadata 不应该重置 secret)
	if metadata.Secret != "" {
		model.Secret = string(metadata.Secret)
	}

	if err := s.db.WithContext(ctx).Save(&model).Error; err != nil {
		return nil, err
	}
	return &model, nil
}

func (s *GormStorage) DeleteClient(ctx context.Context, clientID oidc.BinaryUUID) error {
	return s.db.WithContext(ctx).Delete(&ClientModel{}, "id = ?", clientID).Error
}

func (s *GormStorage) ListClientsByOwner(ctx context.Context, ownerID oidc.BinaryUUID) ([]oidc.RegisteredClient, error) {
	var models []ClientModel
	if err := s.db.WithContext(ctx).Where("owner_id = ?", ownerID).Find(&models).Error; err != nil {
		return nil, err
	}
	clients := make([]oidc.RegisteredClient, len(models))
	for i := range models {
		clients[i] = &models[i]
	}
	return clients, nil
}

func (s *GormStorage) ListClients(ctx context.Context, query oidc.ListQuery) ([]oidc.RegisteredClient, error) {
	var models []ClientModel
	db := s.db.WithContext(ctx).Preload("oidc_clients")
	if query.Limit > 0 {
		db = db.Limit(query.Limit)
	}
	if query.Offset > 0 {
		db = db.Offset(query.Offset)
	}
	if err := db.Order("id ASC").Find(&models).Error; err != nil {
		return nil, err
	}
	clients := make([]oidc.RegisteredClient, len(models))
	for i := range models {
		clients[i] = &models[i]
	}
	return clients, nil
}

// --- KeyStorage Implementation ---

// Save 存储 JWK
func (s *GormStorage) Save(ctx context.Context, key jwk.Key) error {
	if key.KeyID() == "" {
		return errors.New("key must have a kid")
	}

	// 序列化为 JSON (包含私钥)
	data, err := sonic.Marshal(key)
	if err != nil {
		return fmt.Errorf("failed to marshal JWK: %w", err)
	}

	model := KeyModel{
		KID:       key.KeyID(),
		JWK:       string(data),
		CreatedAt: time.Now(),
	}

	// 使用 Clauses 确保如果 key 已存在则更新
	return s.db.WithContext(ctx).Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "kid"}},
		DoUpdates: clause.AssignmentColumns([]string{"jwk"}),
	}).Create(&model).Error
}

// Get 获取 JWK
func (s *GormStorage) Get(ctx context.Context, kid string) (jwk.Key, error) {
	var model KeyModel
	if err := s.db.WithContext(ctx).First(&model, "kid = ?", kid).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, oidc.ErrKeyNotFound
		}
		return nil, err
	}

	key, err := jwk.ParseKey([]byte(model.JWK))
	if err != nil {
		return nil, fmt.Errorf("failed to parse JWK from database: %w", err)
	}
	return key, nil
}

// List 获取所有 JWK
func (s *GormStorage) List(ctx context.Context) ([]jwk.Key, error) {
	var models []KeyModel
	if err := s.db.WithContext(ctx).Find(&models).Error; err != nil {
		return nil, err
	}

	keys := make([]jwk.Key, 0, len(models))
	for _, model := range models {
		key, err := jwk.ParseKey([]byte(model.JWK))
		if err != nil {
			// 忽略损坏的 key 或记录日志
			continue
		}
		keys = append(keys, key)
	}
	return keys, nil
}

// Delete 删除 JWK
func (s *GormStorage) Delete(ctx context.Context, kid string) error {
	return s.db.WithContext(ctx).Delete(&KeyModel{}, "kid = ?", kid).Error
}

// SaveSigningKeyID 存储当前签名密钥 ID
// 使用特殊的 KID "__signing_key__" 来存储
func (s *GormStorage) SaveSigningKeyID(ctx context.Context, kid string) error {
	const signingKeyMarker = "__signing_key__"

	model := KeyModel{
		KID:       signingKeyMarker,
		JWK:       kid,
		CreatedAt: time.Now(),
	}

	return s.db.WithContext(ctx).Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "kid"}},
		DoUpdates: clause.AssignmentColumns([]string{"jwk"}),
	}).Create(&model).Error
}

// GetSigningKeyID 获取当前签名密钥 ID
func (s *GormStorage) GetSigningKeyID(ctx context.Context) (string, error) {
	const signingKeyMarker = "__signing_key__"

	var model KeyModel
	if err := s.db.WithContext(ctx).First(&model, "kid = ?", signingKeyMarker).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return "", oidc.ErrKeyNotFound
		}
		return "", err
	}
	return model.JWK, nil
}

// --- TokenStorage Implementation ---

func (s *GormStorage) CreateRefreshToken(ctx context.Context, session *oidc.RefreshTokenSession) error {
	model := RefreshTokenModel{
		ID:        session.ID,
		ClientID:  session.ClientID,
		UserID:    session.UserID,
		Scope:     session.Scope,
		Nonce:     session.Nonce,
		AuthTime:  session.AuthTime,
		ExpiresAt: session.ExpiresAt,
		ACR:       session.ACR,
		AMR:       session.AMR,
	}
	return s.db.WithContext(ctx).Create(&model).Error
}

func (s *GormStorage) GetRefreshToken(ctx context.Context, tokenID oidc.Hash256) (*oidc.RefreshTokenSession, error) {
	var model RefreshTokenModel
	if err := s.db.WithContext(ctx).First(&model, "id = ?", tokenID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, oidc.ErrTokenNotFound
		}
		return nil, err
	}

	if time.Now().After(model.ExpiresAt) {
		// 懒惰删除
		_ = s.RevokeRefreshToken(ctx, tokenID)
		return nil, oidc.ErrTokenNotFound
	}

	return &oidc.RefreshTokenSession{
		ID:        model.ID,
		ClientID:  model.ClientID,
		UserID:    model.UserID,
		Scope:     model.Scope,
		AuthTime:  model.AuthTime,
		ExpiresAt: model.ExpiresAt,
		Nonce:     model.Nonce,
		ACR:       model.ACR,
		AMR:       model.AMR,
	}, nil
}

func (s *GormStorage) RotateRefreshToken(ctx context.Context, oldTokenID oidc.Hash256, newSession *oidc.RefreshTokenSession) error {
	return s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		// 删除旧的
		if err := tx.Delete(&RefreshTokenModel{}, "id = ?", oldTokenID).Error; err != nil {
			return err
		}

		// 创建新的
		newModel := RefreshTokenModel{
			ID:        newSession.ID,
			ClientID:  newSession.ClientID,
			UserID:    newSession.UserID,
			Scope:     newSession.Scope,
			Nonce:     newSession.Nonce,
			AuthTime:  newSession.AuthTime,
			ExpiresAt: newSession.ExpiresAt,
			ACR:       newSession.ACR,
			AMR:       newSession.AMR,
		}
		return tx.Create(&newModel).Error
	})
}

func (s *GormStorage) RevokeRefreshToken(ctx context.Context, tokenID oidc.Hash256) error {
	return s.db.WithContext(ctx).Delete(&RefreshTokenModel{}, "id = ?", tokenID).Error
}

func (s *GormStorage) RevokeTokensForUser(ctx context.Context, userID oidc.BinaryUUID) ([]oidc.Hash256, error) {
	var tokens []RefreshTokenModel

	// 使用 Clauses(clause.Returning{})
	err := s.db.WithContext(ctx).
		Clauses(clause.Returning{Columns: []clause.Column{{Name: "id"}}}). // 只返回 ID
		Where("user_id = ?", userID).
		Delete(&tokens).Error
	if err != nil {
		return nil, err
	}

	var ids []oidc.Hash256
	for _, t := range tokens {
		ids = append(ids, t.ID)
	}

	return ids, nil
}

// --- UserInfoGetter & UserAuthenticator Implementation ---

func (s *GormStorage) GetUserInfo(ctx context.Context, userID oidc.BinaryUUID, scopes []string) (*oidc.UserInfo, error) {
	var user UserModel
	if err := s.db.WithContext(ctx).First(&user, "id = ?", userID).Error; err != nil {
		return nil, oidc.ErrUserNotFound
	}

	info := &oidc.UserInfo{
		Subject:   user.ID.String(),
		UpdatedAt: user.UpdatedAt.Unix(),
	}

	// 简单的 Scope 过滤逻辑
	// 在实际生产中，可能需要更精细的字段级控制
	scopeSet := make(map[string]struct{})
	for _, sc := range scopes {
		scopeSet[sc] = struct{}{}
	}

	if _, ok := scopeSet["profile"]; ok {
		info.Name = &user.Name
		info.PreferredUsername = &user.Username
		info.Profile = &user.Profile
		info.Picture = &user.Picture
		info.Website = &user.Website
	}
	if _, ok := scopeSet["email"]; ok {
		info.Email = &user.Email
		info.EmailVerified = &user.EmailVerified
	}
	if _, ok := scopeSet["phone"]; ok {
		info.PhoneNumber = &user.PhoneNumber
		info.PhoneNumberVerified = &user.PhoneNumberVerified
	}

	return info, nil
}

func (s *GormStorage) GetUser(ctx context.Context, username, password string) (oidc.BinaryUUID, error) {
	var user UserModel
	if err := s.db.WithContext(ctx).First(&user, "username = ?", username).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return oidc.BinaryUUID{}, oidc.ErrUserNotFound
		}
		return oidc.BinaryUUID{}, err
	}

	// 验证密码
	// 使用注入的 Hasher 进行验证
	if s.hasher == nil {
		return oidc.BinaryUUID{}, errors.New("hasher not configured for password verification")
	}

	if err := s.hasher.Compare(ctx, []byte(user.PasswordHash), []byte(password)); err != nil {
		// 密码错误统一返回 UserNotFound 或 InvalidGrant，防止枚举
		return oidc.BinaryUUID{}, oidc.ErrUserNotFound
	}

	return user.ID, nil
}

func (s *GormStorage) CreateUserInfo(ctx context.Context, userInfo *oidc.UserInfo) error {
	model := &UserModel{}
	id, err := uuid.Parse(userInfo.Subject)
	if err != nil {
		return err
	}
	model.ID = oidc.BinaryUUID(id)
	if userInfo.Name != nil {
		model.Username = *userInfo.Name
	}
	if userInfo.Name != nil {
		model.Name = *userInfo.Name
	}
	if userInfo.Email != nil {
		model.Email = *userInfo.Email
	}
	if userInfo.PhoneNumber != nil {
		model.PhoneNumber = *userInfo.PhoneNumber
	}
	if userInfo.Picture != nil {
		model.Picture = *userInfo.Picture
	}
	if userInfo.Website != nil {
		model.Website = *userInfo.Website
	}
	if userInfo.Profile != nil {
		model.Profile = *userInfo.Profile
	}
	if userInfo.EmailVerified != nil {
		model.EmailVerified = *userInfo.EmailVerified
	}
	if userInfo.PhoneNumberVerified != nil {
		model.PhoneNumberVerified = *userInfo.PhoneNumberVerified
	}
	return s.db.WithContext(ctx).Create(model).Error
}
