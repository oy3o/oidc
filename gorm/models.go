package gorm

import (
	"context"
	"errors"
	"time"

	"github.com/bytedance/sonic"
	"github.com/oy3o/oidc"
)

// ClientModel 对应 oidc.RegisteredClient
type ClientModel struct {
	ID                      oidc.BinaryUUID `gorm:"column:id;primaryKey"`
	OwnerID                 oidc.BinaryUUID `gorm:"column:owner_id;index"`
	Secret                  string          `gorm:"column:secret;type:text"`        // 存储哈希后的 Secret
	RedirectURIs            StringSlice     `gorm:"column:redirect_uris;type:text"` // JSON
	GrantTypes              StringSlice     `gorm:"column:grant_types;type:text"`   // JSON
	Scope                   string          `gorm:"column:scope;type:text"`
	Name                    string          `gorm:"column:name;type:varchar(255)"`
	LogoURI                 string          `gorm:"column:logo_uri;type:text"`
	TokenEndpointAuthMethod string          `gorm:"column:token_endpoint_auth_method;type:varchar(50)"`
	IsConfidentialClient    bool            `gorm:"column:is_confidential_client"`
	CreatedAt               time.Time       `gorm:"column:created_at"`
	UpdatedAt               time.Time       `gorm:"column:updated_at"`
}

// 实现 RegisteredClient 接口
func (c *ClientModel) GetID() oidc.BinaryUUID    { return c.ID }
func (c *ClientModel) GetRedirectURIs() []string { return c.RedirectURIs }
func (c *ClientModel) GetGrantTypes() []string   { return c.GrantTypes }
func (c *ClientModel) GetScope() string          { return c.Scope }
func (c *ClientModel) IsConfidential() bool      { return c.IsConfidentialClient }
func (c *ClientModel) TableName() string         { return "oidc_clients" }
func (c *ClientModel) Serialize() (string, error) {
	b, err := sonic.ConfigDefault.Marshal(c)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func (c *ClientModel) Deserialize(data string) error {
	return sonic.ConfigDefault.Unmarshal([]byte(data), c)
}

// ValidateSecret 需要 hasher 协助，这里只提供数据，逻辑在 Server 层或 Storage 方法中
// 为了满足接口，我们在 Storage 实现中处理，这里仅作占位
func (c *ClientModel) ValidateSecret(ctx context.Context, hasher oidc.Hasher, secret string) error {
	// 如果是 Public Client，无需验证
	if !c.IsConfidentialClient {
		return nil
	}
	if hasher == nil {
		return errors.New("hasher not configured in storage")
	}
	return hasher.Compare(ctx, []byte(c.Secret), []byte(secret))
}

// AuthCodeModel 对应 oidc.AuthCodeSession
type AuthCodeModel struct {
	Code                string          `gorm:"column:code;primaryKey;size:128"`
	ClientID            oidc.BinaryUUID `gorm:"column:client_id;index"`
	UserID              oidc.BinaryUUID `gorm:"column:user_id;index"`
	Scope               string          `gorm:"column:scope;type:text"`
	Nonce               string          `gorm:"column:nonce;type:varchar(255)"`
	RedirectURI         string          `gorm:"column:redirect_uri;type:text"`
	CodeChallenge       string          `gorm:"column:code_challenge;type:varchar(255)"`
	CodeChallengeMethod string          `gorm:"column:code_challenge_method;type:varchar(20)"`
	AuthTime            time.Time       `gorm:"column:auth_time"`
	ExpiresAt           time.Time       `gorm:"column:expires_at;index"`
	ACR                 string          `gorm:"column:acr"`
	AMR                 StringSlice     `gorm:"column:amr;type:text"`
}

func (AuthCodeModel) TableName() string { return "oidc_auth_codes" }

// RefreshTokenModel 对应 oidc.RefreshTokenSession
type RefreshTokenModel struct {
	ID        oidc.Hash256    `gorm:"column:id;primaryKey"`
	ClientID  oidc.BinaryUUID `gorm:"column:client_id;index"`
	UserID    oidc.BinaryUUID `gorm:"column:user_id;index"`
	Scope     string          `gorm:"column:scope;type:text"`
	Nonce     string          `gorm:"column:nonce;type:varchar(255)"`
	AuthTime  time.Time       `gorm:"column:auth_time"`
	ExpiresAt time.Time       `gorm:"column:expires_at;index"`
	ACR       string          `gorm:"column:acr"`
	AMR       StringSlice     `gorm:"column:amr;type:text"`
}

func (RefreshTokenModel) TableName() string { return "oidc_refresh_tokens" }

// BlacklistModel 用于撤销 Access Token
type BlacklistModel struct {
	JTI       string    `gorm:"column:jti;primaryKey;size:64"`
	ExpiresAt time.Time `gorm:"column:expires_at;index"`
}

func (BlacklistModel) TableName() string { return "oidc_token_blacklist" }

// DeviceCodeModel 对应 oidc.DeviceCodeSession
type DeviceCodeModel struct {
	DeviceCode      string          `gorm:"column:device_code;primaryKey;size:128"`
	UserCode        string          `gorm:"column:user_code;index;size:20"`
	ClientID        oidc.BinaryUUID `gorm:"column:client_id"`
	UserID          oidc.BinaryUUID `gorm:"column:user_id"`
	Scope           string          `gorm:"column:scope;type:text"`
	AuthorizedScope string          `gorm:"column:authorized_scope;type:text"`
	Status          string          `gorm:"column:status;type:varchar(20)"` // pending, allowed, denied
	ExpiresAt       time.Time       `gorm:"column:expires_at;index"`
	LastPolled      time.Time       `gorm:"column:last_polled"`
}

func (DeviceCodeModel) TableName() string { return "oidc_device_codes" }

// UserModel 一个基础的用户表实现
type UserModel struct {
	ID                  oidc.BinaryUUID `gorm:"column:id;primaryKey"`
	Username            string          `gorm:"column:username;uniqueIndex;size:100"`
	PasswordHash        string          `gorm:"column:password_hash;type:varchar(255)"`
	Name                string          `gorm:"column:name"`
	Email               string          `gorm:"column:email"`
	EmailVerified       bool            `gorm:"column:email_verified"`
	PhoneNumber         string          `gorm:"column:phone_number"`
	PhoneNumberVerified bool            `gorm:"column:phone_number_verified"`
	Picture             string          `gorm:"column:picture"`
	Profile             string          `gorm:"column:profile"`
	Website             string          `gorm:"column:website"`
	UpdatedAt           time.Time       `gorm:"column:updated_at"`
}

func (UserModel) TableName() string { return "users" }

// PARModel 对应 PAR (Pushed Authorization Request) 会话
// RFC 9126: OAuth 2.0 Pushed Authorization Requests
type PARModel struct {
	RequestURI string    `gorm:"column:request_uri;primaryKey;size:128"`
	Request    string    `gorm:"column:request;type:text"` // JSON 序列化的 AuthorizeRequest
	ExpiresAt  time.Time `gorm:"column:expires_at;index"`
}

func (PARModel) TableName() string { return "oidc_par_sessions" }

// KeyModel 对应 JWK (JSON Web Key) 存储
type KeyModel struct {
	KID       string    `gorm:"column:kid;primaryKey;size:128"`
	JWK       string    `gorm:"column:jwk;type:text"` // JSON 序列化的 JWK (包含私钥)
	CreatedAt time.Time `gorm:"column:created_at"`
}

func (KeyModel) TableName() string { return "oidc_keys" }

// LockModel 对应分布式锁
type LockModel struct {
	LockKey   string    `gorm:"column:lock_key;primaryKey;size:128"`
	ExpiresAt time.Time `gorm:"column:expires_at;index"`
	CreatedAt time.Time `gorm:"column:created_at"`
}

func (LockModel) TableName() string { return "oidc_locks" }
