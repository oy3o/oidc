package persist

import (
	"encoding/json"
	"slices"
	"time"

	"github.com/bytedance/sonic"
	"github.com/oy3o/oidc"
)

// User 是核心的用户领域模型。
// 它代表了一个用户在系统中的核心身份，不包含任何认证或个人资料细节。
type User struct {
	// 1. ID: 使用标准 uuid 包
	// default:gen_random_uuid() 是 Postgres 的写法，让数据库负责生成 ID
	ID oidc.BinaryUUID `db:"id"`

	// 2. 角色与状态:
	// 建议加索引，因为经常需要查询 "所有管理员" 或 "所有封禁用户"
	// 使用 not null 和 default 保证数据完整性
	Role   UserRole   `db:"role"`
	Status UserStatus `db:"status"`

	// 3. 最后登录时间: 必须改为指针 *time.Time
	// 原因：用户刚注册时从未登录。
	// - 如果用 time.Time，数据库存的是 0001-01-01，查询出来不仅丑陋，而且在某些语言/前端解析时会报错。
	// - 如果用 *time.Time，数据库存 NULL，业务逻辑判断 if user.LastLoginAt == nil 即可。
	LastLoginAt *time.Time `db:"last_login_at"`

	// 4. 审计时间
	CreatedAt time.Time `db:"created_at"`
	UpdatedAt time.Time `db:"updated_at"`
}

func (User) TableName() string {
	return "users"
}

type UserRole string

const (
	RoleAdmin UserRole = "admin"
	RoleUser  UserRole = "user"
	RoleGuest UserRole = "guest"
)

// 校验方法（用于 API 接收参数后的验证）
func (r UserRole) IsValid() bool {
	switch r {
	case RoleAdmin, RoleUser, RoleGuest:
		return true
	}
	return false
}

type UserStatus string

const (
	StatusPending     UserStatus = "pending"
	StatusActive      UserStatus = "active"
	StatusSuspended   UserStatus = "suspended"
	StatusDeactivated UserStatus = "deactivated"
)

func (u *User) IsAdmin() bool {
	return u.Role == RoleAdmin
}

func (u *User) IsUser() bool {
	return u.Role == RoleUser
}

func (u *User) IsActive() bool {
	return u.Status == StatusActive
}

func (u *User) IsPending() bool {
	return u.Status == StatusPending
}

func (u *User) IsNormal() bool {
	return u.Status == StatusActive || u.Status == StatusPending
}

type Profile struct {
	// 1. 主键与 UUID
	// 移除了 gorm:"..."，合并入 db 标签
	// 如果你的字段名不是 ID，必须指定 primaryKey
	UserID oidc.BinaryUUID `db:"user_id" json:"sub"`

	// 2. 普通文本字段
	// 数据库层面设置 NOT NULL DEFAULT ''，防止 NULL
	// db:"type:varchar(100);not null;default:''" 既定义了类型也定义了约束
	Name              string `db:"name" json:"name,omitempty"`
	GivenName         string `db:"given_name" json:"given_name,omitempty"`
	FamilyName        string `db:"family_name" json:"family_name,omitempty"`
	Nickname          string `db:"nickname" json:"nickname,omitempty"`
	PreferredUsername string `db:"preferred_username" json:"preferred_username,omitempty"`
	Profile           string `db:"profile" json:"profile,omitempty"`
	Picture           string `db:"picture" json:"picture,omitempty"`
	Website           string `db:"website" json:"website,omitempty"`

	// 3. 唯一索引与指针类型
	// Email 必须是指针，因为数据库 Unique Index 允许无限个 NULL，但不允许无限个 ""
	Email         *string `db:"email" json:"email,omitempty"`
	EmailVerified bool    `db:"email_verified" json:"email_verified,omitempty"` // 让 GORM 自动推断 bool 类型

	Gender    string `db:"gender" json:"gender,omitempty"`
	Birthdate string `db:"birthdate" json:"birthdate,omitempty"`
	Zoneinfo  string `db:"zoneinfo" json:"zoneinfo,omitempty"`
	Locale    string `db:"locale" json:"locale,omitempty"`

	PhoneNumber         *string `db:"phone_number" json:"phone_number,omitempty"`
	PhoneNumberVerified bool    `db:"phone_number_verified" json:"phone_number_verified,omitempty"`

	// 4. 时间字段
	// GORM 依然会根据类型自动识别 autoCreateTime/autoUpdateTime 行为，
	// 但如果不引入 gorm 包，无法使用 gorm.DeletedAt 等类型，
	// 需要用 autoCreateTime 标签显式声明 (注意：GORM 识别 db 标签里的 autoCreateTime 关键字)
	CreatedAt time.Time `db:"created_at" json:"-"`
	UpdatedAt time.Time `db:"updated_at" json:"updated_at,omitempty"`

	// 5. JSONB 字段
	// Postgres 专用类型
	Metadata json.RawMessage `db:"metadata" json:"metadata,omitempty"`
}

func (Profile) TableName() string {
	return "profiles"
}

func (p *Profile) ToUserInfo(scopes []string) *oidc.UserInfo {
	if p == nil {
		return nil
	}

	// 处理 Metadata 转换 (json.RawMessage -> map[string]interface{})
	var metaMap map[string]interface{}
	if len(p.Metadata) > 0 {
		// 忽略错误，如果 metadata 格式不对，就留空
		_ = sonic.Unmarshal(p.Metadata, &metaMap)
	}

	info := &oidc.UserInfo{
		Subject:   p.UserID.String(),
		UpdatedAt: p.UpdatedAt.Unix(),
		Metadata:  metaMap,
	}
	if slices.Contains(scopes, oidc.ScopeProfile) {
		info.Name = strToPtr(p.Name)
		info.GivenName = strToPtr(p.GivenName)
		info.FamilyName = strToPtr(p.FamilyName)
		info.Nickname = strToPtr(p.Nickname)
		info.PreferredUsername = strToPtr(p.PreferredUsername)
		info.Profile = strToPtr(p.Profile)
		info.Picture = strToPtr(p.Picture)
		info.Website = strToPtr(p.Website)
		info.Gender = strToPtr(p.Gender)
		info.Birthdate = strToPtr(p.Birthdate)
		info.Zoneinfo = strToPtr(p.Zoneinfo)
		info.Locale = strToPtr(p.Locale)
	}

	if slices.Contains(scopes, oidc.ScopeEmail) {
		info.Email = p.Email
		if p.Email != nil {
			info.EmailVerified = boolToPtr(p.EmailVerified)
		}
	}
	if slices.Contains(scopes, oidc.ScopePhone) {
		info.PhoneNumber = p.PhoneNumber
		if p.PhoneNumber != nil {
			info.PhoneNumberVerified = boolToPtr(p.PhoneNumberVerified)
		}
	}

	return info
}

// 将 string 转换为 *string
// 如果输入为空字符串，返回 nil（这样 JSON 中就会省略该字段）
func strToPtr(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

// 简单的 bool 转指针
func boolToPtr(b bool) *bool {
	return &b
}
