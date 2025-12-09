package persist

import (
	"context"
	"time"

	"github.com/georgysavva/scany/v2/pgxscan"
	"github.com/oy3o/oidc"
)

// CredentialType 使用 string 枚举，数据库存 varchar
type CredentialType string

const (
	CredentialTypePassword CredentialType = "password" // 用于存密码Hash，Identifier是id
	CredentialTypeEmail    CredentialType = "email"    // 仅用于标识邮箱登录（无密码，Magic Link）
	CredentialTypePhone    CredentialType = "phone"    // 手机验证码登录（无密码，Magic Link）
	CredentialTypeWebAuthn CredentialType = "webauthn" // Passkeys / FIDO2
)

type Credential struct {
	// 1. 物理主键 (自增 ID)
	// 虽然业务上很少用 ID 查询 Credential，但作为 GORM 模型需要一个主键
	ID uint64 `db:"id"`

	// 2. 外键关联
	// 关联到 User 表，必须加索引以快速查找某用户的所有凭证
	UserID oidc.BinaryUUID `db:"user_id"`

	// 3. 核心认证信息 (复合唯一索引)
	// 语义：在某种认证类型下，标识符必须唯一。
	// 索引名: idx_cred_type_identifier (自定义索引名)
	// Type: 凭证类型 (password, google, email...)
	Type CredentialType `db:"type"`

	// Identifier: 唯一标识 (username, email, phone number, openid_sub)
	Identifier string `db:"identifier"`

	// 4. 密钥/凭证数据
	// 密码存 Hash，OAuth 存 Token。
	// 建议 SecretBytes 实现 GormDataTypeInterface 返回 "bytea" 或 "blob"
	// 或者直接使用 string 存储 hex/base64 编码后的数据
	Secret oidc.SecretBytes `db:"secret"`

	// 5. 状态与审计
	// Verified: 对于 Email/Phone 类型很重要
	Verified bool `db:"verified"`

	CreatedAt time.Time `db:"created_at"`
	UpdatedAt time.Time `db:"updated_at"`
}

func (Credential) TableName() string {
	return "credentials"
}

// UserUpdatePassword 原子性更新用户的所有密码凭证
func (s *PgxStorage) UserUpdatePassword(ctx context.Context, userID oidc.BinaryUUID, newHashedPassword oidc.SecretBytes) error {
	query, args, err := psql.Update("credentials").
		Set("secret", newHashedPassword).
		Set("updated_at", time.Now()).
		Where(map[string]interface{}{
			"user_id": userID,
			"type":    CredentialTypePassword,
		}).ToSql()
	if err != nil {
		return err
	}

	_, err = s.db.Exec(ctx, query, args...)
	return err
}

func (s *PgxStorage) CredentialCreate(ctx context.Context, cred *Credential) error {
	query, args, err := psql.Insert("credentials").
		Columns("user_id", "type", "identifier", "secret", "verified").
		Values(cred.UserID, cred.Type, cred.Identifier, cred.Secret, cred.Verified).
		Suffix("RETURNING id, created_at, updated_at"). // 回填 ID
		ToSql()
	if err != nil {
		return err
	}

	if err := pgxscan.Get(ctx, s.db, cred, query, args...); err != nil {
		if isUniqueViolation(err) {
			return ErrIdentifierExists
		}
		return err
	}
	return nil
}

func (s *PgxStorage) CredentialDeleteByID(ctx context.Context, credID uint64) error {
	query, args, err := psql.Delete("credentials").Where(map[string]interface{}{"id": credID}).ToSql()
	if err != nil {
		return err
	}
	tag, err := s.db.Exec(ctx, query, args...)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrCredentialNotFound
	}
	return nil
}

func (s *PgxStorage) CredentialFindByIdentifier(ctx context.Context, credType CredentialType, identifier string) (*Credential, error) {
	var cred Credential
	query, args, err := psql.Select("*").
		From("credentials").
		Where(map[string]interface{}{
			"type":       credType,
			"identifier": identifier,
		}).ToSql()
	if err != nil {
		return nil, err
	}

	if err := pgxscan.Get(ctx, s.db, &cred, query, args...); err != nil {
		if pgxscan.NotFound(err) {
			return nil, ErrCredentialNotFound
		}
		return nil, err
	}
	return &cred, nil
}

func (s *PgxStorage) CredentialUpdate(ctx context.Context, cred *Credential) error {
	query, args, err := psql.Update("credentials").
		Set("secret", cred.Secret).
		Set("verified", cred.Verified).
		Set("updated_at", time.Now()).
		Where(map[string]interface{}{"id": cred.ID}).
		ToSql()
	if err != nil {
		return err
	}
	tag, err := s.db.Exec(ctx, query, args...)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrCredentialNotFound
	}
	return nil
}
