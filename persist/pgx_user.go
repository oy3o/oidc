package persist

import (
	"context"
	"errors"
	"time"

	"github.com/georgysavva/scany/v2/pgxscan"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/oy3o/oidc"
)

// 定义一些业务错误
var (
	ErrUserNotFound       = errors.New("user not found")
	ErrCredentialNotFound = errors.New("credential not found")
	ErrIdentifierExists   = errors.New("identifier already exists")
)

// UserCreate 事务性创建用户、Profile 和 Credentials
func (s *PgxStorage) UserCreate(ctx context.Context, user *User, credentials []*Credential, profile *Profile) error {
	return s.execTx(ctx, func(tx pgx.Tx) error {
		// 1. Insert User
		// 假设 ID 由数据库生成 (DEFAULT gen_random_uuid())，我们需要 RETURNING id
		builder := psql.Insert("users")
		if user.ID != oidc.BinaryUUID(uuid.Nil) {
			builder = builder.Columns("id", "role", "status", "last_login_at").
				Values(user.ID, user.Role, user.Status, user.LastLoginAt)
		} else {
			builder = builder.Columns("role", "status", "last_login_at").
				Values(user.Role, user.Status, user.LastLoginAt)
		}

		userQuery, userArgs, err := builder.
			Suffix("RETURNING id, created_at, updated_at").
			ToSql()
		if err != nil {
			return err
		}

		if err := pgxscan.Get(ctx, tx, user, userQuery, userArgs...); err != nil {
			return err
		}

		// 将生成的用户 ID 赋给关联对象
		if profile != nil {
			profile.UserID = user.ID
			// 2. Insert Profile
			profQuery, profArgs, err := psql.Insert("profiles").
				Columns("user_id", "name", "given_name", "family_name", "nickname",
					"preferred_username", "profile", "picture", "website", "email", "email_verified",
					"gender", "birthdate", "zoneinfo", "locale", "phone_number", "phone_number_verified", "metadata").
				Values(profile.UserID, profile.Name, profile.GivenName, profile.FamilyName, profile.Nickname,
					profile.PreferredUsername, profile.Profile, profile.Picture, profile.Website, profile.Email, profile.EmailVerified,
					profile.Gender, profile.Birthdate, profile.Zoneinfo, profile.Locale, profile.PhoneNumber, profile.PhoneNumberVerified, profile.Metadata).
				ToSql()
			if err != nil {
				return err
			}
			if _, err := tx.Exec(ctx, profQuery, profArgs...); err != nil {
				if isUniqueViolation(err) {
					return ErrIdentifierExists // Profile 中的 Email/Phone 可能冲突
				}
				return err
			}
		}

		// 3. Insert Credentials
		for _, cred := range credentials {
			cred.UserID = user.ID // 关联 ID
			credQuery, credArgs, err := psql.Insert("credentials").
				Columns("user_id", "type", "identifier", "secret", "verified").
				Values(cred.UserID, cred.Type, cred.Identifier, cred.Secret, cred.Verified).
				ToSql()
			if err != nil {
				return err
			}
			if _, err := tx.Exec(ctx, credQuery, credArgs...); err != nil {
				if isUniqueViolation(err) {
					return ErrIdentifierExists
				}
				return err
			}
		}

		return nil
	})
}

func (s *PgxStorage) UserDelete(ctx context.Context, id oidc.BinaryUUID) error {
	// 级联删除通常由数据库外键约束 (ON DELETE CASCADE) 处理
	// 如果没有级联约束，需要手动删除 creds 和 profile
	// 这里假设数据库已配置 CASCADE，直接删除 user
	query, args, err := psql.Delete("users").Where(map[string]interface{}{"id": id}).ToSql()
	if err != nil {
		return err
	}
	tag, err := s.db.Exec(ctx, query, args...)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrUserNotFound
	}
	return nil
}

func (s *PgxStorage) UserFindByID(ctx context.Context, id oidc.BinaryUUID) (*User, error) {
	var user User
	query, args, err := psql.Select("*").From("users").Where(map[string]interface{}{"id": id}).ToSql()
	if err != nil {
		return nil, err
	}
	if err := pgxscan.Get(ctx, s.db, &user, query, args...); err != nil {
		if pgxscan.NotFound(err) {
			return nil, ErrUserNotFound
		}
		return nil, err
	}
	return &user, nil
}

func (s *PgxStorage) UserUpdateStatus(ctx context.Context, id oidc.BinaryUUID, status UserStatus) error {
	query, args, err := psql.Update("users").
		Set("status", status).
		Set("updated_at", time.Now()).
		Where(map[string]interface{}{"id": id}).
		ToSql()
	if err != nil {
		return err
	}
	tag, err := s.db.Exec(ctx, query, args...)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrUserNotFound
	}
	return nil
}

// --- Profile Methods ---

func (s *PgxStorage) ProfileFindByUserID(ctx context.Context, userID oidc.BinaryUUID) (*Profile, error) {
	var profile Profile
	query, args, err := psql.Select("*").From("profiles").Where(map[string]interface{}{"user_id": userID}).ToSql()
	if err != nil {
		return nil, err
	}

	if err := pgxscan.Get(ctx, s.db, &profile, query, args...); err != nil {
		if pgxscan.NotFound(err) {
			return nil, ErrUserNotFound // Profile not found often means user context issue
		}
		return nil, err
	}
	return &profile, nil
}

func (s *PgxStorage) ProfileUpdate(ctx context.Context, profile *Profile) error {
	// 构建 update map
	updateMap := map[string]interface{}{
		"name":                  profile.Name,
		"given_name":            profile.GivenName,
		"family_name":           profile.FamilyName,
		"nickname":              profile.Nickname,
		"preferred_username":    profile.PreferredUsername,
		"profile":               profile.Profile,
		"picture":               profile.Picture,
		"website":               profile.Website,
		"email":                 profile.Email,
		"email_verified":        profile.EmailVerified,
		"gender":                profile.Gender,
		"birthdate":             profile.Birthdate,
		"zoneinfo":              profile.Zoneinfo,
		"locale":                profile.Locale,
		"phone_number":          profile.PhoneNumber,
		"phone_number_verified": profile.PhoneNumberVerified,
		"metadata":              profile.Metadata,
		"updated_at":            time.Now(),
	}

	query, args, err := psql.Update("profiles").
		SetMap(updateMap).
		Where(map[string]interface{}{"user_id": profile.UserID}).
		ToSql()
	if err != nil {
		return err
	}

	tag, err := s.db.Exec(ctx, query, args...)
	if err != nil {
		if isUniqueViolation(err) {
			return ErrIdentifierExists
		}
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrUserNotFound
	}
	return nil
}

// --- UserInfo Methods ---

func (s *PgxStorage) UserGetInfoByID(ctx context.Context, userID oidc.BinaryUUID, scopes []string) (*oidc.UserInfo, error) {
	profile, err := s.ProfileFindByUserID(ctx, userID)
	if err != nil {
		return nil, err
	}
	return profile.ToUserInfo(scopes), nil
}
