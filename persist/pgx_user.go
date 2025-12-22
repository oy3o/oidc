package persist

import (
	"context"
	"time"

	"github.com/Masterminds/squirrel"
	"github.com/georgysavva/scany/v2/pgxscan"
	"github.com/google/uuid"
	"github.com/oy3o/oidc"
)

// 定义一些业务错误

// UserCreate 事务性创建用户、Profile 和 Credentials
func (s *PgxStorage) UserCreate(ctx context.Context, user *User, credentials []*Credential, profile *Profile) error {
	return s.Tx(ctx, func(ctx context.Context, uow *PgxUOW) error {
		executor := uow.Tx

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

		if err := pgxscan.Get(ctx, executor, user, userQuery, userArgs...); err != nil {
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
			if _, err := executor.Exec(ctx, profQuery, profArgs...); err != nil {
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
				Columns("user_id", "type", "identifier", "secret").
				Values(cred.UserID, cred.Type, cred.Identifier, cred.Secret).
				ToSql()
			if err != nil {
				return err
			}
			if _, err := executor.Exec(ctx, credQuery, credArgs...); err != nil {
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
	tag, err := s.DB(ctx).Exec(ctx, query, args...)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrUserNotFound
	}
	return nil
}

func (s *PgxStorage) UserGetByID(ctx context.Context, id oidc.BinaryUUID) (*User, error) {
	var user User
	query, args, err := psql.Select("*").From("users").Where(map[string]interface{}{"id": id}).ToSql()
	if err != nil {
		return nil, err
	}
	if err := pgxscan.Get(ctx, s.DB(ctx), &user, query, args...); err != nil {
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
	tag, err := s.DB(ctx).Exec(ctx, query, args...)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrUserNotFound
	}
	return nil
}

func (s *PgxStorage) UserList(ctx context.Context, limit, offset int, query string) ([]*Profile, int64, error) {
	// Base Builder
	baseBuilder := psql.Select("user_id", "name", "email", "email_verified", "updated_at").From("profiles")
	countBuilder := psql.Select("COUNT(*)").From("profiles")

	if query != "" {
		likePattern := "%" + query + "%"
		filter := squirrel.Or{
			squirrel.ILike{"name": likePattern},
			squirrel.ILike{"email": likePattern},
		}
		baseBuilder = baseBuilder.Where(filter)
		countBuilder = countBuilder.Where(filter)
	}

	// 1. Get Count
	var total int64
	countSql, countArgs, err := countBuilder.ToSql()
	if err != nil {
		return nil, 0, err
	}
	if err := s.DB(ctx).QueryRow(ctx, countSql, countArgs...).Scan(&total); err != nil {
		return nil, 0, err
	}

	// 2. Get Data
	sql, args, err := baseBuilder.OrderBy("updated_at DESC").Limit(uint64(limit)).Offset(uint64(offset)).ToSql()
	if err != nil {
		return nil, 0, err
	}

	var profiles []*Profile
	if err := pgxscan.Select(ctx, s.DB(ctx), &profiles, sql, args...); err != nil {
		return nil, 0, err
	}

	return profiles, total, nil
}

// --- Profile Methods ---

func (s *PgxStorage) ProfileGetByUserID(ctx context.Context, userID oidc.BinaryUUID) (*Profile, error) {
	var profile Profile
	query, args, err := psql.Select("*").From("profiles").Where(map[string]interface{}{"user_id": userID}).ToSql()
	if err != nil {
		return nil, err
	}

	if err := pgxscan.Get(ctx, s.DB(ctx), &profile, query, args...); err != nil {
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
		"name":               profile.Name,
		"given_name":         profile.GivenName,
		"family_name":        profile.FamilyName,
		"nickname":           profile.Nickname,
		"preferred_username": profile.PreferredUsername,
		"profile":            profile.Profile,
		"picture":            profile.Picture,
		"website":            profile.Website,
		"gender":             profile.Gender,
		"birthdate":          profile.Birthdate,
		"zoneinfo":           profile.Zoneinfo,
		"locale":             profile.Locale,
		"metadata":           profile.Metadata,
		"updated_at":         time.Now(),
	}

	query, args, err := psql.Update("profiles").
		SetMap(updateMap).
		Where(map[string]interface{}{"user_id": profile.UserID}).
		ToSql()
	if err != nil {
		return err
	}

	tag, err := s.DB(ctx).Exec(ctx, query, args...)
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

func (s *PgxStorage) ProfileMarkVerified(ctx context.Context, userID oidc.BinaryUUID, identifier string) error {
	var idenType IdenType
	var check func(string) bool
	for idenType, check = range IdentifierChecker {
		if check(identifier) {
			break
		}
	}
	if idenType != IdentEmail && idenType != IdentPhone {
		return oidc.ErrInvalidIdentifier
	}

	query, args, err := psql.Update("profiles").
		Set(string(idenType), identifier).
		Set(string(idenType)+"_verified", true).
		Set("updated_at", time.Now()).
		Where(map[string]interface{}{"user_id": userID}).
		ToSql()
	if err != nil {
		return err
	}
	tag, err := s.DB(ctx).Exec(ctx, query, args...)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrUserNotFound
	}
	return nil
}

// --- UserInfo Methods ---

func (s *PgxStorage) UserGetInfoByID(ctx context.Context, userID oidc.BinaryUUID, scopes []string) (*oidc.UserInfo, error) {
	profile, err := s.ProfileGetByUserID(ctx, userID)
	if err != nil {
		return nil, err
	}
	return profile.ToUserInfo(scopes), nil
}
