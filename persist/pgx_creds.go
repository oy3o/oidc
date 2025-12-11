package persist

import (
	"context"
	"time"

	"github.com/georgysavva/scany/v2/pgxscan"
	"github.com/oy3o/oidc"
)

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

	_, err = s.getDB(ctx).Exec(ctx, query, args...)
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

	if err := pgxscan.Get(ctx, s.getDB(ctx), cred, query, args...); err != nil {
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
	tag, err := s.getDB(ctx).Exec(ctx, query, args...)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrCredentialNotFound
	}
	return nil
}

func (s *PgxStorage) CredentialGetByIdentifier(ctx context.Context, credType CredentialType, identifier string) (*Credential, error) {
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

	if err := pgxscan.Get(ctx, s.getDB(ctx), &cred, query, args...); err != nil {
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
	tag, err := s.getDB(ctx).Exec(ctx, query, args...)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrCredentialNotFound
	}
	return nil
}
