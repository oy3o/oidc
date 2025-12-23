package persist

import (
	"context"
	"time"

	"github.com/georgysavva/scany/v2/pgxscan"
)

func (s *PgxStorage) CredentialCreate(ctx context.Context, cred *Credential) error {
	query, args, err := psql.Insert("credentials").
		Columns("user_id", "type", "identifier", "secret").
		Values(cred.UserID, cred.Type, cred.Identifier, cred.Secret).
		Suffix("RETURNING id, created_at, updated_at"). // 回填 ID
		ToSql()
	if err != nil {
		return err
	}

	if err := pgxscan.Get(ctx, s.DB(ctx), cred, query, args...); err != nil {
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
	tag, err := s.DB(ctx).Exec(ctx, query, args...)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrCredentialNotFound
	}
	return nil
}

func (s *PgxStorage) CredentialGetByIdentifier(ctx context.Context, idenType IdenType, identifier string) (*Credential, error) {
	var cred Credential
	query, args, err := psql.Select("*").
		From("credentials").
		Where(map[string]interface{}{
			"type":       idenType,
			"identifier": identifier,
		}).ToSql()
	if err != nil {
		return nil, err
	}

	if err := pgxscan.Get(ctx, s.DB(ctx), &cred, query, args...); err != nil {
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
		Set("updated_at", time.Now()).
		Where(map[string]interface{}{"id": cred.ID}).
		ToSql()
	if err != nil {
		return err
	}
	tag, err := s.DB(ctx).Exec(ctx, query, args...)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrCredentialNotFound
	}
	return nil
}
