package persist

import (
	"context"
	"time"

	"github.com/georgysavva/scany/v2/pgxscan"
	"github.com/jackc/pgx/v5"
	"github.com/oy3o/oidc"
)

func (s *PgxStorage) RefreshTokenCreate(ctx context.Context, session *oidc.RefreshTokenSession) error {
	query, args, err := psql.Insert("oidc_refresh_tokens").
		Columns("id", "client_id", "user_id", "scope", "nonce", "auth_time", "expires_at", "acr", "amr").
		Values(session.ID, session.ClientID, session.UserID, session.Scope, session.Nonce, session.AuthTime, session.ExpiresAt, session.ACR, session.AMR).
		ToSql()
	if err != nil {
		return err
	}

	_, err = s.db.Exec(ctx, query, args...)
	return err
}

func (s *PgxStorage) RefreshTokenGet(ctx context.Context, tokenID oidc.Hash256) (*oidc.RefreshTokenSession, error) {
	var model oidc.RefreshTokenSession

	// 构建查询
	query, args, err := psql.Select("*").
		From("oidc_refresh_tokens").
		Where(map[string]interface{}{"id": tokenID}).
		ToSql()
	if err != nil {
		return nil, err
	}

	// 执行查询并映射
	if err := pgxscan.Get(ctx, s.db, &model, query, args...); err != nil {
		if pgxscan.NotFound(err) {
			return nil, oidc.ErrTokenNotFound
		}
		return nil, err
	}

	// 惰性删除过期 Token
	if time.Now().After(model.ExpiresAt) {
		_ = s.RefreshTokenRevoke(ctx, tokenID)
		return nil, oidc.ErrTokenNotFound
	}

	return &model, nil
}

func (s *PgxStorage) RefreshTokenRotate(ctx context.Context, oldTokenID oidc.Hash256, newSession *oidc.RefreshTokenSession) error {
	return s.execTx(ctx, func(tx pgx.Tx) error {
		// 1. 删除旧的
		delQuery, delArgs, err := psql.Delete("oidc_refresh_tokens").
			Where(map[string]interface{}{"id": oldTokenID}).
			ToSql()
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, delQuery, delArgs...); err != nil {
			return err
		}

		// 2. 创建新的
		insQuery, insArgs, err := psql.Insert("oidc_refresh_tokens").
			Columns("id", "client_id", "user_id", "scope", "nonce", "auth_time", "expires_at", "acr", "amr").
			Values(newSession.ID, newSession.ClientID, newSession.UserID, newSession.Scope, newSession.Nonce, newSession.AuthTime, newSession.ExpiresAt, newSession.ACR, newSession.AMR).
			ToSql()
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, insQuery, insArgs...); err != nil {
			return err
		}

		return nil
	})
}

func (s *PgxStorage) RefreshTokenRevoke(ctx context.Context, tokenID oidc.Hash256) error {
	query, args, err := psql.Delete("oidc_refresh_tokens").
		Where(map[string]interface{}{"id": tokenID}).
		ToSql()
	if err != nil {
		return err
	}
	_, err = s.db.Exec(ctx, query, args...)
	return err
}

func (s *PgxStorage) RefreshTokenRevokeUser(ctx context.Context, userID oidc.BinaryUUID) ([]oidc.Hash256, error) {
	// 相当于 JWKDelete ... Returning id
	query, args, err := psql.Delete("oidc_refresh_tokens").
		Where(map[string]interface{}{"user_id": userID}).
		Suffix("RETURNING id").
		ToSql()
	if err != nil {
		return nil, err
	}

	var ids []oidc.Hash256
	// Select 此时用于处理 RETURNING 的结果
	if err := pgxscan.Select(ctx, s.db, &ids, query, args...); err != nil {
		return nil, err
	}

	return ids, nil
}

func (s *PgxStorage) RefreshTokenListByUser(ctx context.Context, userID oidc.BinaryUUID) ([]*oidc.RefreshTokenSession, error) {
	query, args, err := psql.Select("*").
		From("oidc_refresh_tokens").
		Where(map[string]interface{}{"user_id": userID}).
		ToSql()
	if err != nil {
		return nil, err
	}

	var sessions []*oidc.RefreshTokenSession
	if err := pgxscan.Select(ctx, s.db, &sessions, query, args...); err != nil {
		return nil, err
	}

	// Filter out expired tokens lazily or return them and let caller decide?
	// Usually invalid/expired tokens should not be listed as active sessions.
	// But revocation might want to see them.
	// Let's filter here for "Active" sessions definition.
	activeSessions := make([]*oidc.RefreshTokenSession, 0, len(sessions))
	now := time.Now()
	for _, session := range sessions {
		if session.ExpiresAt.After(now) {
			activeSessions = append(activeSessions, session)
		}
	}

	return activeSessions, nil
}
