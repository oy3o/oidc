package persist

import (
	"context"
	"time"

	"github.com/georgysavva/scany/v2/pgxscan"
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

	_, err = s.DB(ctx).Exec(ctx, query, args...)
	return err
}

// RefreshTokenGet 获取刷新令牌。
// 它会自动检测上下文中是否有事务，并使用正确的执行器。
func (s *PgxStorage) RefreshTokenGet(ctx context.Context, tokenID oidc.Hash256) (*oidc.RefreshTokenSession, error) {
	var model oidc.RefreshTokenSession
	executor := s.DB(ctx) // 获取 Pool 或 Tx

	query, args, err := psql.Select("*").
		From("oidc_refresh_tokens").
		Where(map[string]interface{}{"id": tokenID}).
		ToSql()
	if err != nil {
		return nil, err
	}

	// 使用 pgxscan 简化映射，传入 executor
	if err := pgxscan.Get(ctx, executor, &model, query, args...); err != nil {
		if pgxscan.NotFound(err) {
			return nil, oidc.ErrTokenNotFound
		}
		return nil, err
	}

	// 惰性删除：如果已过期，尝试撤销 (Revoke)
	// 注意：这里调用 Revoke 时，如果当前已在事务中，Revoke 也会复用该事务
	if time.Now().After(model.ExpiresAt) {
		// 忽略撤销错误，因为读操作的主要目的是返回"不存在"
		_ = s.RefreshTokenRevoke(ctx, tokenID)
		return nil, oidc.ErrTokenNotFound
	}

	return &model, nil
}

// RefreshTokenRotate 旋转刷新令牌（原子操作：删旧换新）。
// 它使用 Tx 确保原子性。
func (s *PgxStorage) RefreshTokenRotate(ctx context.Context, oldTokenID oidc.Hash256, newSession *oidc.RefreshTokenSession, gracePeriod time.Duration) error {
	// 调用 Tx，自动处理事务开启或重入
	return s.Tx(ctx, func(ctx context.Context, uow *PgxUOW) error {
		executor := uow.Tx // 在 Tx 回调中，我们明确知道有 Tx，也可以用 s.getDB(ctx)

		// 1. 删除旧令牌
		delQuery, delArgs, err := psql.Delete("oidc_refresh_tokens").
			Where(map[string]interface{}{"id": oldTokenID}).
			ToSql()
		if err != nil {
			return err
		}
		if _, err := executor.Exec(ctx, delQuery, delArgs...); err != nil {
			return err
		}

		// 2. 插入新令牌
		insQuery, insArgs, err := psql.Insert("oidc_refresh_tokens").
			Columns("id", "client_id", "user_id", "scope", "nonce", "auth_time", "expires_at", "acr", "amr").
			Values(newSession.ID, newSession.ClientID, newSession.UserID, newSession.Scope, newSession.Nonce, newSession.AuthTime, newSession.ExpiresAt, newSession.ACR, newSession.AMR).
			ToSql()
		if err != nil {
			return err
		}

		if _, err := executor.Exec(ctx, insQuery, insArgs...); err != nil {
			return err
		}

		return nil
	})
}

// RefreshTokenRevoke 撤销（删除）令牌
func (s *PgxStorage) RefreshTokenRevoke(ctx context.Context, tokenID oidc.Hash256) error {
	executor := s.DB(ctx)

	query, args, err := psql.Delete("oidc_refresh_tokens").
		Where(map[string]interface{}{"id": tokenID}).
		ToSql()
	if err != nil {
		return err
	}

	if _, err := executor.Exec(ctx, query, args...); err != nil {
		return err
	}
	return nil
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
	if err := pgxscan.Select(ctx, s.DB(ctx), &ids, query, args...); err != nil {
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
	if err := pgxscan.Select(ctx, s.DB(ctx), &sessions, query, args...); err != nil {
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
