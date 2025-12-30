package persist

import (
	"context"
	"time"

	"github.com/Masterminds/squirrel"
	"github.com/oy3o/o11y"
	"go.opentelemetry.io/otel/attribute"
)

// Cleanup 实现垃圾回收，物理删除已过期的临时数据
// 返回被删除的总记录数
func (s *PgxStorage) Cleanup(ctx context.Context) (int64, error) {
	var totalDeleted int64

	err := o11y.Run(ctx, "OIDC.CleanStorage", func(ctx context.Context, state o11y.State) error {
		now := time.Now()
		state.SetAttributes(attribute.String("cleanup_time", now.Format(time.RFC3339)))

		// 清理过期的 RefreshToken
		// SQL: DELETE FROM refresh_token_sessions WHERE expires_at < $1
		query, args, err := psql.Delete("refresh_token_sessions").
			Where(squirrel.Lt{"expires_at": now}).
			ToSql()
		if err != nil {
			return err
		}

		commandTag, err := s.DB(ctx).Exec(ctx, query, args...)
		if err != nil {
			return err
		}

		rowsDeleted := commandTag.RowsAffected()
		totalDeleted += rowsDeleted

		state.SetAttributes(attribute.Int64("refresh_tokens_deleted", rowsDeleted))
		state.SetAttributes(attribute.Int64("total_deleted", totalDeleted))
		return nil
	})

	return totalDeleted, err
}
