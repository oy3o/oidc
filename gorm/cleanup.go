package gorm

import (
	"context"
	"time"

	"github.com/oy3o/o11y"
	"go.opentelemetry.io/otel/attribute"
)

// Cleanup 实现垃圾回收，物理删除已过期的临时数据
// 返回被删除的总记录数
func (s *GormStorage) Cleanup(ctx context.Context) (int64, error) {
	var totalDeleted int64

	err := o11y.Run(ctx, "oidc.GormStorage.Cleanup", func(ctx context.Context, state o11y.State) error {
		now := time.Now()
		state.SetAttributes(attribute.String("cleanup_time", now.Format(time.RFC3339)))

		// 1. 清理过期的 RefreshToken
		result := s.db.WithContext(ctx).
			Where("expires_at < ?", now).
			Delete(&RefreshTokenModel{})
		if result.Error != nil {
			return result.Error
		}
		totalDeleted += result.RowsAffected
		state.SetAttributes(attribute.Int64("refresh_tokens_deleted", result.RowsAffected))

		// 2. 清理过期的 DeviceCode
		result = s.db.WithContext(ctx).
			Where("expires_at < ?", now).
			Delete(&DeviceCodeModel{})
		if result.Error != nil {
			return result.Error
		}
		totalDeleted += result.RowsAffected
		state.SetAttributes(attribute.Int64("device_codes_deleted", result.RowsAffected))

		// 3. 清理过期的 Access Token 黑名单
		result = s.db.WithContext(ctx).
			Where("expires_at < ?", now).
			Delete(&BlacklistModel{})
		if result.Error != nil {
			return result.Error
		}
		totalDeleted += result.RowsAffected
		state.SetAttributes(attribute.Int64("blacklist_entries_deleted", result.RowsAffected))

		// 4. （可选）清理过期的 PAR Session
		// PAR 的 TTL 通常很短（60秒），但也需要清理
		result = s.db.WithContext(ctx).
			Where("expires_at < ?", now).
			Delete(&PARModel{})
		if result.Error != nil {
			return result.Error
		}
		totalDeleted += result.RowsAffected
		state.SetAttributes(attribute.Int64("par_sessions_deleted", result.RowsAffected))

		state.SetAttributes(attribute.Int64("total_deleted", totalDeleted))
		return nil
	})

	return totalDeleted, err
}
