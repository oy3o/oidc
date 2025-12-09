package persist

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/bytedance/sonic"
	"github.com/georgysavva/scany/v2/pgxscan"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/oy3o/oidc"
)

// JWKSave 存储 JWK
func (s *PgxStorage) JWKSave(ctx context.Context, key jwk.Key) error {
	if key.KeyID() == "" {
		return errors.New("key must have a kid")
	}

	// 序列化为 JSON (包含私钥)
	data, err := sonic.Marshal(key)
	if err != nil {
		return fmt.Errorf("failed to marshal JWK: %w", err)
	}

	// 使用 Squirrel 构建 Upsert 语句
	// PostgreSQL: INSERT INTO ... ON CONFLICT (kid) DO UPDATE SET ...
	query, args, err := psql.Insert("jwks").
		Columns("kid", "jwk", "created_at").
		Values(key.KeyID(), data, time.Now()).
		Suffix("ON CONFLICT (kid) DO UPDATE SET jwk = EXCLUDED.jwk").
		ToSql()
	if err != nil {
		return err
	}

	_, err = s.db.Exec(ctx, query, args...)
	return err
}

// JWKGet 获取 JWK
func (s *PgxStorage) JWKGet(ctx context.Context, kid string) (jwk.Key, error) {
	var model oidc.JWK

	query, args, err := psql.Select("kid", "jwk", "created_at").
		From("jwks").
		Where(map[string]interface{}{"kid": kid}).
		ToSql()
	if err != nil {
		return nil, err
	}

	if err := pgxscan.Get(ctx, s.db, &model, query, args...); err != nil {
		if pgxscan.NotFound(err) {
			return nil, oidc.ErrKeyNotFound
		}
		return nil, err
	}

	key, err := jwk.ParseKey([]byte(model.JWK))
	if err != nil {
		return nil, fmt.Errorf("failed to parse JWK from database: %w", err)
	}
	return key, nil
}

// JWKList 获取所有 JWK
func (s *PgxStorage) JWKList(ctx context.Context) ([]jwk.Key, error) {
	var models []oidc.JWK

	query, args, err := psql.Select("kid", "jwk", "created_at").
		From("jwks").
		ToSql()
	if err != nil {
		return nil, err
	}

	if err := pgxscan.Select(ctx, s.db, &models, query, args...); err != nil {
		return nil, err
	}

	keys := make([]jwk.Key, 0, len(models))
	for _, model := range models {
		// 跳过特殊的签名 Key ID 标记记录
		if model.KID == "__signing_key__" {
			continue
		}

		key, err := jwk.ParseKey([]byte(model.JWK))
		if err != nil {
			// 忽略损坏的 key 或记录日志
			continue
		}
		keys = append(keys, key)
	}
	return keys, nil
}

// JWKDelete 删除 JWK
func (s *PgxStorage) JWKDelete(ctx context.Context, kid string) error {
	query, args, err := psql.Delete("jwks").
		Where(map[string]interface{}{"kid": kid}).
		ToSql()
	if err != nil {
		return err
	}

	_, err = s.db.Exec(ctx, query, args...)
	return err
}

// JWKMarkSigning 存储当前签名密钥 ID
// 使用特殊的 KID "__signing_key__" 来存储
func (s *PgxStorage) JWKMarkSigning(ctx context.Context, kid string) error {
	const signingKeyMarker = "__signing_key__"

	// 同样使用 Upsert
	query, args, err := psql.Insert("jwks").
		Columns("kid", "jwk", "created_at").
		Values(signingKeyMarker, kid, time.Now()).
		Suffix("ON CONFLICT (kid) DO UPDATE SET jwk = EXCLUDED.jwk, created_at = EXCLUDED.created_at").
		ToSql()
	if err != nil {
		return err
	}

	_, err = s.db.Exec(ctx, query, args...)
	return err
}

// JWKGetSigning 获取当前签名密钥 ID
func (s *PgxStorage) JWKGetSigning(ctx context.Context) (string, error) {
	const signingKeyMarker = "__signing_key__"

	var model oidc.JWK
	query, args, err := psql.Select("jwk").
		From("jwks").
		Where(map[string]interface{}{"kid": signingKeyMarker}).
		ToSql()
	if err != nil {
		return "", err
	}

	if err := pgxscan.Get(ctx, s.db, &model, query, args...); err != nil {
		if pgxscan.NotFound(err) {
			return "", oidc.ErrKeyNotFound
		}
		return "", err
	}
	return string(model.JWK), nil
}
