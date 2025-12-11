package persist

import (
	"context"
	"time"

	"github.com/georgysavva/scany/v2/pgxscan"
	"github.com/oy3o/oidc"
)

var clientTable = (&oidc.ClientMetadata{}).TableName()

func (s *PgxStorage) ClientGetByID(ctx context.Context, clientID oidc.BinaryUUID) (oidc.RegisteredClient, error) {
	var model oidc.ClientMetadata
	query, args, err := psql.Select("*").From(clientTable).Where(map[string]interface{}{"id": clientID}).ToSql()
	if err != nil {
		return nil, err
	}

	if err := pgxscan.Get(ctx, s.getDB(ctx), &model, query, args...); err != nil {
		if pgxscan.NotFound(err) {
			return nil, oidc.ErrClientNotFound
		}
		return nil, err
	}
	return &model, nil
}

func (s *PgxStorage) ClientCreate(ctx context.Context, metadata *oidc.ClientMetadata) (oidc.RegisteredClient, error) {
	if metadata.IsConfidentialClient {
		if len(metadata.Secret) == 0 {
			return nil, ErrConfidentialClientSecretRequired
		}
	}
	metadata.UpdatedAt = time.Now()

	// 这里假设 ClientMetadata 的字段都对应数据库列
	// 注意：Array 字段 (RedirectURIs, GrantTypes 等) pgx 可以自动处理 Go slice -> Postgres Array
	query, args, err := psql.Insert(clientTable).
		Columns("id", "name", "secret", "redirect_uris", "grant_types", "scope", "logo_uri", "token_endpoint_auth_method", "is_confidential_client", "owner_id", "updated_at").
		Values(metadata.ID, metadata.Name, metadata.Secret, metadata.RedirectURIs, metadata.GrantTypes, metadata.Scope, metadata.LogoURI, metadata.TokenEndpointAuthMethod, metadata.IsConfidentialClient, metadata.OwnerID, metadata.UpdatedAt).
		ToSql()
	if err != nil {
		return nil, err
	}

	if _, err := s.getDB(ctx).Exec(ctx, query, args...); err != nil {
		return nil, err
	}
	return metadata, nil
}

func (s *PgxStorage) ClientUpdate(ctx context.Context, clientID oidc.BinaryUUID, metadata *oidc.ClientMetadata) (oidc.RegisteredClient, error) {
	// 构建 Update Builder
	builder := psql.Update(clientTable).
		Set("name", metadata.Name).
		Set("redirect_uris", metadata.RedirectURIs).
		Set("grant_types", metadata.GrantTypes).
		Set("scope", metadata.Scope).
		Set("logo_uri", metadata.LogoURI).
		Set("token_endpoint_auth_method", metadata.TokenEndpointAuthMethod).
		Set("is_confidential_client", metadata.IsConfidentialClient).
		Set("updated_at", time.Now()).
		Where(map[string]interface{}{"id": clientID})

	if metadata.Secret != "" {
		builder = builder.Set("secret", metadata.Secret)
	}

	query, args, err := builder.ToSql()
	if err != nil {
		return nil, err
	}

	tag, err := s.getDB(ctx).Exec(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	if tag.RowsAffected() == 0 {
		return nil, oidc.ErrClientNotFound
	}

	// 重新获取以返回完整对象（或者直接合并）
	return s.ClientGetByID(ctx, clientID)
}

func (s *PgxStorage) ClientDeleteByID(ctx context.Context, clientID oidc.BinaryUUID) error {
	query, args, err := psql.Delete(clientTable).Where(map[string]interface{}{"id": clientID}).ToSql()
	if err != nil {
		return err
	}
	_, err = s.getDB(ctx).Exec(ctx, query, args...)
	return err
}

func (s *PgxStorage) ClientListByOwner(ctx context.Context, ownerID oidc.BinaryUUID) ([]oidc.RegisteredClient, error) {
	var models []oidc.ClientMetadata
	query, args, err := psql.Select("*").From(clientTable).Where(map[string]interface{}{"owner_id": ownerID}).ToSql()
	if err != nil {
		return nil, err
	}

	if err := pgxscan.Select(ctx, s.getDB(ctx), &models, query, args...); err != nil {
		return nil, err
	}

	clients := make([]oidc.RegisteredClient, len(models))
	for i := range models {
		clients[i] = &models[i]
	}
	return clients, nil
}

func (s *PgxStorage) ClientListAll(ctx context.Context, query oidc.ListQuery) ([]oidc.RegisteredClient, error) {
	var models []oidc.ClientMetadata

	builder := psql.Select("*").From(clientTable).OrderBy("id ASC")

	if query.Limit > 0 {
		builder = builder.Limit(uint64(query.Limit))
	}
	if query.Offset > 0 {
		builder = builder.Offset(uint64(query.Offset))
	}

	sql, args, err := builder.ToSql()
	if err != nil {
		return nil, err
	}

	if err := pgxscan.Select(ctx, s.getDB(ctx), &models, sql, args...); err != nil {
		return nil, err
	}

	clients := make([]oidc.RegisteredClient, len(models))
	for i := range models {
		clients[i] = &models[i]
	}
	return clients, nil
}
