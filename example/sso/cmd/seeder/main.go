package main

import (
	"context"
	"fmt"
	"time"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"

	"sso/internal/config"
	"sso/internal/domain"
	"sso/internal/infra/db"

	"github.com/google/uuid"
	"github.com/oy3o/oidc"
	"github.com/oy3o/oidc/hasher"
)

func main() {
	cfg, err := config.Load()
	if err != nil {
		panic(err)
	}

	// 1. Connect DB
	gormDB, err := gorm.Open(postgres.Open(cfg.Database.DSN), &gorm.Config{})
	if err != nil {
		panic(err)
	}

	pwHasher := hasher.NewBcryptHasher(10)
	storage, err := db.NewStorage(gormDB, pwHasher)
	if err != nil {
		panic(err)
	}

	ctx := context.Background()

	// 2. Create User
	// admin / password
	adminPass, _ := pwHasher.Hash(ctx, []byte("password"))
	user := &domain.User{
		ID:           uuid.NewString(),
		Username:     "admin",
		PasswordHash: string(adminPass),
		Role:         domain.RoleAdmin,
	}

	if err := storage.CreateUser(ctx, user); err != nil {
		fmt.Printf("User creation skipped (might exist): %v\n", err)
	} else {
		fmt.Println("User 'admin' created. Password: 'password'")
	}

	// 3. Create OIDC Client (Postman / Debugger)
	// client_id: test-client
	// client_secret: test-secret
	clientSecretRaw := "test-secret"
	clientSecretHash, _ := pwHasher.Hash(ctx, []byte(clientSecretRaw))

	clientMeta := oidc.ClientMetadata{
		ID:                      oidc.BinaryUUID(uuid.New()), // 这里的 UUID 需要固定或者打印出来
		Name:                    "Postman Test Client",
		Secret:                  oidc.String(clientSecretHash),
		RedirectURIs:            []string{"https://oauth.pstmn.io/v1/callback", "http://localhost:8080/callback"},
		GrantTypes:              []string{"authorization_code", "refresh_token", "client_credentials"},
		Scope:                   "openid profile email offline_access",
		TokenEndpointAuthMethod: "client_secret_basic",
		IsConfidential:          true,
		CreatedAt:               time.Now(),
	}

	// 为了方便测试，我们将 ClientID 硬编码覆盖一下，或者打印出来
	// 实际 Storage.CreateClient 会使用传入 ID
	// 这里我们生成一个新的
	c, err := storage.CreateClient(ctx, clientMeta)
	if err != nil {
		fmt.Printf("Client creation failed: %v\n", err)
	} else {
		fmt.Printf("Client created!\nID: %s\nSecret: %s\n", c.GetID(), clientSecretRaw)
	}
}
