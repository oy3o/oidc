package oidc_test

import (
	"context"
	"fmt"
	"sync"
	"testing"

	"github.com/google/uuid"
	"github.com/oy3o/oidc"
)

func TestConcurrent_TokenIssuance(t *testing.T) {
	// 跳过短测试，因为压力测试耗时
	if testing.Short() {
		t.Skip("skipping concurrent token test in short mode")
	}

	server, _, client, _ := setupExchangeTest(t)
	ctx := context.Background()
	userID := oidc.BinaryUUID(uuid.New())

	const concurrency = 100
	errCh := make(chan error, concurrency)
	var wg sync.WaitGroup
	wg.Add(concurrency)

	// 并发请求
	for i := 0; i < concurrency; i++ {
		go func(idx int) {
			defer wg.Done()

			req := &oidc.IssuerRequest{
				ClientID: client.GetID(),
				UserID:   userID,
				Scopes:   "openid",
				Audience: []string{client.GetID().String()},
				Nonce:    fmt.Sprintf("nonce-%d", idx),
			}

			// 直接调用 Issuer 核心逻辑
			_, err := server.Issuer().IssueOIDCTokens(ctx, req)
			if err != nil {
				errCh <- err
			}
		}(i)
	}

	wg.Wait()
	close(errCh)

	// 检查错误
	for err := range errCh {
		t.Errorf("Concurrent issue failed: %v", err)
	}
}
