package oidc

import (
	"context"
	"time"

	"github.com/oy3o/o11y"
	"go.opentelemetry.io/otel/attribute"
)

// GCWorker 垃圾回收 Worker
// 定期调用 Persistence.Cleanup() 清理过期数据
type GCWorker struct {
	persistence Persistence
	interval    time.Duration
	stopCh      chan struct{}
}

// NewGCWorker 创建 GC Worker
// interval: 清理间隔，建议 1 小时
func NewGCWorker(persistence Persistence, interval time.Duration) *GCWorker {
	if interval <= 0 {
		interval = time.Hour // 默认 1 小时
	}
	return &GCWorker{
		persistence: persistence,
		interval:    interval,
		stopCh:      make(chan struct{}),
	}
}

// Start 启动 GC Worker (非阻塞)
func (w *GCWorker) Start(ctx context.Context) {
	go func() {
		ticker := time.NewTicker(w.interval)
		defer ticker.Stop()

		// 启动时立即执行一次清理
		w.runCleanup(ctx)

		for {
			select {
			case <-ticker.C:
				w.runCleanup(ctx)
			case <-w.stopCh:
				return
			case <-ctx.Done():
				return
			}
		}
	}()
}

// Stop 停止 GC Worker
func (w *GCWorker) Stop() {
	close(w.stopCh)
}

// runCleanup 执行清理任务
func (w *GCWorker) runCleanup(ctx context.Context) {
	// 使用独立的超时上下文，避免长时间阻塞
	cleanupCtx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()

	err := o11y.Run(cleanupCtx, "OIDC.CleanGCWorker", func(ctx context.Context, state o11y.State) error {
		deleted, err := w.persistence.Cleanup(ctx)
		if err != nil {
			state.SetAttributes(attribute.String("error", err.Error()))
			return err
		}
		state.SetAttributes(attribute.Int64("deleted", deleted))
		return nil
	})
	if err != nil {
		// GC 失败不应中断服务，仅记录错误
		// o11y.Run 内部已经记录了错误，这里无需再次处理
	}
}
