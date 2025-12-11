package persist

import (
	"context"
	"errors"
	"fmt"

	"github.com/Masterminds/squirrel"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/oy3o/oidc"
	"github.com/rs/zerolog/log"
)

// -----------------------------------------------------------------------------
// 基础设施与类型定义
// -----------------------------------------------------------------------------

// psql 全局复用的 SQL 构建器，预设为 PostgreSQL 格式 ($1, $2...)
var psql = squirrel.StatementBuilder.PlaceholderFormat(squirrel.Dollar)

// txKey 是 context 中存储事务对象的私有键，防止外部包冲突
type txKey struct{}

// DBTX 定义了 pgxpool.Pool 和 pgx.Tx 共有的方法，用于统一读写操作接口
type DBTX interface {
	Exec(context.Context, string, ...any) (pgconn.CommandTag, error)
	Query(context.Context, string, ...any) (pgx.Rows, error)
	QueryRow(context.Context, string, ...any) pgx.Row
	SendBatch(context.Context, *pgx.Batch) pgx.BatchResults
	CopyFrom(context.Context, pgx.Identifier, []string, pgx.CopyFromSource) (int64, error)
}

// PgxStorage 实现 oidc.Persistence 接口
type PgxStorage struct {
	db     *pgxpool.Pool
	hasher oidc.Hasher
}

// PgxUOW 事务工作单元，包含底层的 pgx.Tx 和事务钩子
type PgxUOW struct {
	pgx.Tx
	onCommit   []func(context.Context) error
	onRollback []func() error
}

// 确保实现接口
var (
	_ oidc.Persistence = (*PgxStorage)(nil)
	_ Persistence      = (*PgxStorage)(nil)
)

// NewPgx 创建一个新的 Storage 实例
func NewPgx(db *pgxpool.Pool, hasher oidc.Hasher) *PgxStorage {
	return &PgxStorage{
		db:     db,
		hasher: hasher,
	}
}

// Close 关闭连接池
func (s *PgxStorage) Close() {
	s.db.Close()
}

// -----------------------------------------------------------------------------
// 核心：事务管理与 Context 注入
// -----------------------------------------------------------------------------

// getDB 从 context 获取当前事务，如果不存在则返回连接池。
// 这是实现“读写自动跟随事务”的关键。
func (s *PgxStorage) getDB(ctx context.Context) DBTX {
	if uow, ok := ctx.Value(txKey{}).(*PgxUOW); ok {
		return uow.Tx
	}
	return s.db
}

// Register Hooks
func (u *PgxUOW) OnRollback(hooks ...func() error) {
	u.onRollback = append(u.onRollback, hooks...)
}

func (u *PgxUOW) OnCommit(hooks ...func(context.Context) error) {
	u.onCommit = append(u.onCommit, hooks...)
}

// Tx 事务包装器。支持嵌套调用（重入）。
// fn: 业务逻辑闭包。注意：必须使用 fn 传入的 ctx，因为它包含了当前的事务句柄。
func (s *PgxStorage) Tx(ctx context.Context, fn func(ctx context.Context, uow *PgxUOW) error, opts ...ExecuteOption) error {
	// 1. 重入检测：如果 context 中已经存在事务，直接复用，不开启新事务
	if uow, ok := ctx.Value(txKey{}).(*PgxUOW); ok {
		// 所有的钩子将挂载到最外层的事务上
		return fn(ctx, uow)
	}

	// 2. 初始化配置
	cfg := &Config{PreCommitHooks: false}
	for _, opt := range opts {
		opt(cfg)
	}

	// 3. 执行策略
	if cfg.PreCommitHooks {
		return s.executeWithPreCommitHooks(ctx, fn)
	}
	return s.executeWithPostCommitHooks(ctx, fn)
}

// 策略 A: 强一致性 (钩子失败会导致 DB 回滚)
func (s *PgxStorage) executeWithPreCommitHooks(ctx context.Context, fn func(context.Context, *PgxUOW) error) error {
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	// 安全网：未 Commit 前退出均视为回滚
	defer func() { _ = tx.Rollback(ctx) }()

	uow := &PgxUOW{Tx: tx}
	// 将 UOW 注入 Context，传递给业务函数
	txCtx := context.WithValue(ctx, txKey{}, uow)

	// 执行业务逻辑
	if err := fn(txCtx, uow); err != nil {
		s.executeRollbackHooks(uow)
		return err
	}

	// 执行 Pre-Commit 钩子
	for _, hook := range uow.onCommit {
		if err := hook(txCtx); err != nil {
			return err // 钩子报错，触发 defer Rollback
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}
	return nil
}

// 策略 B: 最终一致性 (DB 成功后执行钩子，无法回滚 DB)
func (s *PgxStorage) executeWithPostCommitHooks(ctx context.Context, fn func(context.Context, *PgxUOW) error) error {
	var onCommitHooks []func(context.Context) error

	// 使用 pgx.BeginFunc 自动管理 Commit/Rollback
	err := pgx.BeginFunc(ctx, s.db, func(tx pgx.Tx) error {
		uow := &PgxUOW{Tx: tx}
		txCtx := context.WithValue(ctx, txKey{}, uow)

		if err := fn(txCtx, uow); err != nil {
			s.executeRollbackHooks(uow)
			return err
		}

		// 暂存 Commit 钩子
		onCommitHooks = uow.onCommit
		return nil
	})
	if err != nil {
		return err
	}

	// 事务已提交，执行钩子 (Best Effort)
	for _, hook := range onCommitHooks {
		if err := hook(ctx); err != nil {
			log.Error().Err(err).Msg("Post-commit hook failed")
			// 注意：这里不再返回错误，因为主业务已成功
		}
	}

	return nil
}

func (s *PgxStorage) executeRollbackHooks(uow *PgxUOW) {
	for _, hook := range uow.onRollback {
		if err := hook(); err != nil {
			log.Error().Err(err).Msg("Rollback hook failed")
		}
	}
}

// -----------------------------------------------------------------------------
// 辅助函数
// -----------------------------------------------------------------------------

// isUniqueViolation 检查 error 是否为 PostgreSQL 的唯一键约束冲突 (Duplicate Key)
// Error Code 23505: unique_violation
func isUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		return pgErr.Code == "23505"
	}
	return false
}
