package persist

import (
	"context"
	"errors"
	"regexp"
	"time"

	"github.com/Masterminds/squirrel"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nyaruka/phonenumbers"
	"github.com/oy3o/oidc"
)

// psql 是全局复用的 SQL 构建器，预设为 PostgreSQL 格式 ($1, $2...)
var psql = squirrel.StatementBuilder.PlaceholderFormat(squirrel.Dollar)

// PgxStorage 实现 oidc.Persistence 接口
type PgxStorage struct {
	db     *pgxpool.Pool
	hasher oidc.Hasher
}

// 确保 Storage 实现了 oidc.Persistence 接口
var (
	_ oidc.Persistence = (*PgxStorage)(nil)
	_ Persistence      = (*PgxStorage)(nil)
)

// New 创建一个新的 Storage 实例。
// db: 必须是一个已经连接好的 pgx 连接池。
// hasher: 用于密码哈希处理的接口实现。
func NewPgx(db *pgxpool.Pool, hasher oidc.Hasher) *PgxStorage {
	return &PgxStorage{
		db:     db,
		hasher: hasher,
	}
}

// Close 关闭底层的数据库连接池 (如果需要手动管理关闭时调用)
func (s *PgxStorage) Close() {
	s.db.Close()
}

// execTx 辅助函数：简化事务处理逻辑
// 它会自动开启事务，执行 fn，如果有错误则回滚，无错误则提交
func (s *PgxStorage) execTx(ctx context.Context, fn func(tx pgx.Tx) error) error {
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return err
	}

	defer func() {
		if p := recover(); p != nil {
			_ = tx.Rollback(ctx)
			panic(p) // 重新抛出 panic，避免吞掉恐慌
		}
	}()

	if err := fn(tx); err != nil {
		_ = tx.Rollback(ctx)
		return err
	}

	return tx.Commit(ctx)
}

// isUniqueViolation 检查 error 是否为 PostgreSQL 的唯一键约束冲突 (Duplicate Key)
// Error Code 23505: unique_violation
func isUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		return pgErr.Code == "23505"
	}
	return false
}

// 测试用接口实现

const DefaultPassword = "12345678"

// UserCreateInfo 创建用户
func (s *PgxStorage) UserCreateInfo(ctx context.Context, userInfo *oidc.UserInfo) error {
	t := time.Now()
	id, err := oidc.ParseUUID(userInfo.Subject)
	if err != nil {
		return err
	}

	hashedPassword, err := s.hasher.Hash(ctx, []byte(DefaultPassword))
	if err != nil {
		return err
	}

	user := &User{
		ID:          id,
		Role:        RoleUser,
		Status:      StatusActive,
		LastLoginAt: &t,
	}

	creds := []*Credential{
		{
			UserID:     id,
			Type:       CredentialTypePassword,
			Identifier: userInfo.Subject,
			Secret:     oidc.SecretBytes(hashedPassword),
			Verified:   true,
		},
		{
			UserID:     id,
			Type:       CredentialTypeEmail,
			Identifier: *userInfo.Email,
			Secret:     nil,
			Verified:   true,
		},
	}

	profile := &Profile{
		UserID: id,
		Name:   *userInfo.Name,
		Email:  userInfo.Email,
	}

	return s.UserCreate(ctx, user, creds, profile)
}

var (
	EmailRegex        = regexp.MustCompile(`^(?i)[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,16}$`)
	IdentifierChecker = map[CredentialType]func(string) bool{
		CredentialTypeEmail: func(s string) bool {
			return EmailRegex.MatchString(s)
		},
		CredentialTypePhone: func(s string) bool {
			if num, err := phonenumbers.Parse(s, ""); err != nil && phonenumbers.IsValidNumber(num) {
				return true
			}
			return false
		},
	}
)

// AuthenticateByPassword 通过标识符和密码进行认证
func (s *PgxStorage) AuthenticateByPassword(ctx context.Context, identifier, password string) (oidc.BinaryUUID, error) {
	// 1. 智能识别标识符类型
	var credType CredentialType
	var check func(string) bool
	for credType, check = range IdentifierChecker {
		if check(identifier) {
			break
		}
	}
	if credType == "" {
		return oidc.BinaryUUID(uuid.Nil), oidc.ErrInvalidIdentifier
	}

	// 2. 查询凭证
	cred, err := s.CredentialFindByIdentifier(ctx, credType, identifier)
	if err != nil {
		return oidc.BinaryUUID(uuid.Nil), err
	}

	// 3. 验证密码
	if err := s.hasher.Compare(ctx, cred.Secret, []byte(password)); err != nil {
		return oidc.BinaryUUID(uuid.Nil), err
	}

	return cred.UserID, nil
}

// 业务逻辑

type IdentifierVerifier interface {
	// SendVerificationCode 生成、存储并发送一个验证码。
	// target 可以是邮箱地址或手机号码。
	SendVerificationCode(ctx context.Context, purpose, target string) error

	// VerifyCode 验证用户提供的验证码是否正确。
	VerifyCode(ctx context.Context, purpose, target, code string) error
}

type AuthRequest struct {
	Identifier string `json:"identifier"`
	Password   string `json:"password"`
}

// AuthResult 封装了认证成功后的结果
type AuthResult struct {
	User                *User
	PasswordChangeToken string
}

// AuthenticateByPassword 通过标识符和密码进行认证
func AuthenticateByPassword(ctx context.Context, s *PgxStorage, issuer *oidc.Issuer, idenifierVerifier IdentifierVerifier, req *AuthRequest) (*AuthResult, error) {
	// 1. 认证
	userID, err := s.AuthenticateByPassword(ctx, req.Identifier, req.Password)
	if err != nil {
		return nil, err
	}

	// 2. 获取用户
	user, err := s.UserFindByID(ctx, userID)
	if err != nil {
		return nil, err
	}

	// 3. 检查用户是否激活
	if user.IsPending() {
		if err := idenifierVerifier.SendVerificationCode(ctx, "login", req.Identifier); err != nil {
			return nil, err
		}
		return nil, oidc.ErrUserNotConfirmed
	}

	// 4. 用户未激活禁止登录
	if !user.IsActive() {
		return nil, oidc.ErrUserForbidden
	}

	// 5. 检查是否使用了默认密码
	changeToken := ""
	if req.Password == DefaultPassword {
		result, err := issuer.IssuePasswordResetAccessToken(ctx, &oidc.IssuerRequest{
			ClientID: oidc.BinaryUUID([]byte(issuer.Issuer())),
			UserID:   user.ID,
			Audience: []string{issuer.Issuer()},
		})
		if err != nil {
			return nil, err
		}
		changeToken = result.AccessToken
	}

	// 6. 返回结果
	return &AuthResult{
		User:                user,
		PasswordChangeToken: changeToken,
	}, nil
}
