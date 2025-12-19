package persist

import (
	"context"
	"regexp"
	"time"

	"github.com/google/uuid"
	"github.com/nyaruka/phonenumbers"
	"github.com/oy3o/oidc"
)

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

	// 构造凭证列表
	creds := []*Credential{
		{
			UserID:     id,
			Type:       IdentPassword,
			Identifier: userInfo.Subject,
			Secret:     oidc.SecretBytes(hashedPassword),
			Verified:   true,
		},
	}

	// 仅当 Email 存在时才添加 Email 凭证
	if userInfo.Email != nil {
		creds = append(creds, &Credential{
			UserID:     id,
			Type:       IdentEmail,
			Identifier: *userInfo.Email,
			Secret:     nil,
			Verified:   true,
		})
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
	IdentifierChecker = map[IdenType]func(string) bool{
		IdentEmail: func(s string) bool {
			return EmailRegex.MatchString(s)
		},
		IdentPhone: func(s string) bool {
			if num, err := phonenumbers.Parse(s, ""); err != nil && phonenumbers.IsValidNumber(num) {
				return true
			}
			return false
		},
	}
)

// AuthenticateByPassword 通过标识符和密码进行认证
func (s *PgxStorage) AuthenticateByPassword(ctx context.Context, identifier, password string) (oidc.BinaryUUID, string, error) {
	// 1. 智能识别标识符类型
	var idenType IdenType
	var check func(string) bool
	for idenType, check = range IdentifierChecker {
		if check(identifier) {
			break
		}
	}
	if idenType == "" {
		return oidc.BinaryUUID(uuid.Nil), "", oidc.ErrInvalidIdentifier
	}

	// 2. 查询凭证对应的用户ID
	idCred, err := s.CredentialGetByIdentifier(ctx, idenType, identifier)
	if err != nil {
		return oidc.BinaryUUID(uuid.Nil), "", err
	}

	// 3. 查询密码
	pswCred, err := s.CredentialGetByIdentifier(ctx, IdentPassword, idCred.UserID.String())
	if err != nil {
		return oidc.BinaryUUID(uuid.Nil), "", err
	}

	// 4. 验证密码
	if err := s.hasher.Compare(ctx, pswCred.Secret, []byte(password)); err != nil {
		return oidc.BinaryUUID(uuid.Nil), "", err
	}

	return idCred.UserID, string(idenType), nil
}

// 业务逻辑

type IdentifierVerifier interface {
	// SendVerificationCode 生成、存储并发送一个验证码。
	// target 可以是邮箱地址或手机号码。
	SendVerificationCode(ctx context.Context, identType IdenType, purpose, target string) error

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

type AuthStorage interface {
	AuthenticateByPassword(ctx context.Context, identifier string, password string) (oidc.BinaryUUID, string, error)
	UserGetByID(ctx context.Context, id oidc.BinaryUUID) (*User, error)
}

// AuthenticateByPassword 通过标识符和密码进行认证
func AuthenticateByPassword(ctx context.Context, s AuthStorage, issuer *oidc.Issuer, idenifierVerifier IdentifierVerifier, req *AuthRequest) (*AuthResult, error) {
	// 1. 认证
	userID, identType, err := s.AuthenticateByPassword(ctx, req.Identifier, req.Password)
	if err != nil {
		return nil, err
	}

	// 2. 获取用户
	user, err := s.UserGetByID(ctx, userID)
	if err != nil {
		return nil, err
	}

	// 3. 检查用户是否激活
	if user.IsPending() {
		go func() {
			// 使用独立的 context 处理异步发送，避免 caller context 取消导致发送中断
			idenifierVerifier.SendVerificationCode(context.Background(), IdenType(identType), "login", req.Identifier)
		}()
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
