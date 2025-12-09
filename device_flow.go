package oidc

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
	"time"

	"github.com/rs/zerolog/log"
)

const (
	DeviceCodeStatusPending = "pending"
	DeviceCodeStatusAllowed = "allowed"
	DeviceCodeStatusDenied  = "denied"
)

type DeviceAuthorizationRequest struct {
	ClientID string `form:"client_id" json:"client_id"`
	Scope    string `form:"scope" json:"scope"`
}

type DeviceAuthorizedRequest struct {
	ClientID   string `form:"client_id" json:"client_id"`
	UserID     string `form:"user_id" json:"user_id"`
	UserCode   string `form:"user_code" json:"user_code"`
	FinalScope string `form:"final_scope" json:"final_scope"`
}

type DeviceAuthorizationResponse struct {
	DeviceCode      string `json:"device_code"`
	UserCode        string `json:"user_code"`
	VerificationURI string `json:"verification_uri"`
	ExpiresIn       int    `json:"expires_in"`
	Interval        int    `json:"interval,omitempty"` // Polling interval in seconds
}

// DeviceAuthorization 处理设备授权请求
func DeviceAuthorization(ctx context.Context, storage Storage, issuer string, req *DeviceAuthorizationRequest) (*DeviceAuthorizationResponse, error) {
	// 1. 验证 Client
	clientIDRaw, err := ParseUUID(req.ClientID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid client_id", ErrInvalidRequest)
	}
	client, err := storage.ClientFindByID(ctx, clientIDRaw)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid client", ErrInvalidClient)
	}

	// 2. 生成 Device Code 和 User Code
	deviceCode, err := RandomString(32)
	if err != nil {
		return nil, err
	}
	userCode, err := generateUserCode()
	if err != nil {
		return nil, err
	}

	// 3. 创建会话
	expiresIn := 600 // 10 minutes
	session := &DeviceCodeSession{
		DeviceCode: deviceCode,
		UserCode:   userCode,
		ClientID:   client.GetID(),
		Scope:      req.Scope,
		ExpiresAt:  time.Now().Add(time.Duration(expiresIn) * time.Second),
		Status:     DeviceCodeStatusPending,
	}

	if err := storage.DeviceCodeSave(ctx, session); err != nil {
		return nil, fmt.Errorf("failed to save device code: %w", err)
	}

	return &DeviceAuthorizationResponse{
		DeviceCode:      deviceCode,
		UserCode:        userCode,
		VerificationURI: issuer + "/oauth/device",
		ExpiresIn:       expiresIn,
		Interval:        5,
	}, nil
}

// DeviceAuthorized 处理设备授权确认 (用户在前端点击同意后调用)
func DeviceAuthorized(ctx context.Context, storage Storage, req *DeviceAuthorizedRequest) error {
	// 1. 基础参数校验
	if req.UserCode == "" {
		return fmt.Errorf("%w: user_code is required", ErrInvalidRequest)
	}
	if req.UserID == "" {
		return fmt.Errorf("%w: user_id is required", ErrInvalidRequest)
	}

	// 2. 通过 UserCode 查找会话 (Redis/Cache 层)
	session, err := storage.DeviceCodeGetByUserCode(ctx, req.UserCode)
	if err != nil {
		if errors.Is(err, ErrTokenNotFound) {
			// 为了安全，不要明确提示是 Code 不存在还是过期，统称无效
			return fmt.Errorf("%w: invalid or expired user code", ErrAccessDenied)
		}
		return err
	}

	// 3. 校验 ClientID (可选，但推荐)
	// 如果前端透传了 client_id，校验它是否与会话中的一致，防止混淆
	if req.ClientID != "" && session.ClientID.String() != req.ClientID {
		return fmt.Errorf("%w: client_id mismatch", ErrInvalidRequest)
	}

	// 4. 校验过期时间
	if time.Now().After(session.ExpiresAt) {
		return ErrExpiredToken
	}

	// 5. 校验当前状态
	// 只有 pending 状态的请求才能被批准
	if session.Status != DeviceCodeStatusPending {
		return fmt.Errorf("%w: request has already been processed", ErrInvalidRequest)
	}

	// 6. 解析并绑定 UserID
	uid, err := ParseUUID(req.UserID)
	if err != nil {
		return fmt.Errorf("%w: invalid user_id format", ErrInvalidRequest)
	}

	// 7. 更新会话状态
	session.UserID = uid
	session.Status = DeviceCodeStatusAllowed
	session.AuthTime = time.Now() // 记录用户授权时间

	// 处理 Scope：如果请求中指定了 FinalScope (用户修改了权限)，则使用它，否则使用原始 Scope
	if req.FinalScope != "" {
		// 这里可以加入 validateScopes 逻辑，确保 FinalScope 是 OriginalScope 的子集
		session.AuthorizedScope = req.FinalScope
	} else {
		session.AuthorizedScope = session.Scope
	}

	// 8. 持久化更新
	// 注意：DeviceCodeSession 的存储通常以 DeviceCode 为主键
	if err := storage.DeviceCodeUpdate(ctx, session.DeviceCode, session); err != nil {
		return fmt.Errorf("failed to update device session: %w", err)
	}

	return nil
}

// 补充：处理用户拒绝授权的逻辑 (建议添加)
func DeviceDenied(ctx context.Context, storage Storage, userCode string) error {
	if userCode == "" {
		return fmt.Errorf("%w: user_code is required", ErrInvalidRequest)
	}

	session, err := storage.DeviceCodeGetByUserCode(ctx, userCode)
	if err != nil {
		return err
	}

	if session.Status != DeviceCodeStatusPending {
		return nil // 已经被处理过，忽略
	}

	// 更新状态为 Denied
	session.Status = DeviceCodeStatusDenied

	// 更新存储
	// 客户端下一次轮询时会收到 access_denied 错误
	return storage.DeviceCodeUpdate(ctx, session.DeviceCode, session)
}

// DeviceTokenExchange 处理设备码换取 Token
func DeviceTokenExchange(ctx context.Context, storage Storage, issuer *Issuer, req *TokenRequest) (*IssuerResponse, error) {
	// 1. 验证 Device Code
	if req.DeviceCode == "" {
		return nil, fmt.Errorf("%w: device_code is required", ErrInvalidRequest)
	}

	session, err := storage.DeviceCodeGet(ctx, req.DeviceCode)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid device_code", ErrInvalidGrant)
	}

	// 2. 检查过期
	if time.Now().After(session.ExpiresAt) {
		// 过期了也可以顺手清理一下
		_ = storage.DeviceCodeDelete(ctx, req.DeviceCode)
		return nil, ErrExpiredToken
	}

	// 3. 状态检查与处理
	switch session.Status {
	case DeviceCodeStatusPending:
		// 还在等待用户操作，返回特定错误让客户端继续轮询
		return nil, ErrAuthorizationPending

	case DeviceCodeStatusDenied:
		// 用户明确拒绝了
		// 关键：返回 AccessDenied 错误，并清理 Session，让这个 Code 作废
		_ = storage.DeviceCodeDelete(ctx, req.DeviceCode)
		return nil, ErrAccessDenied

	case DeviceCodeStatusAllowed:
		// 用户已同意，继续下方发证逻辑
		// (不要在这里清理，要在发证成功后清理)

	default:
		return nil, fmt.Errorf("%w: invalid session status", ErrServerError)
	}

	// 4. 生成 Token (Access Token + Refresh Token + ID Token)
	issueReq := &IssuerRequest{
		ClientID: session.ClientID,
		UserID:   session.UserID,
		Scopes:   session.AuthorizedScope, // 使用用户最终授权的 Scope
		AuthTime: session.AuthTime,
	}

	resp, err := issuer.IssueOIDCTokens(ctx, issueReq)
	if err != nil {
		return nil, err
	}

	// 5. 成功发证后，立即销毁 Device Code Session
	// 防止重放攻击 (RFC 8628 要求 Device Code 是一次性的)
	if err := storage.DeviceCodeDelete(ctx, req.DeviceCode); err != nil {
		// 如果清理失败，记录日志但不阻断流程，因为 Token 已经生成
		log.Error().Err(err).Msg("Failed to cleanup device code session")
	}

	return resp, nil
}

// generateUserCode 生成易读的 8 位用户码 (BCDFGHJKLMNPQRSTVWXZ)
func generateUserCode() (string, error) {
	const charset = "BCDFGHJKLMNPQRSTVWXZ"
	b := make([]byte, 8)
	for i := range b {
		num, err := rand.Int(rand.Reader, big.NewInt(int64(len(charset))))
		if err != nil {
			return "", err
		}
		b[i] = charset[num.Int64()]
	}
	return string(b), nil
}
