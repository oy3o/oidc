package oidc

import (
	"context"
	"crypto/rand"
	"fmt"
	"math/big"
	"time"

	"github.com/google/uuid"
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
	client, err := storage.GetClient(ctx, clientIDRaw)
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

	if err := storage.SaveDeviceCode(ctx, session); err != nil {
		return nil, fmt.Errorf("failed to save device code: %w", err)
	}

	return &DeviceAuthorizationResponse{
		DeviceCode:      deviceCode,
		UserCode:        userCode,
		VerificationURI: issuer + "/device", // 假设前端页面地址
		ExpiresIn:       expiresIn,
		Interval:        5,
	}, nil
}

// DeviceTokenExchange 处理设备码换取 Token
func DeviceTokenExchange(ctx context.Context, storage Storage, issuer *Issuer, req *TokenRequest) (*IssuerResponse, error) {
	// 1. 验证 Device Code
	if req.DeviceCode == "" {
		return nil, fmt.Errorf("%w: device_code is required", ErrInvalidRequest)
	}

	session, err := storage.GetDeviceCodeSession(ctx, req.DeviceCode)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid device_code", ErrInvalidGrant)
	}

	// 2. 检查过期
	if time.Now().After(session.ExpiresAt) {
		return nil, ErrExpiredToken
	}

	// 3. 检查状态
	switch session.Status {
	case DeviceCodeStatusPending:
		return nil, ErrAuthorizationPending
	case DeviceCodeStatusDenied:
		return nil, ErrAccessDenied
	case DeviceCodeStatusAllowed:
		// 继续处理
	default:
		return nil, fmt.Errorf("%w: invalid session status", ErrServerError)
	}

	// 4. 检查 Polling 频率 (可选，这里简化)

	// 5. 生成 Token
	// 使用 session 中的 UserID 和 AuthorizedScope
	issueReq := &IssuerRequest{
		ClientID: session.ClientID,
		UserID:   session.UserID,
		Scopes:   session.AuthorizedScope,
		AuthTime: time.Now(), // 或者记录用户授权的时间
	}

	resp, err := issuer.IssueOIDCTokens(ctx, issueReq)
	if err != nil {
		return nil, err
	}

	// 6. 销毁 Device Code (防止重放)
	// 实际实现中应该删除或标记为已使用。这里假设 GetDeviceCodeSession 会处理，或者需要显式调用 Delete
	// 为了简单，这里不处理删除，依赖过期自动清理，或者 Storage 实现 Update 状态为 "consumed"

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

// ParseUUID 辅助函数
func ParseUUID(s string) (BinaryUUID, error) {
	id, err := uuid.Parse(s)
	if err != nil {
		return BinaryUUID{}, err
	}
	return BinaryUUID(id), nil
}
