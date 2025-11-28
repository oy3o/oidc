package oidc

import (
	"fmt"
	"net/http"
	"time"
)

// DPoPTimeSkewInfo 记录 DPoP 时间偏差信息
type DPoPTimeSkewInfo struct {
	ServerTime time.Time
	ClientTime time.Time
	Skew       time.Duration
}

// String 返回人类可读的时间偏差信息
func (d DPoPTimeSkewInfo) String() string {
	return fmt.Sprintf("server=%s, client=%s, skew=%s",
		d.ServerTime.Format(time.RFC3339),
		d.ClientTime.Format(time.RFC3339),
		d.Skew)
}

// SetServerTimeHeader 设置服务器时间响应头
// 帮助客户端计算时间偏差
func SetServerTimeHeader(w http.ResponseWriter) {
	if w != nil {
		w.Header().Set("Date", time.Now().UTC().Format(http.TimeFormat))
	}
}

// DPoPTimeSkewError DPoP 时间偏差错误
// 包含详细的时间信息以便客户端调试
type DPoPTimeSkewError struct {
	Info DPoPTimeSkewInfo
	Err  error
}

func (e *DPoPTimeSkewError) Error() string {
	return fmt.Sprintf("%v (time skew: %s)", e.Err, e.Info)
}

func (e *DPoPTimeSkewError) Unwrap() error {
	return e.Err
}
