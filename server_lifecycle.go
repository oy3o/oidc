package oidc

import "context"

// StartBackgroundWorkers 启动所有后台 Worker
// 应在 HTTP 服务启动之前调用
// ctx 用于传递取消信号和 tracing context
func (s *Server) StartBackgroundWorkers(ctx context.Context) {
	if s.gcWorker != nil {
		s.gcWorker.Start(ctx)
	}
}

// StopBackgroundWorkers 停止所有后台 Worker
// 应在 HTTP 服务关闭时调用
func (s *Server) StopBackgroundWorkers() {
	if s.gcWorker != nil {
		s.gcWorker.Stop()
	}
}
