# OIDC: Next-Gen OpenID Connect Library

[![Go Report Card](https://goreportcard.com/badge/github.com/oy3o/oidc)](https://goreportcard.com/report/github.com/oy3o/oidc)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

[中文](./README.zh.md) | [English](./README.md)

`oidc` 是一个**安全优先**、**架构解耦**且符合**现代标准（OAuth 2.1 Ready）**的 Go 语言 OpenID Connect 库。

它不仅仅是一个协议实现，更是一套**生产级的认证基础设施**。它采用了**分层存储架构**，完美平衡了数据持久性（SQL）与高并发性能（Redis），内置了针对高并发场景的抗 DoS 设计、分布式一致性支持，并原生支持 DPoP、PAR、PKCE 等前沿安全规范。

## 核心特性

*   **全标准覆盖**: 完整实现 OIDC Core 1.0 与 RFC 6749 (OAuth 2.0)。
*   **分层存储架构 (Tiered Storage)**:
    *   **持久层 (SQL)**: 负责存储 Client、User、Refresh Token 等“资产型”数据，确保存储可靠。
    *   **缓存层 (Redis)**: 负责 Auth Code、分布式锁、黑名单、防重放等“高频/临时”数据，确保高性能。
    *   **混合防重放**: Refresh Token 轮换时的**宽限期 (Grace Period)** 检查由 Redis 处理，兼顾性能与一致性。
*   **前沿安全防御**:
    *   **DPoP (RFC 9449)**: 应用层防令牌窃取与重放（Sender-Constrained Tokens）。
    *   **PAR (RFC 9126)**: 推送授权请求，隐藏参数，防止前端篡改。
    *   **PKCE (RFC 7636)**: 强制开启，杜绝授权码拦截攻击。
*   **防御性架构**:
    *   **混合刷新令牌 (Hybrid RT)**: 采用“结构化令牌 + 数据库索引”设计，在查库前通过 CPU 计算验证签名与过期，有效防御数据库 DoS 攻击。
    *   **密钥轮换**: 支持自动化的非对称密钥轮换，利用 Redis 实现多实例间的即时感知。
*   **可观测性**: 深度集成 `o11y`，自动输出结构化日志、分布式追踪与关键指标。

## 安装

```bash
go get github.com/oy3o/oidc
```

## 快速开始

构建一个生产级的 OIDC 服务器，你需要组合 **SQL** (持久化) 和 **Redis** (缓存) 两个存储层。

### 1. 初始化与配置

```go
package main

import (
    "context"
    "time"
    "net/http"
    
    "github.com/redis/go-redis/v9"
    "github.com/oy3o/oidc"
    "github.com/oy3o/oidc/gorm"  // SQL 实现
    "github.com/oy3o/oidc/redis" // Redis 实现
)

func main() {
    ctx := context.Background()

    // 1. 初始化持久层 (SQL) -> 负责资产数据 (Client, User, RefreshToken)
    // db 为 *gorm.DB 实例
    persistStore := gorm.NewGormStorage(db, &MyHasher{})
    
    // 2. 初始化缓存层 (Redis) -> 负责高频状态 (AuthCode, Lock, GracePeriod)
    // rdb 为 *redis.Client 实例
    cacheStore := redis.NewRedisStorage(rdb)

    // 3. [关键] 组合分层存储
    // TieredStorage 会自动将请求路由到正确的存储层
    storage := oidc.NewTieredStorage(persistStore, cacheStore)

    // 4. 初始化密钥管理器
    // 自动利用 TieredStorage 实现 L1(内存)+L2(Redis)+L3(SQL) 多级缓存
    km := oidc.NewKeyManager(storage)
    if _, _, err := km.GetSigningKey(ctx); err != nil {
        km.Generate(ctx, oidc.KEY_RSA, true)
    }

    // 5. 初始化 HMAC 密钥管理器
    sm := oidc.NewSecretManager()
    sm.AddKey("hmac-key-1", "your-32-byte-hex-secret...")

    // 6. 创建 Server
    server, err := oidc.NewServer(oidc.ServerConfig{
        Issuer:         "https://auth.example.com",
        Storage:        storage, // 传入组合后的存储
        Hasher:         &MyHasher{},
        SecretManager:  sm,
        AccessTokenTTL: 1 * time.Hour,
    })
    if err != nil {
        panic(err)
    }

    // 7. 注册路由
    // Note: httpx adapters are in the 'oidc/httpx' package
    // mux.Handle("POST /token", oidc_httpx.TokenHandler(server))
    // ...
    
    http.ListenAndServe(":8080", nil)
}
```

## 高级安全特性

### DPoP (应用层防重放)

DPoP (Demonstration of Proof-of-Possession) 将 Access Token 绑定到客户端的私钥，即使 Token 被窃取也无法使用。

```go
// 启用 DPoP 中间件 (replayCache 通常使用 Redis 实现)
mux.Handle("/token", oidc.DPoPRequiredMiddleware(cacheStore)(
    httpx.NewHandler(oidc.HandleToken(server))
))
```

### PAR (推送授权请求)

PAR (Pushed Authorization Requests) 要求客户端先将参数推送到后端，换取 `request_uri`，再进行重定向。这避免了 URL 过长和敏感参数泄露。

```go
// 注册 PAR 端点 (数据存入 Redis，TTL 60秒)
mux.Handle("POST /par", oidc_httpx.PARHandler(server))
```

## 支持的标准 (RFCs)

| 规范 | 描述 | 支持状态 |
| :--- | :--- | :--- |
| **OIDC Core 1.0** | OpenID Connect Core Functionality | ✅ 完全支持 |
| **RFC 6749** | OAuth 2.0 Framework | ✅ 完全支持 |
| **RFC 7636** | PKCE (Proof Key for Code Exchange) | ✅ 强制开启 |
| **RFC 7009** | Token Revocation | ✅ 支持 |
| **RFC 7662** | Token Introspection | ✅ 支持 |
| **RFC 8628** | Device Authorization Grant (Device Flow) | ✅ 支持 |
| **RFC 9126** | Pushed Authorization Requests (PAR) | ✅ 支持 |
| **RFC 9449** | DPoP (Demonstration of Proof-of-Possession) | ✅ 支持 |

---

> **注意**: 本库依赖 `github.com/oy3o/o11y` 进行日志和指标记录，请确保在应用启动时正确初始化 o11y 配置。
