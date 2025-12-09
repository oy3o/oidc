# OIDC: Next-Gen OpenID Connect Library

[![Go Report Card](https://goreportcard.com/badge/github.com/oy3o/oidc)](https://goreportcard.com/report/github.com/oy3o/oidc)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

[中文](./README.zh.md) | [English](./README.md)

`oidc` is a **security-first**, **architecture-decoupled**, and **OAuth 2.1 ready** OpenID Connect library for Go.

It goes beyond a simple protocol implementation to provide **production-grade authentication infrastructure**. It features a **Tiered Storage Architecture** that perfectly balances data durability (SQL) with high-concurrency performance (Redis), along with built-in defenses against DoS attacks, distributed consistency support, and native support for cutting-edge security standards like DPoP, PAR, and PKCE.

## Core Features

*   **Standard Compliance**: Full implementation of OIDC Core 1.0 and RFC 6749 (OAuth 2.0).
*   **Tiered Storage Architecture**:
    *   **Persistence Layer (SQL)**: Stores "asset" data like Clients, Users, and Refresh Tokens.
    *   **Cache Layer (Redis)**: Handles high-frequency/ephemeral data like Auth Codes, Distributed Locks, Blacklists, and Replay Caches.
    *   **Hybrid Replay Protection**: Manages **Grace Period** for Refresh Token rotation via Redis, ensuring both performance and consistency.
*   **Cutting-Edge Security**:
    *   **DPoP (RFC 9449)**: Application-layer proof-of-possession to prevent token theft and replay (Sender-Constrained Tokens).
    *   **PAR (RFC 9126)**: Pushed Authorization Requests to hide parameters and prevent frontend tampering.
    *   **PKCE (RFC 7636)**: Enforced by default to prevent authorization code interception.
*   **Defensive Architecture**:
    *   **Hybrid Refresh Tokens**: Uses "Structured Token + DB Index" design. Signatures and expiration are verified via CPU before any database lookup, effectively mitigating DB DoS attacks.
    *   **Key Rotation**: Supports automated asymmetric key rotation with Redis-based coordination for zero-downtime updates across multiple instances.
*   **Observability**: Deep integration with `o11y` for structured logging, distributed tracing, and key metrics.

## Installation

```bash
go get github.com/oy3o/oidc
```

## Quick Start

To build a production-grade OIDC server, you combine **SQL** (Persistence) and **Redis** (Cache).

### 1. Initialization

```go
package main

import (
    "context"
    "net/http"
    "time"
    
    "github.com/redis/go-redis/v9"
    "github.com/oy3o/oidc"
    "github.com/oy3o/oidc/persist"
    "github.com/oy3o/oidc/cache"
)

func main() {
    ctx := context.Background()

    // 1. Init Persistence Layer (SQL) -> Assets (Client, User, RT)
    persistStore := persist.NewPgx(db, &MyHasher{})
    
    // 2. Init Cache Layer (Redis) -> Ephemeral (AuthCode, Lock, DPoP)
    cacheStore := cache.NewRedis(redisClient)

    // 3. [Crucial] Compose Tiered Storage
    // Requests are automatically routed to the correct layer
    storage := oidc.NewTieredStorage(persistStore, cacheStore)

    // 4. Init Key Manager (Auto L1+L2+L3 Caching)
    km := oidc.NewKeyManager(storage)
    // Generate initial key if none exists
    if _, _, err := km.GetSigningKey(ctx); err != nil {
        km.Generate(ctx, oidc.KEY_RSA, true)
    }

    // 5. Init HMAC Secret Manager (for Refresh Token signatures)
    sm := oidc.NewSecretManager()
    sm.AddKey("hmac-key-1", "your-32-byte-hex-secret...")

    // 6. Create Server
    server, err := oidc.NewServer(oidc.ServerConfig{
        Issuer:         "https://auth.example.com",
        Storage:        storage,
        Hasher:         &MyHasher{},
        SecretManager:  sm,
        AccessTokenTTL: 1 * time.Hour,
    })
    if err != nil {
        panic(err)
    }

    // 7. Register Routes (using httpx adapters)
    // Note: httpx adapters are in the 'oidc/httpx' package
    // mux.Handle("POST /token", oidc_httpx.TokenHandler(server))
    // ...
}
```

## Advanced Security

### DPoP (Sender-Constrained Tokens)

DPoP binds Access Tokens to the client's private key. Even if stolen, the token cannot be used without the corresponding private key signature.

```go
// Enable DPoP Middleware (replayCache is usually Redis)
mux.Handle("POST /token", oidc.DPoPRequiredMiddleware(cacheStore)(
    httpx.NewHandler(oidc_httpx.TokenHandler(server))
))
```

### PAR (Pushed Authorization Requests)

PAR requires clients to push parameters to the backend first to exchange for a `request_uri`.

```go
// Register PAR Endpoint (Data stored in Redis, TTL 60s)
mux.Handle("POST /par", oidc_httpx.PARHandler(server))
```

## Supported Standards (RFCs)

| Spec | Description | Status |
| :--- | :--- | :--- |
| **OIDC Core 1.0** | OpenID Connect Core | ✅ Full |
| **RFC 6749** | OAuth 2.0 Framework | ✅ Full |
| **RFC 7636** | PKCE | ✅ Enforced |
| **RFC 7009** | Token Revocation | ✅ Supported |
| **RFC 7662** | Token Introspection | ✅ Supported |
| **RFC 8628** | Device Flow | ✅ Supported |
| **RFC 9126** | PAR (Pushed Authorization Requests) | ✅ Supported |
| **RFC 9449** | DPoP | ✅ Supported |
```

> **Note:** This library relies on `github.com/oy3o/o11y` for logging and metrics. Please ensure that the o11y configuration is initialized correctly when the application starts.
