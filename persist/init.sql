-- ----------------------------------------------------------------------------
-- 初始化与扩展
-- ----------------------------------------------------------------------------

-- 启用 pgcrypto 以支持 gen_random_uuid()
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- ----------------------------------------------------------------------------
-- 1. Users 表 (核心用户模型)
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    
    -- 角色与状态 (使用 Check 约束模拟枚举)
    role VARCHAR(20) NOT NULL DEFAULT 'user',
    status VARCHAR(20) NOT NULL DEFAULT 'active',
    
    -- 最后登录时间 (可为 NULL)
    last_login_at TIMESTAMPTZ,
    
    -- 审计时间
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- 约束
    CONSTRAINT chk_users_role CHECK (role IN ('admin', 'user', 'guest')),
    CONSTRAINT chk_users_status CHECK (status IN ('pending', 'active', 'suspended', 'deactivated'))
);

-- 索引
CREATE INDEX IF NOT EXISTS idx_users_role ON users(role);
CREATE INDEX IF NOT EXISTS idx_users_status ON users(status);
CREATE INDEX IF NOT EXISTS idx_users_last_login_at ON users(last_login_at);

-- ----------------------------------------------------------------------------
-- 2. Profiles 表 (用户资料，1:1 关系)
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS profiles (
    -- 主键也是外键，构成 1:1 关系
    user_id UUID PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    
    -- 普通文本字段 (Not Null Default '')
    name VARCHAR(100) NOT NULL DEFAULT '',
    given_name VARCHAR(100) NOT NULL DEFAULT '',
    family_name VARCHAR(100) NOT NULL DEFAULT '',
    nickname VARCHAR(100) NOT NULL DEFAULT '',
    preferred_username VARCHAR(100) NOT NULL DEFAULT '',
    profile VARCHAR(255) NOT NULL DEFAULT '',
    picture VARCHAR(255) NOT NULL DEFAULT '',
    website VARCHAR(255) NOT NULL DEFAULT '',
    
    -- 唯一索引字段 (允许 NULL)
    email VARCHAR(255),
    email_verified BOOLEAN NOT NULL DEFAULT FALSE,
    
    gender VARCHAR(50) NOT NULL DEFAULT '',
    birthdate VARCHAR(20) NOT NULL DEFAULT '',
    zoneinfo VARCHAR(100) NOT NULL DEFAULT '',
    locale VARCHAR(50) NOT NULL DEFAULT '',
    
    phone_number VARCHAR(50),
    phone_number_verified BOOLEAN NOT NULL DEFAULT FALSE,
    
    -- 元数据 (JSONB)
    metadata JSONB,
    
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- 唯一索引 (Postgres 默认允许唯一索引中有多个 NULL 值)
CREATE UNIQUE INDEX IF NOT EXISTS idx_profiles_email ON profiles(email);
CREATE UNIQUE INDEX IF NOT EXISTS idx_profiles_phone_number ON profiles(phone_number);

-- ----------------------------------------------------------------------------
-- 3. Credentials 表 (认证凭证)
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS credentials (
    -- 物理主键
    id BIGSERIAL PRIMARY KEY,
    
    -- 外键关联
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    
    -- 核心认证信息
    type VARCHAR(50) NOT NULL,
    identifier VARCHAR(255) NOT NULL,
    
    -- 密钥 (Hash 或 Token) 可为空作为 Magic Link
    secret VARCHAR(255),
    
    -- 状态
    verified BOOLEAN NOT NULL DEFAULT FALSE,
    
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    
    -- 约束
    CONSTRAINT chk_credentials_type CHECK (type IN ('password', 'email', 'phone', 'webauthn', 'google', 'github'))
);

-- 索引
CREATE INDEX IF NOT EXISTS idx_credentials_user_id ON credentials(user_id);

-- 复合唯一索引 (idx_cred_type_identifier)
CREATE UNIQUE INDEX IF NOT EXISTS idx_cred_type_identifier ON credentials(type, identifier);

-- ----------------------------------------------------------------------------
-- 4. OIDC Clients 表 (客户端元数据)
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS oidc_clients (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    
    owner_id UUID, -- 如果需要强关联用户，可加 REFERENCES users(id)
    
    -- 密钥 (Confidential Client)
    secret VARCHAR(255),
    
    name VARCHAR(100) NOT NULL,
    
    -- 数组类型，Go 结构体映射为 JSON 字符串存储在 TEXT 中
    redirect_uris TEXT,
    grant_types TEXT,
    scope TEXT,
    
    logo_uri VARCHAR(255),
    token_endpoint_auth_method VARCHAR(50) DEFAULT 'client_secret_basic',
    is_confidential_client BOOLEAN DEFAULT FALSE,
    
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_oidc_clients_owner_id ON oidc_clients(owner_id);

-- ----------------------------------------------------------------------------
-- 5. Auth Code Session 表 (短期临时数据)
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS oidc_auth_codes (
    code VARCHAR(255) PRIMARY KEY,
    
    client_id UUID, -- 对应 oidc_clients(id)
    user_id UUID,   -- 对应 users(id)
    
    auth_time TIMESTAMPTZ,
    expires_at TIMESTAMPTZ,
    
    acr VARCHAR(255),
    amr JSONB, -- 对应 Go tag type:jsonb
    
    redirect_uri VARCHAR(255),
    scope TEXT,
    nonce VARCHAR(255),
    
    -- PKCE
    code_challenge VARCHAR(255) NOT NULL,
    code_challenge_method VARCHAR(20) DEFAULT 'S256',
    
    -- DPoP
    d_pop_jkt VARCHAR(255)
);

CREATE INDEX IF NOT EXISTS idx_oidc_auth_codes_client_id ON oidc_auth_codes(client_id);
CREATE INDEX IF NOT EXISTS idx_oidc_auth_codes_user_id ON oidc_auth_codes(user_id);
CREATE INDEX IF NOT EXISTS idx_oidc_auth_codes_expires_at ON oidc_auth_codes(expires_at); -- 用于 GC
CREATE INDEX IF NOT EXISTS idx_oidc_auth_codes_d_pop_jkt ON oidc_auth_codes(d_pop_jkt);

-- ----------------------------------------------------------------------------
-- 6. Device Code Session 表 (设备流)
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS oidc_device_codes (
    device_code VARCHAR(255) PRIMARY KEY,
    
    user_code VARCHAR(50) NOT NULL,
    
    client_id UUID,
    user_id UUID,
    
    scope TEXT,
    authorized_scope TEXT,
    
    expires_at TIMESTAMPTZ,
    last_polled TIMESTAMPTZ,
    auth_time TIMESTAMPTZ,
    
    status VARCHAR(20) DEFAULT 'pending'
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_oidc_device_codes_user_code ON oidc_device_codes(user_code);
CREATE INDEX IF NOT EXISTS idx_oidc_device_codes_client_id ON oidc_device_codes(client_id);
CREATE INDEX IF NOT EXISTS idx_oidc_device_codes_user_id ON oidc_device_codes(user_id);
CREATE INDEX IF NOT EXISTS idx_oidc_device_codes_expires_at ON oidc_device_codes(expires_at);
CREATE INDEX IF NOT EXISTS idx_oidc_device_codes_status ON oidc_device_codes(status);

-- ----------------------------------------------------------------------------
-- 7. Refresh Token Session 表
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS oidc_refresh_tokens (
    -- ID 通常是 SHA256 哈希后的 Hex 字符串 (64 chars)
    id VARCHAR(64) PRIMARY KEY,
    
    client_id UUID,
    user_id UUID,
    
    scope TEXT,
    
    auth_time TIMESTAMPTZ,
    expires_at TIMESTAMPTZ,
    
    nonce VARCHAR(255),
    acr VARCHAR(255),
    amr TEXT -- Go tag type:text (StringSlice)
);

CREATE INDEX IF NOT EXISTS idx_oidc_refresh_tokens_client_id ON oidc_refresh_tokens(client_id);
CREATE INDEX IF NOT EXISTS idx_oidc_refresh_tokens_user_id ON oidc_refresh_tokens(user_id);
CREATE INDEX IF NOT EXISTS idx_oidc_refresh_tokens_expires_at ON oidc_refresh_tokens(expires_at);

-- ----------------------------------------------------------------------------
-- 8. JWK 表 (密钥存储，补充)
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS jwks (
    kid VARCHAR(255) PRIMARY KEY,
    jwk TEXT NOT NULL, -- 存储 JSON 字符串
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
