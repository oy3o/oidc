import * as jose from 'jose';

// =============================================================================
// Types & Interfaces
// =============================================================================

export interface ClientConfig {
    issuer: string;
    clientId: string;
    clientSecret?: string; // 仅在服务端环境使用，浏览器端请勿配置
    redirectUri?: string;
    scopes?: string[];
}

export interface TokenResponse {
    access_token: string;
    token_type: string;
    refresh_token?: string;
    expires_in: number;
    id_token?: string;
    scope?: string;
}

export interface UserInfo {
    sub: string;
    name?: string;
    picture?: string;
    email?: string;
    [key: string]: any;
}

export interface DiscoveryDocument {
    authorization_endpoint: string;
    token_endpoint: string;
    jwks_uri: string;
    userinfo_endpoint: string;
    revocation_endpoint: string;
    introspection_endpoint: string;
    device_authorization_endpoint: string;
    pushed_authorization_request_endpoint?: string;
}

export interface DeviceAuthorizationResponse {
    device_code: string;
    user_code: string;
    verification_uri: string;
    expires_in: number;
    interval?: number;
}

// =============================================================================
// OIDC Client Class
// =============================================================================

export class OIDCClient {
    private config: ClientConfig;
    private discovery?: DiscoveryDocument;
    private dpopPrivateKey?: jose.KeyLike;
    private dpopPublicKey?: jose.KeyLike;

    constructor(config: ClientConfig) {
        this.config = config;
    }

    /**
     * 初始化：自动发现 OIDC 配置
     */
    async discover(): Promise<void> {
        const wellKnownUrl = `${this.config.issuer.replace(/\/$/, '')}/.well-known/openid-configuration`;
        const response = await fetch(wellKnownUrl);
        if (!response.ok) throw new Error(`Failed to discover issuer: ${response.statusText}`);
        this.discovery = await response.json();
    }

    /**
     * 启用 DPoP 支持 (生成新的非对称密钥对)
     * 建议在应用初始化时调用，并将 key 存储在 IndexedDB 中以保持会话持久性
     */
    async enableDPoP(): Promise<void> {
        const { privateKey, publicKey } = await jose.generateKeyPair('ES256');
        this.dpopPrivateKey = privateKey;
        this.dpopPublicKey = publicKey;
    }

    /**
     * 生成 PKCE 参数
     */
    async generatePKCE() {
        const verifier = this.generateRandomString(43);
        const encoder = new TextEncoder();
        const data = encoder.encode(verifier);
        const hash = await crypto.subtle.digest('SHA-256', data);
        const challenge = this.base64UrlEncode(new Uint8Array(hash));
        return { verifier, challenge, method: 'S256' };
    }

    // ===========================================================================
    // Authorization Flow (Code & PAR)
    // ===========================================================================

    /**
     * 构建标准授权 URL
     */
    buildAuthorizeURL(state: string, nonce: string, codeChallenge?: string): string {
        this.checkDiscovery();
        const params = new URLSearchParams(this.baseAuthParams(state));
        params.append('nonce', nonce);
        if (codeChallenge) {
            params.append('code_challenge', codeChallenge);
            params.append('code_challenge_method', 'S256');
        }
        return `${this.discovery!.authorization_endpoint}?${params.toString()}`;
    }

    /**
     * Pushed Authorization Request (PAR) - RFC 9126
     * 将参数推送到后端，换取 request_uri，提高安全性
     */
    async pushAuthorize(state: string, nonce: string, codeChallenge: string): Promise<{ authURL: string; requestURI: string }> {
        this.checkDiscovery();
        const endpoint = this.discovery!.pushed_authorization_request_endpoint;
        if (!endpoint) throw new Error('Server does not support PAR');

        const params = new URLSearchParams(this.baseAuthParams(state));
        params.append('nonce', nonce);
        params.append('code_challenge', codeChallenge);
        params.append('code_challenge_method', 'S256');

        // PAR 需要客户端认证
        const headers = await this.buildHeaders('POST', endpoint);

        const response = await fetch(endpoint, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
                ...headers,
            },
            body: params.toString(),
        });

        const data = await this.handleResponse(response);
        const requestURI = data.request_uri;

        const authParams = new URLSearchParams();
        authParams.append('client_id', this.config.clientId);
        authParams.append('request_uri', requestURI);

        return {
            authURL: `${this.discovery!.authorization_endpoint}?${authParams.toString()}`,
            requestURI,
        };
    }

    // ===========================================================================
    // Token Exchange
    // ===========================================================================

    /**
     * 使用授权码换取 Token
     */
    async exchangeAuthorizationCode(code: string, codeVerifier: string): Promise<TokenResponse> {
        const params = new URLSearchParams();
        params.append('grant_type', 'authorization_code');
        params.append('code', code);
        params.append('redirect_uri', this.config.redirectUri || '');
        params.append('code_verifier', codeVerifier);

        return this.doTokenRequest(params);
    }

    /**
     * 刷新 Token
     */
    async exchangeRefreshToken(refreshToken: string): Promise<TokenResponse> {
        const params = new URLSearchParams();
        params.append('grant_type', 'refresh_token');
        params.append('refresh_token', refreshToken);
        return this.doTokenRequest(params);
    }

    /**
     * 客户端凭证模式 (M2M) - 仅限服务端使用
     */
    async exchangeClientCredentials(scope?: string[]): Promise<TokenResponse> {
        const params = new URLSearchParams();
        params.append('grant_type', 'client_credentials');
        const finalScopes = scope || this.config.scopes;
        if (finalScopes) {
            params.append('scope', finalScopes.join(' '));
        }
        return this.doTokenRequest(params);
    }

    // ===========================================================================
    // Device Flow
    // ===========================================================================

    /**
     * 发起设备授权请求
     */
    async requestDeviceAuthorization(): Promise<DeviceAuthorizationResponse> {
        this.checkDiscovery();
        const endpoint = this.discovery!.device_authorization_endpoint;

        const params = new URLSearchParams();
        params.append('client_id', this.config.clientId);
        if (this.config.scopes) {
            params.append('scope', this.config.scopes.join(' '));
        }

        const headers = await this.buildHeaders('POST', endpoint);

        const response = await fetch(endpoint, {
            method: 'POST',
            headers: { 'Content-Type': 'application/x-www-form-urlencoded', ...headers },
            body: params.toString()
        });

        return this.handleResponse(response);
    }

    /**
     * 轮询设备 Token
     */
    async pollDeviceToken(deviceCode: string, intervalSeconds: number = 5): Promise<TokenResponse> {
        return new Promise((resolve, reject) => {
            const check = async () => {
                const params = new URLSearchParams();
                params.append('grant_type', 'urn:ietf:params:oauth:grant-type:device_code');
                params.append('device_code', deviceCode);
                params.append('client_id', this.config.clientId);

                try {
                    // 这里不使用 doTokenRequest 默认的错误抛出，因为需要处理 pending
                    const endpoint = this.discovery!.token_endpoint;
                    const headers = await this.buildHeaders('POST', endpoint);

                    const response = await fetch(endpoint, {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/x-www-form-urlencoded', ...headers },
                        body: params.toString()
                    });

                    const data = await response.json();

                    if (response.ok) {
                        resolve(data);
                        return;
                    }

                    if (data.error === 'authorization_pending') {
                        setTimeout(check, intervalSeconds * 1000);
                    } else if (data.error === 'slow_down') {
                        setTimeout(check, (intervalSeconds + 5) * 1000);
                    } else {
                        reject(new Error(data.error));
                    }
                } catch (e) {
                    reject(e);
                }
            };
            check();
        });
    }

    // ===========================================================================
    // Utilities (UserInfo, Revoke, Introspect)
    // ===========================================================================

    async userInfo(accessToken: string): Promise<UserInfo> {
        this.checkDiscovery();
        const endpoint = this.discovery!.userinfo_endpoint;

        // 如果启用了 DPoP，这里需要签名
        const headers: Record<string, string> = {};
        if (this.dpopPrivateKey) {
            const dpopProof = await this.createDPoPProof('GET', endpoint, accessToken);
            headers['DPoP'] = dpopProof;
            headers['Authorization'] = `DPoP ${accessToken}`;
        } else {
            headers['Authorization'] = `Bearer ${accessToken}`;
        }

        const response = await fetch(endpoint, { headers });
        return this.handleResponse(response);
    }

    async revoke(token: string, hint?: 'access_token' | 'refresh_token'): Promise<void> {
        this.checkDiscovery();
        const endpoint = this.discovery!.revocation_endpoint;
        const params = new URLSearchParams();
        params.append('token', token);
        if (hint) params.append('token_type_hint', hint);

        const headers = await this.buildHeaders('POST', endpoint);
        await fetch(endpoint, {
            method: 'POST',
            headers: { 'Content-Type': 'application/x-www-form-urlencoded', ...headers },
            body: params.toString()
        });
    }

    async introspect(token: string): Promise<{ active: boolean;[key: string]: any }> {
        this.checkDiscovery();
        const endpoint = this.discovery!.introspection_endpoint;
        const params = new URLSearchParams();
        params.append('token', token);

        const headers = await this.buildHeaders('POST', endpoint);
        const response = await fetch(endpoint, {
            method: 'POST',
            headers: { 'Content-Type': 'application/x-www-form-urlencoded', ...headers },
            body: params.toString()
        });
        return this.handleResponse(response);
    }

    // ===========================================================================
    // Internal Helpers
    // ===========================================================================

    private checkDiscovery() {
        if (!this.discovery) throw new Error('OIDC Discovery not initialized. Call discover() first.');
    }

    private baseAuthParams(state: string) {
        return {
            response_type: 'code',
            client_id: this.config.clientId,
            redirect_uri: this.config.redirectUri || '',
            scope: (this.config.scopes || []).join(' '),
            state,
        };
    }

    /**
     * 执行 Token 请求，自动处理 DPoP 和客户端认证
     */
    private async doTokenRequest(params: URLSearchParams): Promise<TokenResponse> {
        this.checkDiscovery();
        const endpoint = this.discovery!.token_endpoint;

        // 添加 ClientID (如果 Basic Auth 未使用)
        if (!this.config.clientSecret) {
            params.append('client_id', this.config.clientId);
        }

        const headers = await this.buildHeaders('POST', endpoint);

        const response = await fetch(endpoint, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
                ...headers,
            },
            body: params.toString(),
        });

        return this.handleResponse(response);
    }

    /**
     * 构建请求头：处理 Basic Auth 和 DPoP Proof
     */
    private async buildHeaders(method: string, url: string): Promise<Record<string, string>> {
        const headers: Record<string, string> = {};

        // 1. Client Authentication (Basic Auth)
        if (this.config.clientSecret) {
            const basic = btoa(`${this.config.clientId}:${this.config.clientSecret}`);
            headers['Authorization'] = `Basic ${basic}`;
        }

        // 2. DPoP Proof
        if (this.dpopPrivateKey) {
            headers['DPoP'] = await this.createDPoPProof(method, url);
        }

        return headers;
    }

    /**
     * 创建 DPoP Proof JWT
     * 使用 jose 库
     */
    private async createDPoPProof(method: string, url: string, accessToken?: string): Promise<string> {
        if (!this.dpopPrivateKey || !this.dpopPublicKey) {
            throw new Error('DPoP keys not initialized');
        }

        // ath: hash of access token (required when accessing resources)
        let ath: string | undefined;
        if (accessToken) {
            const encoder = new TextEncoder();
            const hash = await crypto.subtle.digest('SHA-256', encoder.encode(accessToken));
            ath = this.base64UrlEncode(new Uint8Array(hash));
        }

        // htu: http uri without query/hash
        const u = new URL(url);
        const htu = `${u.origin}${u.pathname}`;

        const jwt = await new jose.SignJWT({
            htm: method,
            htu: htu,
            jti: crypto.randomUUID(),
            ath: ath
        })
            .setProtectedHeader({
                alg: 'ES256',
                typ: 'dpop+jwt',
                jwk: await jose.exportJWK(this.dpopPublicKey) // 公钥嵌入 Header
            })
            .setIssuedAt()
            .sign(this.dpopPrivateKey);

        return jwt;
    }

    private async handleResponse(response: Response): Promise<any> {
        const data = await response.json();
        if (!response.ok) {
            const errorMsg = data.error_description || data.error || response.statusText;
            throw new Error(`OIDC Error: ${errorMsg}`);
        }
        return data;
    }

    // Utils
    private generateRandomString(length: number): string {
        const array = new Uint8Array(length);
        crypto.getRandomValues(array);
        return this.base64UrlEncode(array);
    }

    private base64UrlEncode(buffer: Uint8Array): string {
        return btoa(String.fromCharCode(...buffer))
            .replace(/\+/g, '-')
            .replace(/\//g, '_')
            .replace(/=+$/, '');
    }
}