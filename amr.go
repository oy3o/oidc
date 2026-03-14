package oidc

// AMR (Authentication Methods References) 标识了具体的认证手段。
// 这里的定义遵循 RFC 8176 标准及 IANA 注册表。
type AMR = string

// -----------------------------------------------------------------------------
// 1. 生物识别类 (Biometric) - RFC 8176
// -----------------------------------------------------------------------------
const (
	// AMR_Face 面部识别 (Face Recognition)
	// 场景: Apple FaceID, Android Face Unlock
	AMR_Face AMR = "face"

	// AMR_Fingerprint 指纹识别 (Fingerprint)
	// 场景: TouchID, 安卓指纹
	AMR_Fingerprint AMR = "fpt"

	// AMR_Geo 地理位置 (Geo-Location)
	// 场景: 基于用户地理位置的隐式认证或风控通过
	AMR_Geo AMR = "geo"

	// AMR_Iris 虹膜扫描 (Iris Scan)
	AMR_Iris AMR = "iris"

	// AMR_Retina 视网膜扫描 (Retina Scan)
	AMR_Retina AMR = "retina"

	// AMR_Voice 语音生物特征 (Voice Biometric)
	// 场景: 声纹识别
	AMR_Voice AMR = "vbm"

	// AMR_Bio 通用生物特征 (Biometric)
	// 场景: 当无法区分具体是脸还是指纹，或不想暴露具体细节时使用
	AMR_Bio AMR = "bio"
)

// -----------------------------------------------------------------------------
// 2. 知识类 (Knowledge - Something you know) - RFC 8176
// -----------------------------------------------------------------------------
const (
	// AMR_Password 密码 (Password)
	// 场景: 用户输入了密码
	AMR_Password AMR = "pwd"

	// AMR_PIN 个人识别码 (Personal Identification Number)
	// 场景: 银行卡PIN，只有数字的简短密码
	AMR_PIN AMR = "pin"

	// AMR_KBA 基于知识的认证 (Knowledge-Based Authentication)
	// 场景: 安全问题 ("你母亲的姓氏是什么？")
	AMR_KBA AMR = "kba"
)

// -----------------------------------------------------------------------------
// 3. 持有类 (Possession - Something you have) - RFC 8176
// -----------------------------------------------------------------------------
const (
	// AMR_OTP 一次性密码 (One-Time Password)
	// 场景: TOTP (Google Authenticator), HOTP
	// 注意: 虽然短信验证码也是OTP，但通常建议用 "sms" 区分
	AMR_OTP AMR = "otp"

	// AMR_HardwareKey 硬件持有的加密密钥 (Proof-of-Possession Hardware Secured Key)
	// 场景: WebAuthn, FIDO2, Passkey (Passkey通常结合 hwk + user)
	AMR_HardwareKey AMR = "hwk"

	// AMR_SoftwareKey 软件持有的加密密钥 (Proof-of-Possession Software Secured Key)
	// 场景: 客户端证书文件 (非硬件存储), 软件生成的非对称密钥签名
	AMR_SoftwareKey AMR = "swk"

	// AMR_SmartCard 智能卡 (Smart Card)
	// 场景: 银行U盾, 身份证读卡器, PIV 卡 (通过 mTLS 认证)
	AMR_SmartCard AMR = "sc"

	// AMR_SMS 短信 (SMS)
	// 场景: 通过短信发送的验证码
	AMR_SMS AMR = "sms"

	// AMR_Tel 电话回呼 (Telephone)
	// 场景: 接听电话并按键确认，或语音播报验证码
	AMR_Tel AMR = "tel"

	// AMR_UserPresence 用户在场测试 (User Presence Test)
	// 场景: 触摸 YubiKey 的金属片 (仅证明有人在，不验证生物特征), 点击确认按钮
	AMR_UserPresence AMR = "user"

	// AMR_WIA Windows 集成认证 (Windows Integrated Authentication)
	// 场景: 企业内网自动登录 (Kerberos/NTLM)
	AMR_WIA AMR = "wia"

	// AMR_PoP 密钥持有证明 (Proof of Possession)
	// 场景: 只有持有特定私钥才能签署的请求 (通用定义)
	AMR_PoP AMR = "pop"
)

// -----------------------------------------------------------------------------
// 4. 逻辑与组合类 (Logic & Combination) - RFC 8176
// -----------------------------------------------------------------------------
const (
	// AMR_MFA 多因素认证 (Multi-Factor Authentication)
	// 场景: 明确标记本次认证使用了多种因素 (如 pwd + otp)
	AMR_MFA AMR = "mfa"

	// AMR_MCA 多通道认证 (Multi-Channel Authentication)
	// 场景: 在网页登录，在手机App上点击确认 (Out-of-band)
	AMR_MCA AMR = "mca"

	// AMR_Risk 基于风险的认证 (Risk-based Authentication)
	// 场景: 系统判定环境安全，自动放行 (无交互)
	AMR_Risk AMR = "risk"
)

// -----------------------------------------------------------------------------
// 5. 工业界通用扩展 (Common Industry Practice / Non-RFC)
// -----------------------------------------------------------------------------
const (
	// AMR_Email 电子邮件 (Email) - 非 RFC 8176 标准，但极常用
	// 场景: Magic Link (魔术链接), 邮箱验证码
	// RFC 倾向于用 "otp" (如果是码) 或 "mca" (如果是链接)，但 "email" 语义更清晰
	AMR_Email AMR = "email"

	// AMR_PhishingResistant 防钓鱼 (Phishing Resistant) - FIDO 联盟建议
	// 场景: 明确标记使用了 FIDO/WebAuthn 等防中间人攻击的手段
	// 许多高安全级应用 (如银行) 会检查此标记
	AMR_PhishingResistant AMR = "phrh"
)
