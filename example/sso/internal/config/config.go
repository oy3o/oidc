package config

import (
	"time"

	"github.com/oy3o/conf"
	"github.com/oy3o/o11y"
	"github.com/oy3o/oidc"
)

type AppConfig struct {
	Name string `mapstructure:"name" default:"sso"`
	Env  string `mapstructure:"env" default:"dev"`
}

type ServerConfig struct {
	Addr string    `mapstructure:"addr" default:":8080"`
	TLS  TLSConfig `mapstructure:"tls"`
}

type TLSConfig struct {
	Enabled  bool   `mapstructure:"enabled"`
	CertFile string `mapstructure:"cert_file"`
	KeyFile  string `mapstructure:"key_file"`
}

type DatabaseConfig struct {
	// env:"strict" 确保在 GO_ENV=production 时，此字段必须由环境变量填充，防止配置文件泄露密码
	DSN string `mapstructure:"dsn" validate:"required" env:"strict"`
}

type RedisConfig struct {
	Addr     string `mapstructure:"addr" default:"localhost:6379"`
	Password string `mapstructure:"password" env:"strict"`
	DB       int    `mapstructure:"db" default:"0"`
}

type OIDCConfig struct {
	Issuer          string        `mapstructure:"issuer" validate:"required,url"`
	AccessTokenTTL  time.Duration `mapstructure:"access_token_ttl" default:"1h"`
	RefreshTokenTTL time.Duration `mapstructure:"refresh_token_ttl" default:"720h"`
	IDTokenTTL      time.Duration `mapstructure:"id_token_ttl" default:"1h"`
	SigningKeyFile  string        `mapstructure:"signing_key_file" validate:"required"`
}

type PoWConfig struct {
	Difficulty   int           `mapstructure:"difficulty" default:"4"`
	LockDuration time.Duration `mapstructure:"lock_duration" default:"5m"`
	MaxFailures  int           `mapstructure:"max_failures" default:"3"`
}

// Config 聚合根
type Config struct {
	App      AppConfig      `mapstructure:"app"`
	Server   ServerConfig   `mapstructure:"server"`
	Database DatabaseConfig `mapstructure:"database"`
	Redis    RedisConfig    `mapstructure:"redis"`
	OIDC     OIDCConfig     `mapstructure:"oidc"`
	PoW      PoWConfig      `mapstructure:"pow"`
	O11y     o11y.Config    `mapstructure:"o11y"`
}

// Load 加载配置
// 它会自动查找当前目录下的 config.yaml，并应用环境变量覆盖
func Load() (*Config, error) {
	return conf.Load[Config]("sso",
		conf.WithSearchPaths(".", "./config"), // 搜索路径
		conf.WithFileName("config"),
		conf.WithFileType("yaml"),
	)
}

// ToOIDCServerConfig 将内部配置转换为 oidc 库所需的配置结构
// 这里的 Storage, Hasher, SecretManager 需要在 main 中初始化后传入
func (c *Config) ToOIDCServerConfig(storage oidc.Storage, hasher oidc.Hasher, secretManager *oidc.SecretManager) oidc.ServerConfig {
	return oidc.ServerConfig{
		Issuer:          c.OIDC.Issuer,
		Storage:         storage,
		Hasher:          hasher,
		SecretManager:   secretManager,
		AccessTokenTTL:  c.OIDC.AccessTokenTTL,
		RefreshTokenTTL: c.OIDC.RefreshTokenTTL,
		IDTokenTTL:      c.OIDC.IDTokenTTL,
		EnableGC:        true,
	}
}
