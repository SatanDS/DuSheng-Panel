package config

import (
	"errors"
	"os"
	"strings"
)

const (
	DefaultJWTSecret        = "change-me-in-production"
	DefaultAdminUsername    = "admin_user"
	DefaultAdminPassword    = "admin_user"
	DefaultAgentReleaseBase = "https://github.com/SatanDS/DuSheng-Panel/releases/latest/download"
)

type Config struct {
	Listen           string
	DatabaseURL      string
	JWTSecret        string
	AdminUsername    string
	AdminPassword    string
	PublicURL        string
	Environment      string
	CORSOrigins      []string
	AgentReleaseBase string
}

func FromEnv() Config {
	return Config{
		Listen:           getenv("DUSHENG_LISTEN", "0.0.0.0:18888"),
		DatabaseURL:      getenv("DUSHENG_DATABASE_URL", "sqlite://data/dusheng.db"),
		JWTSecret:        getenv("DUSHENG_JWT_SECRET", DefaultJWTSecret),
		AdminUsername:    getenv("DUSHENG_ADMIN_USERNAME", DefaultAdminUsername),
		AdminPassword:    getenv("DUSHENG_ADMIN_PASSWORD", DefaultAdminPassword),
		PublicURL:        getenv("DUSHENG_PUBLIC_URL", "http://127.0.0.1:18888"),
		Environment:      strings.ToLower(getenv("DUSHENG_ENV", "development")),
		CORSOrigins:      splitCSV(getenv("DUSHENG_CORS_ORIGINS", "*")),
		AgentReleaseBase: strings.TrimRight(getenv("DUSHENG_AGENT_RELEASE_BASE", DefaultAgentReleaseBase), "/"),
	}
}

func (c Config) Validate() error {
	if !c.IsProduction() {
		return nil
	}
	if c.JWTSecret == "" || c.JWTSecret == DefaultJWTSecret || len(c.JWTSecret) < 32 {
		return errors.New("DUSHENG_JWT_SECRET must be changed to at least 32 characters in production")
	}
	if c.AdminUsername == DefaultAdminUsername && c.AdminPassword == DefaultAdminPassword {
		return errors.New("DUSHENG_ADMIN_USERNAME or DUSHENG_ADMIN_PASSWORD must be changed in production")
	}
	for _, origin := range c.CORSOrigins {
		if strings.TrimSpace(origin) == "*" {
			return errors.New("DUSHENG_CORS_ORIGINS must be an explicit allowlist in production")
		}
	}
	dbURL := strings.ToLower(c.DatabaseURL)
	if strings.Contains(dbURL, "change-me-dusheng") || strings.Contains(dbURL, "password=change-me") || strings.Contains(dbURL, "password:change-me") {
		return errors.New("database password must be changed in production")
	}
	return nil
}

func (c Config) IsProduction() bool {
	switch strings.ToLower(strings.TrimSpace(c.Environment)) {
	case "prod", "production":
		return true
	default:
		return false
	}
}

func getenv(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}

func splitCSV(value string) []string {
	parts := strings.Split(value, ",")
	result := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			result = append(result, part)
		}
	}
	if len(result) == 0 {
		return []string{"*"}
	}
	return result
}
