package config

import "os"

type Config struct {
	Listen        string
	DatabaseURL   string
	JWTSecret     string
	AdminUsername string
	AdminPassword string
	PublicURL     string
}

func FromEnv() Config {
	return Config{
		Listen:        getenv("DUSHENG_LISTEN", "0.0.0.0:18888"),
		DatabaseURL:   getenv("DUSHENG_DATABASE_URL", "sqlite://data/dusheng.db"),
		JWTSecret:     getenv("DUSHENG_JWT_SECRET", "change-me-in-production"),
		AdminUsername: getenv("DUSHENG_ADMIN_USERNAME", "admin_user"),
		AdminPassword: getenv("DUSHENG_ADMIN_PASSWORD", "admin_user"),
		PublicURL:     getenv("DUSHENG_PUBLIC_URL", "http://127.0.0.1:18888"),
	}
}

func getenv(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}
