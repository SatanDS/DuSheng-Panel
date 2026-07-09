package store

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"dusheng-panel/apps/api/internal/auth"
	"dusheng-panel/apps/api/internal/config"
	"dusheng-panel/apps/api/internal/models"
	"gorm.io/driver/mysql"
	"gorm.io/driver/postgres"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	_ "modernc.org/sqlite"
)

func Open(cfg config.Config) (*gorm.DB, error) {
	dialector, err := dialector(cfg.DatabaseURL)
	if err != nil {
		return nil, err
	}
	db, err := gorm.Open(dialector, &gorm.Config{})
	if err != nil {
		return nil, err
	}
	if err := db.AutoMigrate(
		&models.SchemaMigration{},
		&models.User{},
		&models.DeviceGroup{},
		&models.Node{},
		&models.Tunnel{},
		&models.ForwardRule{},
		&models.ProtocolPolicy{},
		&models.SpeedLimit{},
		&models.TrafficSample{},
		&models.AuditLog{},
		&models.InstallToken{},
		&models.ProtocolViolation{},
	); err != nil {
		return nil, err
	}
	if err := runMigrations(db); err != nil {
		return nil, err
	}
	if err := seedProtocolPolicies(db); err != nil {
		return nil, err
	}
	if err := seedAdmin(db, cfg); err != nil {
		return nil, err
	}
	return db, nil
}

func dialector(databaseURL string) (gorm.Dialector, error) {
	switch {
	case strings.HasPrefix(databaseURL, "sqlite://"):
		path := strings.TrimPrefix(databaseURL, "sqlite://")
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			return nil, err
		}
		return sqlite.Dialector{DriverName: "sqlite", DSN: path}, nil
	case strings.HasPrefix(databaseURL, "postgres://"), strings.HasPrefix(databaseURL, "postgresql://"):
		return postgres.Open(databaseURL), nil
	case strings.HasPrefix(databaseURL, "mysql://"):
		return mysql.Open(strings.TrimPrefix(databaseURL, "mysql://")), nil
	default:
		return nil, fmt.Errorf("unsupported database url %q", databaseURL)
	}
}

func runMigrations(db *gorm.DB) error {
	return applyMigration(db, "2026071001_forward_rule_unique_port", func(tx *gorm.DB) error {
		if tx.Migrator().HasIndex(&models.ForwardRule{}, "idx_forward_rules_tunnel_listen") {
			return nil
		}
		return tx.Migrator().CreateIndex(&models.ForwardRule{}, "idx_forward_rules_tunnel_listen")
	})
}

func applyMigration(db *gorm.DB, version string, fn func(*gorm.DB) error) error {
	var existing models.SchemaMigration
	err := db.First(&existing, "version = ?", version).Error
	if err == nil {
		return nil
	}
	if err != nil && err != gorm.ErrRecordNotFound {
		return err
	}
	return db.Transaction(func(tx *gorm.DB) error {
		if err := fn(tx); err != nil {
			return err
		}
		return tx.Create(&models.SchemaMigration{Version: version, AppliedAt: time.Now().UTC()}).Error
	})
}

func seedAdmin(db *gorm.DB, cfg config.Config) error {
	var count int64
	if err := db.Model(&models.User{}).Where("role = ?", "admin").Count(&count).Error; err != nil {
		return err
	}
	if count > 0 {
		return nil
	}
	hash, err := auth.HashPassword(cfg.AdminPassword)
	if err != nil {
		return err
	}
	user := models.User{
		Username:       cfg.AdminUsername,
		DisplayName:    "DuSheng Admin",
		PasswordHash:   hash,
		Role:           "admin",
		Status:         "active",
		FlowLimitBytes: 0,
		ForwardLimit:   0,
	}
	return db.Create(&user).Error
}

func seedProtocolPolicies(db *gorm.DB) error {
	policies := []models.ProtocolPolicy{
		{
			Name:        "不限制",
			Template:    "none",
			Mode:        "observe",
			Description: "仅记录协议检测结果，不阻断连接。",
		},
		{
			Name:                 "IEPL/IPLC 禁止 TLS/QUIC",
			Template:             "iepl_iplc_no_tls",
			Mode:                 "block",
			BlockTLS:             true,
			BlockQUIC:            true,
			BlockEncryptedTunnel: true,
			Description:          "用于不允许 TLS、QUIC 或加密隧道协议的专线，命中后强制阻断。",
		},
		{
			Name:              "仅允许明文 TCP",
			Template:          "plain_tcp_only",
			Mode:              "block",
			BlockTLS:          true,
			BlockQUIC:         true,
			AllowPlainTCPOnly: true,
			BlockProxyLike:    true,
			Description:       "阻断 TLS、QUIC、SSH、HTTP CONNECT、SOCKS 等明显协议特征。",
		},
		{
			Name:          "仅允许 HTTP",
			Template:      "http_only",
			Mode:          "block",
			AllowHTTPOnly: true,
			BlockTLS:      true,
			BlockQUIC:     true,
			Description:   "只允许入口首包为 HTTP 明文请求。",
		},
		{
			Name:           "禁止代理特征协议",
			Template:       "block_proxy_like",
			Mode:           "block",
			BlockProxyLike: true,
			Description:    "阻断 SOCKS、HTTP CONNECT、SSH 等常见代理或隧道握手特征。",
		},
	}
	for _, policy := range policies {
		var existing models.ProtocolPolicy
		err := db.Where("template = ?", policy.Template).First(&existing).Error
		if err == nil {
			continue
		}
		if err != nil && err != gorm.ErrRecordNotFound {
			return err
		}
		if err := db.Create(&policy).Error; err != nil {
			return err
		}
	}

	var groups int64
	if err := db.Model(&models.DeviceGroup{}).Count(&groups).Error; err != nil {
		return err
	}
	if groups == 0 {
		entry := models.DeviceGroup{Name: "默认入口组", Role: "entry", PortStart: 10000, PortEnd: 60000, TrafficRatio: 1}
		exit := models.DeviceGroup{Name: "默认出口组", Role: "exit", PortStart: 20000, PortEnd: 60000, TrafficRatio: 1}
		if err := db.Create(&entry).Error; err != nil {
			return err
		}
		if err := db.Create(&exit).Error; err != nil {
			return err
		}
		tunnel := models.Tunnel{
			Name:              "默认单端直连隧道",
			Mode:              "single",
			EntryGroupID:      entry.ID,
			Protocol:          "direct",
			FlowAccounting:    "single",
			EntryTrafficRatio: 1,
			ExitTrafficRatio:  1,
		}
		if err := db.Create(&tunnel).Error; err != nil {
			return err
		}
	}
	return nil
}
