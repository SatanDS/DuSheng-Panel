package store

import (
	"path/filepath"
	"testing"

	"dusheng-panel/apps/api/internal/config"
	"dusheng-panel/apps/api/internal/models"
)

func TestOpenAppliesVersionedSchemaOnce(t *testing.T) {
	databaseURL := "sqlite://" + filepath.ToSlash(filepath.Join(t.TempDir(), "dusheng.db"))
	cfg := config.Config{
		DatabaseURL: databaseURL, JWTSecret: "test-secret", AdminUsername: "admin", AdminPassword: "strong-password",
	}
	db, err := Open(cfg)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatalf("DB() error = %v", err)
	}
	for _, model := range []any{&models.Tenant{}, &models.TenantTunnelGrant{}, &models.UserTunnelGrant{}, &models.PortLease{}, &models.Node{}, &models.LineCircuit{}, &models.LineProbe{}, &models.AgentEvent{}} {
		if !db.Migrator().HasTable(model) {
			t.Fatalf("missing migrated table for %T", model)
		}
	}
	var firstCount int64
	if err := db.Model(&models.SchemaMigration{}).Count(&firstCount).Error; err != nil {
		t.Fatalf("count migrations: %v", err)
	}
	if firstCount < 4 {
		t.Fatalf("migration count = %d, want at least 4", firstCount)
	}
	secondDB, err := Open(cfg)
	if err != nil {
		t.Fatalf("second Open() error = %v", err)
	}
	var secondCount int64
	if err := db.Model(&models.SchemaMigration{}).Count(&secondCount).Error; err != nil {
		t.Fatalf("count second migrations: %v", err)
	}
	if secondCount != firstCount {
		t.Fatalf("migration count changed from %d to %d", firstCount, secondCount)
	}
	secondSQLDB, err := secondDB.DB()
	if err != nil {
		t.Fatalf("second DB() error = %v", err)
	}
	if err := secondSQLDB.Close(); err != nil {
		t.Fatalf("close second database: %v", err)
	}
	if err := sqlDB.Close(); err != nil {
		t.Fatalf("close database: %v", err)
	}
}

func TestForwardRuleOperationalStatusMigration(t *testing.T) {
	databaseURL := "sqlite://" + filepath.ToSlash(filepath.Join(t.TempDir(), "legacy-status.db"))
	cfg := config.Config{
		DatabaseURL: databaseURL, JWTSecret: "test-secret", AdminUsername: "admin", AdminPassword: "strong-password",
	}
	db, err := Open(cfg)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatalf("DB() error = %v", err)
	}
	t.Cleanup(func() {
		if err := sqlDB.Close(); err != nil {
			t.Errorf("close database: %v", err)
		}
	})
	var user models.User
	if err := db.Where("role = ?", "admin").First(&user).Error; err != nil {
		t.Fatalf("find seeded admin: %v", err)
	}
	var tunnel models.Tunnel
	if err := db.First(&tunnel).Error; err != nil {
		t.Fatalf("find seeded tunnel: %v", err)
	}
	rule := models.ForwardRule{
		UserID: user.ID, TunnelID: tunnel.ID, Name: "legacy", Protocol: "tcp", ListenPort: 12345,
		RemoteHost: "8.8.8.8", RemotePort: 53, Status: "unsynced", Strategy: "least_conn",
	}
	if err := db.Create(&rule).Error; err != nil {
		t.Fatalf("create legacy forwarding rule: %v", err)
	}
	if err := db.Where("version = ?", "2026072201_forward_rule_operational_status").Delete(&models.SchemaMigration{}).Error; err != nil {
		t.Fatalf("remove migration marker: %v", err)
	}
	if err := runMigrations(db); err != nil {
		t.Fatalf("rerun migrations: %v", err)
	}
	if err := db.First(&rule, rule.ID).Error; err != nil {
		t.Fatalf("reload forwarding rule: %v", err)
	}
	if rule.Status != "active" {
		t.Fatalf("forwarding rule status = %q, want active", rule.Status)
	}
}
