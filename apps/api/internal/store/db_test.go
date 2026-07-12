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
	for _, model := range []any{&models.Node{}, &models.LineCircuit{}, &models.LineProbe{}, &models.AgentEvent{}} {
		if !db.Migrator().HasTable(model) {
			t.Fatalf("missing migrated table for %T", model)
		}
	}
	var firstCount int64
	if err := db.Model(&models.SchemaMigration{}).Count(&firstCount).Error; err != nil {
		t.Fatalf("count migrations: %v", err)
	}
	if firstCount < 2 {
		t.Fatalf("migration count = %d, want at least 2", firstCount)
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
