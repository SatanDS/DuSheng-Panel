package store

import (
	"fmt"
	"os"
	"testing"
	"time"

	"dusheng-panel/apps/api/internal/config"
	"dusheng-panel/apps/api/internal/models"
)

func TestPostgresMigrationsAndJSONCapabilities(t *testing.T) {
	databaseURL := os.Getenv("DUSHENG_TEST_POSTGRES_URL")
	if databaseURL == "" {
		t.Skip("DUSHENG_TEST_POSTGRES_URL is not set")
	}
	db, err := Open(config.Config{
		DatabaseURL: databaseURL, JWTSecret: "integration-secret", AdminUsername: "integration-admin", AdminPassword: "integration-password",
	})
	if err != nil {
		t.Fatalf("Open(PostgreSQL) error = %v", err)
	}
	for _, model := range []any{&models.Tenant{}, &models.TenantTrafficHourlyBucket{}, &models.PortLease{}, &models.LineProvider{}, &models.LineCircuit{}, &models.LineProbeSample{}, &models.AgentEvent{}} {
		if !db.Migrator().HasTable(model) {
			t.Fatalf("PostgreSQL is missing table for %T", model)
		}
	}
	suffix := time.Now().UnixNano()
	group := models.DeviceGroup{Name: fmt.Sprintf("integration-entry-%d", suffix), Role: "entry", TrafficRatio: 1}
	if err := db.Create(&group).Error; err != nil {
		t.Fatalf("create group: %v", err)
	}
	node := models.Node{
		DeviceGroupID: group.ID, Name: "integration-node", UUID: fmt.Sprintf("integration-node-%d", suffix), TokenHash: fmt.Sprintf("integration-hash-%d", suffix),
		Status: "online", Capabilities: []string{"tcp_runtime", "config_ack_v1"},
	}
	if err := db.Create(&node).Error; err != nil {
		t.Fatalf("create node: %v", err)
	}
	var loaded models.Node
	if err := db.First(&loaded, node.ID).Error; err != nil {
		t.Fatalf("load node: %v", err)
	}
	if len(loaded.Capabilities) != 2 || loaded.Capabilities[1] != "config_ack_v1" {
		t.Fatalf("capabilities = %#v", loaded.Capabilities)
	}
}
