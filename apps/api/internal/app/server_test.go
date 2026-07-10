package app

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"dusheng-panel/apps/api/internal/auth"
	"dusheng-panel/apps/api/internal/config"
	"dusheng-panel/apps/api/internal/models"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	_ "modernc.org/sqlite"
)

func testServer(t *testing.T) *Server {
	t.Helper()
	name := strings.NewReplacer("/", "_", " ", "_").Replace(t.Name())
	db, err := gorm.Open(sqlite.Dialector{DriverName: "sqlite", DSN: fmt.Sprintf("file:%s?mode=memory&cache=shared", name)}, &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(
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
	))
	return &Server{db: db}
}

func seedForwardFixture(t *testing.T, s *Server) (models.User, models.DeviceGroup, models.Tunnel, models.ProtocolPolicy) {
	t.Helper()
	hash, err := auth.HashPassword("secret")
	require.NoError(t, err)
	user := models.User{
		Username:       "alice",
		PasswordHash:   hash,
		Role:           "user",
		Status:         "active",
		FlowLimitBytes: 1024 * 1024 * 1024,
		ForwardLimit:   2,
	}
	require.NoError(t, s.db.Create(&user).Error)
	entry := models.DeviceGroup{
		Name:         "entry",
		Role:         "entry",
		PortStart:    20000,
		PortEnd:      20002,
		TrafficRatio: 1,
	}
	require.NoError(t, s.db.Create(&entry).Error)
	policy := models.ProtocolPolicy{
		Name:                 "no tls",
		Template:             "iepl_iplc_no_tls",
		Mode:                 "block",
		BlockTLS:             true,
		BlockQUIC:            true,
		BlockEncryptedTunnel: true,
	}
	require.NoError(t, s.db.Create(&policy).Error)
	tunnel := models.Tunnel{
		Name:              "direct",
		Mode:              "single",
		EntryGroupID:      entry.ID,
		Protocol:          "direct",
		FlowAccounting:    "single",
		EntryTrafficRatio: 1,
		ExitTrafficRatio:  1,
	}
	require.NoError(t, s.db.Create(&tunnel).Error)
	return user, entry, tunnel, policy
}

func testRouter(t *testing.T, s *Server) http.Handler {
	t.Helper()
	return NewServer(config.Config{JWTSecret: "test-secret-for-unit-tests"}, s.db)
}

func jsonRequest(t *testing.T, router http.Handler, method, path string, body any, token string) *httptest.ResponseRecorder {
	t.Helper()
	content, err := json.Marshal(body)
	require.NoError(t, err)
	req := httptest.NewRequest(method, path, bytes.NewReader(content))
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	return rec
}

func adminToken(t *testing.T, s *Server) string {
	t.Helper()
	hash, err := auth.HashPassword("secret")
	require.NoError(t, err)
	admin := models.User{Username: "admin", PasswordHash: hash, Role: "admin", Status: "active"}
	require.NoError(t, s.db.Create(&admin).Error)
	token, err := auth.GenerateToken(admin.ID, admin.Role, auth.TokenTypeAccess, "test-secret-for-unit-tests", time.Hour)
	require.NoError(t, err)
	return token
}

func TestPrepareForwardRuleAllocatesFirstFreePort(t *testing.T) {
	s := testServer(t)
	user, _, tunnel, _ := seedForwardFixture(t, s)
	existing := models.ForwardRule{
		UserID:     user.ID,
		TunnelID:   tunnel.ID,
		Name:       "used",
		Protocol:   "tcp",
		ListenPort: 20000,
		RemoteHost: "127.0.0.1",
		RemotePort: 8080,
	}
	require.NoError(t, s.db.Create(&existing).Error)

	rule := models.ForwardRule{
		UserID:     user.ID,
		TunnelID:   tunnel.ID,
		Name:       "next",
		Protocol:   "tcp",
		RemoteHost: "127.0.0.1",
		RemotePort: 8081,
	}
	require.NoError(t, s.prepareForwardRule(&rule, 0))
	require.Equal(t, 20001, rule.ListenPort)
}

func TestPrepareForwardRuleRejectsEncryptedTunnelPolicy(t *testing.T) {
	s := testServer(t)
	user, _, tunnel, policy := seedForwardFixture(t, s)
	tunnel.Protocol = "ws-over-tls"
	tunnel.ProtocolPolicyID = &policy.ID
	require.NoError(t, s.db.Save(&tunnel).Error)

	rule := models.ForwardRule{
		UserID:     user.ID,
		TunnelID:   tunnel.ID,
		Name:       "bad",
		Protocol:   "tcp",
		ListenPort: 20001,
		RemoteHost: "127.0.0.1",
		RemotePort: 8081,
	}
	require.ErrorContains(t, s.prepareForwardRule(&rule, 0), "forbids encrypted tunnel")
}

func TestPrepareForwardRuleRejectsExpiredUser(t *testing.T) {
	s := testServer(t)
	user, _, tunnel, _ := seedForwardFixture(t, s)
	expired := time.Now().Add(-time.Hour)
	user.ExpiresAt = &expired
	require.NoError(t, s.db.Save(&user).Error)

	rule := models.ForwardRule{
		UserID:     user.ID,
		TunnelID:   tunnel.ID,
		Name:       "expired",
		Protocol:   "tcp",
		ListenPort: 20001,
		RemoteHost: "127.0.0.1",
		RemotePort: 8081,
	}
	require.ErrorContains(t, s.prepareForwardRule(&rule, 0), "expired")
}

func TestForwardRuleUniqueTunnelListenPort(t *testing.T) {
	s := testServer(t)
	user, _, tunnel, _ := seedForwardFixture(t, s)
	first := models.ForwardRule{
		UserID:     user.ID,
		TunnelID:   tunnel.ID,
		Name:       "first",
		Protocol:   "tcp",
		Strategy:   "least_conn",
		ListenPort: 20001,
		RemoteHost: "127.0.0.1",
		RemotePort: 8081,
	}
	require.NoError(t, s.db.Create(&first).Error)

	second := first
	second.ID = 0
	second.Name = "second"
	require.Error(t, s.db.Create(&second).Error)
}

func TestDeleteNodeRequestsAgentUninstallAndAckDeletesNode(t *testing.T) {
	s := testServer(t)
	token := adminToken(t, s)
	group := models.DeviceGroup{Name: "entry", Role: "entry", PortStart: 20000, PortEnd: 30000, TrafficRatio: 1}
	require.NoError(t, s.db.Create(&group).Error)
	nodeToken := "node-token"
	node := models.Node{
		DeviceGroupID: group.ID,
		Name:          "node",
		UUID:          "node-uninstall",
		TokenHash:     auth.TokenHash(nodeToken),
		Status:        "online",
	}
	require.NoError(t, s.db.Create(&node).Error)
	router := testRouter(t, s)

	rec := jsonRequest(t, router, http.MethodDelete, fmt.Sprintf("/api/v1/nodes/%d", node.ID), map[string]any{}, token)
	require.Equal(t, http.StatusAccepted, rec.Code)
	require.NoError(t, s.db.First(&node, node.ID).Error)
	require.Equal(t, "uninstalling", node.Status)
	require.NotEmpty(t, node.UninstallCommandID)
	require.NotNil(t, node.UninstallRequestedAt)

	rec = jsonRequest(t, router, http.MethodPost, "/api/v1/agent/heartbeat", map[string]any{
		"version":         "test",
		"appliedRevision": 0,
		"system":          map[string]any{"runtime": "test"},
	}, nodeToken)
	require.Equal(t, http.StatusOK, rec.Code)
	var heartbeat map[string]any
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &heartbeat))
	command, ok := heartbeat["command"].(map[string]any)
	require.True(t, ok)
	require.Equal(t, "uninstall", command["action"])
	require.Equal(t, node.UninstallCommandID, command["id"])

	rec = jsonRequest(t, router, http.MethodPost, "/api/v1/agent/commands/"+node.UninstallCommandID+"/ack", map[string]any{
		"status": "accepted",
	}, nodeToken)
	require.Equal(t, http.StatusNoContent, rec.Code)
	require.ErrorIs(t, s.db.First(&models.Node{}, node.ID).Error, gorm.ErrRecordNotFound)
}

func TestAgentTrafficRejectsNegativeBytes(t *testing.T) {
	s := testServer(t)
	user, entry, tunnel, _ := seedForwardFixture(t, s)
	rule := models.ForwardRule{
		UserID:     user.ID,
		TunnelID:   tunnel.ID,
		Name:       "rule",
		Protocol:   "tcp",
		Strategy:   "least_conn",
		ListenPort: 20001,
		RemoteHost: "127.0.0.1",
		RemotePort: 8081,
	}
	require.NoError(t, s.db.Create(&rule).Error)
	nodeToken := "node-token"
	node := models.Node{
		DeviceGroupID: entry.ID,
		Name:          "node",
		UUID:          "node-1",
		TokenHash:     auth.TokenHash(nodeToken),
		Status:        "online",
	}
	require.NoError(t, s.db.Create(&node).Error)

	rec := jsonRequest(t, testRouter(t, s), http.MethodPost, "/api/v1/agent/traffic", map[string]any{
		"samples": []map[string]any{{"ruleId": rule.ID, "inBytes": -1, "outBytes": 0}},
	}, nodeToken)
	require.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestAgentTrafficRejectsRuleOutsideNodeTunnel(t *testing.T) {
	s := testServer(t)
	user, _, tunnel, _ := seedForwardFixture(t, s)
	otherGroup := models.DeviceGroup{Name: "other", Role: "entry", PortStart: 30000, PortEnd: 30010, TrafficRatio: 1}
	require.NoError(t, s.db.Create(&otherGroup).Error)
	rule := models.ForwardRule{
		UserID:     user.ID,
		TunnelID:   tunnel.ID,
		Name:       "rule",
		Protocol:   "tcp",
		Strategy:   "least_conn",
		ListenPort: 20001,
		RemoteHost: "127.0.0.1",
		RemotePort: 8081,
	}
	require.NoError(t, s.db.Create(&rule).Error)
	nodeToken := "node-token"
	node := models.Node{
		DeviceGroupID: otherGroup.ID,
		Name:          "node",
		UUID:          "node-2",
		TokenHash:     auth.TokenHash(nodeToken),
		Status:        "online",
	}
	require.NoError(t, s.db.Create(&node).Error)

	rec := jsonRequest(t, testRouter(t, s), http.MethodPost, "/api/v1/agent/traffic", map[string]any{
		"samples": []map[string]any{{"ruleId": rule.ID, "inBytes": 1, "outBytes": 2}},
	}, nodeToken)
	require.Equal(t, http.StatusForbidden, rec.Code)
}

func TestDashboardScopesNonAdminUser(t *testing.T) {
	s := testServer(t)
	user, _, tunnel, _ := seedForwardFixture(t, s)
	other := models.User{Username: "bob", PasswordHash: "x", Role: "user", Status: "active"}
	require.NoError(t, s.db.Create(&other).Error)
	userRule := models.ForwardRule{
		UserID:     user.ID,
		TunnelID:   tunnel.ID,
		Name:       "alice-rule",
		Protocol:   "tcp",
		Strategy:   "least_conn",
		ListenPort: 20001,
		RemoteHost: "127.0.0.1",
		RemotePort: 8081,
	}
	otherRule := userRule
	otherRule.UserID = other.ID
	otherRule.ListenPort = 20002
	otherRule.Name = "bob-rule"
	require.NoError(t, s.db.Create(&userRule).Error)
	require.NoError(t, s.db.Create(&otherRule).Error)
	require.NoError(t, s.db.Create(&models.TrafficSample{UserID: user.ID, RuleID: userRule.ID, Direction: "in", Bytes: 100, SampledAt: time.Now()}).Error)
	require.NoError(t, s.db.Create(&models.TrafficSample{UserID: other.ID, RuleID: otherRule.ID, Direction: "in", Bytes: 900, SampledAt: time.Now()}).Error)
	require.NoError(t, s.db.Create(&models.ProtocolViolation{RuleID: otherRule.ID, Protocol: "tls", Action: "block", OccurredAt: time.Now()}).Error)

	token, err := auth.GenerateToken(user.ID, user.Role, auth.TokenTypeAccess, "test-secret-for-unit-tests", time.Hour)
	require.NoError(t, err)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/dashboard", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	testRouter(t, s).ServeHTTP(rec, req)
	require.Equal(t, http.StatusOK, rec.Code)

	var payload map[string]any
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &payload))
	require.Equal(t, float64(1), payload["users"])
	require.Equal(t, float64(1), payload["forwardRules"])
	require.Equal(t, float64(100), payload["todayBytes"])
	require.Equal(t, float64(0), payload["violations24h"])
}

func TestListUsersPaginationAndSearch(t *testing.T) {
	s := testServer(t)
	token := adminToken(t, s)
	hash, err := auth.HashPassword("secret")
	require.NoError(t, err)
	for i := 0; i < 5; i++ {
		user := models.User{
			Username:     fmt.Sprintf("alice-%d", i),
			PasswordHash: hash,
			Role:         "user",
			Status:       "active",
		}
		require.NoError(t, s.db.Create(&user).Error)
	}

	rec := jsonRequest(t, testRouter(t, s), http.MethodGet, "/api/v1/users?page=1&pageSize=2&q=alice", map[string]any{}, token)
	require.Equal(t, http.StatusOK, rec.Code)
	var page struct {
		Items    []models.User `json:"items"`
		Total    int64         `json:"total"`
		Page     int           `json:"page"`
		PageSize int           `json:"pageSize"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &page))
	require.Len(t, page.Items, 2)
	require.Equal(t, int64(5), page.Total)
	require.Equal(t, 1, page.Page)
	require.Equal(t, 2, page.PageSize)
}

func TestUserAuthRejectsDisabledUserAfterTokenIssued(t *testing.T) {
	s := testServer(t)
	hash, err := auth.HashPassword("secret")
	require.NoError(t, err)
	user := models.User{Username: "carol", PasswordHash: hash, Role: "admin", Status: "active"}
	require.NoError(t, s.db.Create(&user).Error)
	token, err := auth.GenerateToken(user.ID, user.Role, auth.TokenTypeAccess, "test-secret-for-unit-tests", time.Hour)
	require.NoError(t, err)
	require.NoError(t, s.db.Model(&user).Update("status", "disabled").Error)

	rec := jsonRequest(t, testRouter(t, s), http.MethodGet, "/api/v1/me", map[string]any{}, token)
	require.Equal(t, http.StatusUnauthorized, rec.Code)
}

func TestLoginRateLimiterBlocksRepeatedFailures(t *testing.T) {
	s := testServer(t)
	hash, err := auth.HashPassword("secret")
	require.NoError(t, err)
	user := models.User{Username: "dave", PasswordHash: hash, Role: "admin", Status: "active"}
	require.NoError(t, s.db.Create(&user).Error)
	router := testRouter(t, s)

	for i := 0; i < 8; i++ {
		rec := jsonRequest(t, router, http.MethodPost, "/api/v1/auth/login", map[string]any{
			"username": "dave",
			"password": "wrong",
		}, "")
		require.Equal(t, http.StatusUnauthorized, rec.Code)
	}
	rec := jsonRequest(t, router, http.MethodPost, "/api/v1/auth/login", map[string]any{
		"username": "dave",
		"password": "wrong",
	}, "")
	require.Equal(t, http.StatusTooManyRequests, rec.Code)
}

func TestDeviceGroupUpdateIgnoresSystemFields(t *testing.T) {
	s := testServer(t)
	token := adminToken(t, s)
	group := models.DeviceGroup{Name: "entry", Role: "entry", PortStart: 20000, PortEnd: 30000, TrafficRatio: 1}
	require.NoError(t, s.db.Create(&group).Error)

	rec := jsonRequest(t, testRouter(t, s), http.MethodPut, fmt.Sprintf("/api/v1/device-groups/%d", group.ID), map[string]any{
		"id":           999,
		"createdAt":    "2000-01-01T00:00:00Z",
		"name":         "entry-updated",
		"role":         "entry",
		"portStart":    20000,
		"portEnd":      30000,
		"trafficRatio": 1,
	}, token)
	require.Equal(t, http.StatusOK, rec.Code)

	var updated models.DeviceGroup
	require.NoError(t, s.db.First(&updated, group.ID).Error)
	require.Equal(t, group.ID, updated.ID)
	require.Equal(t, "entry-updated", updated.Name)
	require.ErrorIs(t, s.db.First(&models.DeviceGroup{}, 999).Error, gorm.ErrRecordNotFound)
}

func TestProductionConfigRejectsUnsafeDefaults(t *testing.T) {
	cfg := config.Config{
		Environment:   "production",
		JWTSecret:     "0123456789abcdef0123456789abcdef",
		AdminUsername: "admin",
		AdminPassword: "strong-password",
		CORSOrigins:   []string{"*"},
		DatabaseURL:   "postgres://dusheng:strong@db:5432/dusheng",
	}
	require.ErrorContains(t, cfg.Validate(), "CORS")

	cfg.CORSOrigins = []string{"https://panel.example.com"}
	cfg.DatabaseURL = "postgres://dusheng:change-me-dusheng@db:5432/dusheng"
	require.ErrorContains(t, cfg.Validate(), "database password")
}
