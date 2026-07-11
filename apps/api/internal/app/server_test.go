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
		&models.AgentTrafficReport{},
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

func TestCreateGamingProtocolPolicyAppliesSafeDefaults(t *testing.T) {
	s := testServer(t)
	router := testRouter(t, s)
	token := adminToken(t, s)

	rec := jsonRequest(t, router, http.MethodPost, "/api/v1/protocol-policies", map[string]any{
		"name":     "game safe",
		"template": "game_acceleration",
		"mode":     "block",
	}, token)
	require.Equal(t, http.StatusCreated, rec.Code, rec.Body.String())
	var row models.ProtocolPolicy
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &row))
	require.Equal(t, "gaming", row.Purpose)
	require.True(t, row.BlockProxyLike)
	require.Equal(t, "allow", row.QUICAction)
	require.Equal(t, "block", row.SSHAction)
	require.Contains(t, row.BlockedProtocolGroups, "vpn")
}

func TestEvaluateProtocolPolicyBlocksNDPIVPNGroup(t *testing.T) {
	s := testServer(t)
	router := testRouter(t, s)
	token := adminToken(t, s)
	policy := models.ProtocolPolicy{
		Name:                  "game dpi",
		Template:              "game_acceleration",
		Purpose:               "gaming",
		InspectionLevel:       "advanced",
		Mode:                  "block",
		BlockedProtocolGroups: "vpn,p2p",
	}
	require.NoError(t, s.db.Create(&policy).Error)

	rec := jsonRequest(t, router, http.MethodPost, "/api/v1/protocol-policies/evaluate", map[string]any{
		"policyId":     policy.ID,
		"network":      "udp",
		"protocol":     "unknown",
		"ndpiProtocol": "wireguard",
		"ndpiCategory": "vpn",
		"confidence":   90,
		"riskScore":    85,
	}, token)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	var payload map[string]any
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &payload))
	require.Equal(t, "block", payload["action"])
	require.Contains(t, payload["matchedRule"], "ndpi_group:vpn")
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

func TestPrepareForwardRuleRejectsOverlappingEntryGroupPort(t *testing.T) {
	s := testServer(t)
	user, entry, tunnel, _ := seedForwardFixture(t, s)
	user.ForwardLimit = 10
	require.NoError(t, s.db.Save(&user).Error)
	otherTunnel := models.Tunnel{
		Name:              "other",
		Mode:              "single",
		EntryGroupID:      entry.ID,
		Protocol:          "direct",
		FlowAccounting:    "single",
		EntryTrafficRatio: 1,
		ExitTrafficRatio:  1,
	}
	require.NoError(t, s.db.Create(&otherTunnel).Error)
	first := models.ForwardRule{
		UserID:     user.ID,
		TunnelID:   tunnel.ID,
		Name:       "first",
		Protocol:   "tcp",
		Strategy:   "least_conn",
		ListenPort: 20001,
		RemoteHost: "127.0.0.1",
		RemotePort: 8081,
		Status:     "active",
	}
	require.NoError(t, s.db.Create(&first).Error)

	udpSamePort := first
	udpSamePort.ID = 0
	udpSamePort.TunnelID = otherTunnel.ID
	udpSamePort.Name = "udp-ok"
	udpSamePort.Protocol = "udp"
	require.NoError(t, s.prepareForwardRule(&udpSamePort, 0))

	tcpSamePort := udpSamePort
	tcpSamePort.Name = "tcp-conflict"
	tcpSamePort.Protocol = "tcp"
	require.ErrorContains(t, s.prepareForwardRule(&tcpSamePort, 0), "entry device group")

	tcpUDPSamePort := udpSamePort
	tcpUDPSamePort.Name = "tcp-udp-conflict"
	tcpUDPSamePort.Protocol = "tcp_udp"
	require.ErrorContains(t, s.prepareForwardRule(&tcpUDPSamePort, 0), "entry device group")
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
		"version":         "v0.1.5",
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
	require.NoError(t, s.db.First(&node, node.ID).Error)
	require.Equal(t, "uninstalling", node.Status)
	require.Equal(t, "accepted", node.UninstallAckStatus)
	require.False(t, node.UninstallLegacy)

	rec = jsonRequest(t, router, http.MethodPost, "/api/v1/agent/commands/"+node.UninstallCommandID+"/ack", map[string]any{
		"status": "done",
	}, nodeToken)
	require.Equal(t, http.StatusNoContent, rec.Code)
	require.ErrorIs(t, s.db.First(&models.Node{}, node.ID).Error, gorm.ErrRecordNotFound)
}

func TestLegacyAgentAcceptedUninstallDoesNotRemainPending(t *testing.T) {
	s := testServer(t)
	group := models.DeviceGroup{Name: "entry", Role: "entry", PortStart: 20000, PortEnd: 30000, TrafficRatio: 1}
	require.NoError(t, s.db.Create(&group).Error)
	nodeToken := "legacy-node-token"
	now := time.Now().UTC()
	node := models.Node{
		DeviceGroupID: group.ID, Name: "legacy", UUID: "legacy-uninstall", TokenHash: auth.TokenHash(nodeToken),
		Status: "uninstalling", Version: "dev", UninstallCommandID: "uninstall-legacy", UninstallRequestedAt: &now,
	}
	require.NoError(t, s.db.Create(&node).Error)

	rec := jsonRequest(t, testRouter(t, s), http.MethodPost, "/api/v1/agent/commands/uninstall-legacy/ack", map[string]any{
		"status": "accepted", "message": "cleanup scheduled",
	}, nodeToken)
	require.Equal(t, http.StatusNoContent, rec.Code)
	require.NoError(t, s.db.First(&node, node.ID).Error)
	require.Equal(t, "uninstall_legacy", node.Status)
	require.True(t, node.UninstallLegacy)
	require.Equal(t, "accepted", node.UninstallAckStatus)
	require.NotNil(t, node.UninstallAckAt)
}

func TestStaleUninstallBecomesTimeout(t *testing.T) {
	s := testServer(t)
	requestedAt := time.Now().Add(-nodeUninstallAckTimeout - time.Second)
	node := models.Node{DeviceGroupID: 1, Name: "timeout", UUID: "timeout-uninstall", TokenHash: "hash", Status: "uninstalling", UninstallCommandID: "uninstall-timeout", UninstallRequestedAt: &requestedAt}
	require.NoError(t, s.db.Create(&node).Error)

	s.markStaleNodesOffline(time.Now())
	require.NoError(t, s.db.First(&node, node.ID).Error)
	require.Equal(t, "uninstall_timeout", node.Status)
	require.Equal(t, "timeout", node.UninstallAckStatus)
	require.NotNil(t, node.UninstallAckAt)
}

func TestStaleLegacyUninstallIsRecoveredAfterAPIUpgrade(t *testing.T) {
	s := testServer(t)
	requestedAt := time.Now().Add(-nodeUninstallAckTimeout - time.Second)
	lastSeenAt := requestedAt.Add(time.Second)
	node := models.Node{
		DeviceGroupID: 1, Name: "legacy-timeout", UUID: "legacy-timeout-uninstall", TokenHash: "hash",
		Status: "uninstalling", Version: "dev", UninstallCommandID: "uninstall-legacy-timeout",
		UninstallRequestedAt: &requestedAt, LastSeenAt: &lastSeenAt,
	}
	require.NoError(t, s.db.Create(&node).Error)

	s.markStaleNodesOffline(time.Now())
	require.NoError(t, s.db.First(&node, node.ID).Error)
	require.Equal(t, "uninstall_legacy", node.Status)
	require.Equal(t, "legacy", node.UninstallAckStatus)
	require.True(t, node.UninstallLegacy)
}

func TestAgentSupportsFinalUninstallAck(t *testing.T) {
	for version, expected := range map[string]bool{
		"v0.1.4": false, "0.1.5": true, "v0.2.0": true, "v1.0.0": true,
		"v0.1.5-rc.1": true, "dev": false, "test": false, "": false, "0.1": false,
	} {
		require.Equal(t, expected, agentSupportsFinalUninstallAck(version), version)
	}
}

func TestForceDeleteNodeRemovesRecordAndAudits(t *testing.T) {
	s := testServer(t)
	token := adminToken(t, s)
	group := models.DeviceGroup{Name: "entry", Role: "entry", PortStart: 20000, PortEnd: 30000, TrafficRatio: 1}
	require.NoError(t, s.db.Create(&group).Error)
	node := models.Node{
		DeviceGroupID:        group.ID,
		Name:                 "offline-node",
		UUID:                 "node-force-delete",
		TokenHash:            auth.TokenHash("node-token"),
		Status:               "uninstalling",
		UninstallCommandID:   "uninstall-test",
		DesiredRevision:      123,
		UninstallRequestedAt: ptrTime(time.Now().Add(-time.Minute)),
	}
	require.NoError(t, s.db.Create(&node).Error)

	rec := jsonRequest(t, testRouter(t, s), http.MethodDelete, fmt.Sprintf("/api/v1/nodes/%d?force=true", node.ID), map[string]any{}, token)
	require.Equal(t, http.StatusNoContent, rec.Code)
	require.ErrorIs(t, s.db.First(&models.Node{}, node.ID).Error, gorm.ErrRecordNotFound)

	var audit models.AuditLog
	require.NoError(t, s.db.Where("action = ? AND resource_type = ? AND resource_id = ?", "node.delete.force", "node", fmt.Sprint(node.ID)).First(&audit).Error)
	require.Contains(t, audit.MetadataJSON, "uninstall-test")
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

func TestAgentTrafficExhaustsQuotaAndStopsConfig(t *testing.T) {
	s := testServer(t)
	user, entry, tunnel, _ := seedForwardFixture(t, s)
	user.FlowLimitBytes = 5
	user.UsedBytes = 0
	require.NoError(t, s.db.Save(&user).Error)
	rule := models.ForwardRule{
		UserID:     user.ID,
		TunnelID:   tunnel.ID,
		Name:       "quota-rule",
		Protocol:   "tcp",
		Strategy:   "least_conn",
		ListenPort: 20001,
		RemoteHost: "127.0.0.1",
		RemotePort: 8081,
		Status:     "active",
		Revision:   1,
	}
	require.NoError(t, s.db.Create(&rule).Error)
	nodeToken := "node-token"
	node := models.Node{
		DeviceGroupID: entry.ID,
		Name:          "node",
		UUID:          "node-quota",
		TokenHash:     auth.TokenHash(nodeToken),
		Status:        "online",
	}
	require.NoError(t, s.db.Create(&node).Error)
	router := testRouter(t, s)

	rec := jsonRequest(t, router, http.MethodPost, "/api/v1/agent/traffic", map[string]any{
		"samples": []map[string]any{{"ruleId": rule.ID, "inBytes": 3, "outBytes": 3}},
	}, nodeToken)
	require.Equal(t, http.StatusOK, rec.Code)

	require.NoError(t, s.db.First(&user, user.ID).Error)
	require.Equal(t, int64(6), user.UsedBytes)
	require.NoError(t, s.db.First(&rule, rule.ID).Error)
	require.Equal(t, "quota_exhausted", rule.Status)
	require.Greater(t, rule.Revision, int64(1))

	rec = jsonRequest(t, router, http.MethodGet, "/api/v1/agent/config", nil, nodeToken)
	require.Equal(t, http.StatusOK, rec.Code)
	var payload struct {
		ForwardRules []models.ForwardRule `json:"forwardRules"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &payload))
	require.Empty(t, payload.ForwardRules)
}

func TestAgentTrafficReportIDIsIdempotent(t *testing.T) {
	s := testServer(t)
	user, entry, tunnel, _ := seedForwardFixture(t, s)
	user.FlowLimitBytes = 1000
	require.NoError(t, s.db.Save(&user).Error)
	rule := models.ForwardRule{
		UserID:     user.ID,
		TunnelID:   tunnel.ID,
		Name:       "idempotent-rule",
		Protocol:   "tcp",
		Strategy:   "least_conn",
		ListenPort: 20001,
		RemoteHost: "127.0.0.1",
		RemotePort: 8081,
		Status:     "active",
	}
	require.NoError(t, s.db.Create(&rule).Error)
	nodeToken := "node-token"
	node := models.Node{
		DeviceGroupID: entry.ID,
		Name:          "node",
		UUID:          "node-idempotent",
		TokenHash:     auth.TokenHash(nodeToken),
		Status:        "online",
	}
	require.NoError(t, s.db.Create(&node).Error)
	router := testRouter(t, s)
	body := map[string]any{
		"reportId": "report-1",
		"samples":  []map[string]any{{"ruleId": rule.ID, "inBytes": 3, "outBytes": 4}},
	}

	rec := jsonRequest(t, router, http.MethodPost, "/api/v1/agent/traffic", body, nodeToken)
	require.Equal(t, http.StatusOK, rec.Code)
	rec = jsonRequest(t, router, http.MethodPost, "/api/v1/agent/traffic", body, nodeToken)
	require.Equal(t, http.StatusOK, rec.Code)
	require.Contains(t, rec.Body.String(), "duplicate")

	require.NoError(t, s.db.First(&user, user.ID).Error)
	require.Equal(t, int64(7), user.UsedBytes)
	var sampleCount int64
	require.NoError(t, s.db.Model(&models.TrafficSample{}).Where("rule_id = ?", rule.ID).Count(&sampleCount).Error)
	require.Equal(t, int64(2), sampleCount)
}

func TestCreateForwardRuleRejectsDangerousRemoteForUser(t *testing.T) {
	s := testServer(t)
	user, _, tunnel, _ := seedForwardFixture(t, s)
	token, err := auth.GenerateToken(user.ID, user.Role, auth.TokenTypeAccess, "test-secret-for-unit-tests", time.Hour)
	require.NoError(t, err)

	rec := jsonRequest(t, testRouter(t, s), http.MethodPost, "/api/v1/forward-rules", map[string]any{
		"tunnelId":   tunnel.ID,
		"name":       "metadata",
		"protocol":   "tcp",
		"listenPort": 20001,
		"remoteHost": "169.254.169.254",
		"remotePort": 80,
		"strategy":   "least_conn",
	}, token)
	require.Equal(t, http.StatusBadRequest, rec.Code)
	require.Contains(t, rec.Body.String(), "remoteHost")
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

func TestDeleteInstallTokenRevokesAgentRegistration(t *testing.T) {
	s := testServer(t)
	token := adminToken(t, s)
	group := models.DeviceGroup{Name: "entry", Role: "entry", PortStart: 20000, PortEnd: 30000, TrafficRatio: 1}
	require.NoError(t, s.db.Create(&group).Error)
	plain := "install-token"
	row := models.InstallToken{
		Label:         "smoke",
		TokenHash:     auth.TokenHash(plain),
		DeviceGroupID: group.ID,
		ExpiresAt:     time.Now().Add(time.Hour),
	}
	require.NoError(t, s.db.Create(&row).Error)
	router := testRouter(t, s)

	rec := jsonRequest(t, router, http.MethodDelete, fmt.Sprintf("/api/v1/install-tokens/%d", row.ID), map[string]any{}, token)
	require.Equal(t, http.StatusNoContent, rec.Code)

	rec = jsonRequest(t, router, http.MethodPost, "/api/v1/agent/register", map[string]any{
		"installToken": plain,
		"name":         "should-fail",
		"uuid":         "revoked-token-node",
	}, "")
	require.Equal(t, http.StatusUnauthorized, rec.Code)
	require.ErrorIs(t, s.db.First(&models.InstallToken{}, row.ID).Error, gorm.ErrRecordNotFound)
}

func TestInstallTokenCanRegisterOnlyOnce(t *testing.T) {
	s := testServer(t)
	group := models.DeviceGroup{Name: "entry", Role: "entry", PortStart: 20000, PortEnd: 30000, TrafficRatio: 1}
	require.NoError(t, s.db.Create(&group).Error)
	plain := "single-use-install-token"
	row := models.InstallToken{
		Label:         "single-use",
		TokenHash:     auth.TokenHash(plain),
		DeviceGroupID: group.ID,
		ExpiresAt:     time.Now().Add(time.Hour),
	}
	require.NoError(t, s.db.Create(&row).Error)
	router := testRouter(t, s)

	rec := jsonRequest(t, router, http.MethodPost, "/api/v1/agent/register", map[string]any{
		"installToken": plain,
		"name":         "first",
		"uuid":         "single-use-node-1",
	}, "")
	require.Equal(t, http.StatusCreated, rec.Code, rec.Body.String())

	rec = jsonRequest(t, router, http.MethodPost, "/api/v1/agent/register", map[string]any{
		"installToken": plain,
		"name":         "second",
		"uuid":         "single-use-node-2",
	}, "")
	require.Equal(t, http.StatusUnauthorized, rec.Code)
}

func ptrTime(value time.Time) *time.Time {
	return &value
}
