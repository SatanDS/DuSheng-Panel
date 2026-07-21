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
		&models.Tenant{},
		&models.TenantTunnelGrant{},
		&models.UserTunnelGrant{},
		&models.TenantTrafficHourlyBucket{},
		&models.PortLease{},
		&models.User{},
		&models.DeviceGroup{},
		&models.LineProvider{},
		&models.LineSite{},
		&models.LineCircuit{},
		&models.LineEndpoint{},
		&models.LineProbe{},
		&models.LineProbeSample{},
		&models.Node{},
		&models.Tunnel{},
		&models.ForwardRule{},
		&models.ProtocolPolicy{},
		&models.SpeedLimit{},
		&models.TrafficSample{},
		&models.AgentTrafficReport{},
		&models.AuditLog{},
		&models.AgentEvent{},
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
	require.NoError(t, s.db.Create(&models.UserTunnelGrant{
		UserID: user.ID, TunnelID: tunnel.ID, PortStart: entry.PortStart, PortEnd: entry.PortEnd,
	}).Error)
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

func TestHealthAndMetricsEndpoints(t *testing.T) {
	s := testServer(t)
	require.NoError(t, s.db.Create(&models.Tenant{
		Name: "Metrics Tenant", Code: "metrics-tenant", Status: "active", UsedBytes: 42, QuotaBlocked: true,
	}).Error)
	router := testRouter(t, s)
	rec := jsonRequest(t, router, http.MethodGet, "/healthz", nil, "")
	require.Equal(t, http.StatusOK, rec.Code)
	require.Contains(t, rec.Body.String(), `"status":"ok"`)

	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	req.Header.Set("Accept", "text/plain")
	rec = httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	require.Equal(t, http.StatusOK, rec.Code)
	require.Contains(t, rec.Body.String(), "dusheng_panel_accounted_bytes")
	require.Contains(t, rec.Body.String(), `dusheng_panel_tenants{status="active"} 1`)
	require.Contains(t, rec.Body.String(), "dusheng_panel_tenant_accounted_bytes 42")
	require.Contains(t, rec.Body.String(), "dusheng_panel_tenant_quota_blocked 1")
	require.Contains(t, rec.Body.String(), "dusheng_panel_tenant_tunnel_grants 0")
	require.Contains(t, rec.Body.String(), "dusheng_panel_user_tunnel_grants 0")
	require.Contains(t, rec.Body.String(), "dusheng_api_http_requests_total")
}

func TestInstallAgentBootstrapReportsDownloadAndHasTimeout(t *testing.T) {
	s := testServer(t)
	rec := jsonRequest(t, testRouter(t, s), http.MethodGet, "/install-agent.sh", nil, "")
	require.Equal(t, http.StatusOK, rec.Code)
	require.Contains(t, rec.Header().Get("Content-Type"), "text/x-shellscript")
	require.Contains(t, rec.Body.String(), "Downloading DuSheng agent installer")
	require.Contains(t, rec.Body.String(), "--connect-timeout 10 --max-time 90")
	require.Contains(t, rec.Body.String(), "Set DUSHENG_INSTALLER_URL to a reachable mirror")
}

func TestRequestBodyLimitRejectsOversizedPayload(t *testing.T) {
	s := testServer(t)
	rec := jsonRequest(t, testRouter(t, s), http.MethodPost, "/api/v1/auth/login", map[string]any{
		"username": strings.Repeat("x", int(maxRequestBodyBytes)), "password": "secret",
	}, "")
	require.Equal(t, http.StatusRequestEntityTooLarge, rec.Code)
}

func TestLoginLimiterHasBoundedMemory(t *testing.T) {
	limiter := newLoginLimiter()
	now := time.Now()
	for index := 0; index < maxLoginLimiterEntries+100; index++ {
		limiter.fail(fmt.Sprintf("client-%d", index), now.Add(time.Duration(index)*time.Nanosecond))
	}
	require.LessOrEqual(t, len(limiter.attempts), maxLoginLimiterEntries)
}

func TestExpiredUserCannotAuthenticateOrRefresh(t *testing.T) {
	s := testServer(t)
	hash, err := auth.HashPassword("secret")
	require.NoError(t, err)
	expiresAt := time.Now().Add(-time.Minute)
	user := models.User{
		Username: "expired-user", PasswordHash: hash, Role: "user", Status: "active", ExpiresAt: &expiresAt,
	}
	require.NoError(t, s.db.Create(&user).Error)
	router := testRouter(t, s)
	rec := jsonRequest(t, router, http.MethodPost, "/api/v1/auth/login", map[string]any{
		"username": user.Username, "password": "secret",
	}, "")
	require.Equal(t, http.StatusUnauthorized, rec.Code)

	access, err := auth.GenerateToken(user.ID, user.Role, auth.TokenTypeAccess, "test-secret-for-unit-tests", time.Hour)
	require.NoError(t, err)
	rec = jsonRequest(t, router, http.MethodGet, "/api/v1/me", nil, access)
	require.Equal(t, http.StatusUnauthorized, rec.Code)
	refresh, err := auth.GenerateToken(user.ID, user.Role, auth.TokenTypeRefresh, "test-secret-for-unit-tests", time.Hour)
	require.NoError(t, err)
	rec = jsonRequest(t, router, http.MethodPost, "/api/v1/auth/refresh", nil, refresh)
	require.Equal(t, http.StatusUnauthorized, rec.Code)
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

func TestPortLeaseUniqueEntryGroupTransportAndPort(t *testing.T) {
	s := testServer(t)
	_, entry, _, _ := seedForwardFixture(t, s)
	first := models.PortLease{
		EntryGroupID: entry.ID,
		BindIP:       "*",
		Transport:    "tcp",
		ListenPort:   20001,
		RuleID:       1001,
	}
	require.NoError(t, s.db.Create(&first).Error)

	second := first
	second.ID = 0
	second.RuleID = 1002
	require.Error(t, s.db.Create(&second).Error)

	udp := first
	udp.ID = 0
	udp.Transport = "udp"
	udp.RuleID = 1003
	require.NoError(t, s.db.Create(&udp).Error)
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
	require.NoError(t, s.db.Create(&models.UserTunnelGrant{UserID: user.ID, TunnelID: otherTunnel.ID}).Error)
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

func TestLineAssetLifecycleAndReferenceGuards(t *testing.T) {
	s := testServer(t)
	token := adminToken(t, s)
	router := testRouter(t, s)
	group := models.DeviceGroup{Name: "entry", Role: "entry", PortStart: 20000, PortEnd: 30000, TrafficRatio: 1}
	require.NoError(t, s.db.Create(&group).Error)

	rec := jsonRequest(t, router, http.MethodPost, "/api/v1/line-providers", map[string]any{
		"name": "Carrier A", "code": "carrier-a", "status": "active", "portalUrl": "https://carrier.example.com",
	}, token)
	require.Equal(t, http.StatusCreated, rec.Code)
	var provider models.LineProvider
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &provider))

	rec = jsonRequest(t, router, http.MethodPost, "/api/v1/line-sites", map[string]any{
		"name": "Tokyo POP", "code": "tyo", "status": "active", "country": "JP", "city": "Tokyo",
	}, token)
	require.Equal(t, http.StatusCreated, rec.Code)
	var site models.LineSite
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &site))

	rec = jsonRequest(t, router, http.MethodPost, "/api/v1/line-circuits", map[string]any{
		"providerId": provider.ID, "name": "IEPL-TYO-01", "serviceType": "iepl", "status": "active",
		"bandwidthMbps": 100, "committedMbps": 200,
	}, token)
	require.Equal(t, http.StatusBadRequest, rec.Code)

	rec = jsonRequest(t, router, http.MethodPost, "/api/v1/line-circuits", map[string]any{
		"providerId": provider.ID, "name": "IEPL-TYO-01", "circuitCode": "C-1001",
		"serviceType": "iepl", "status": "active", "bandwidthMbps": 1000, "committedMbps": 500,
		"latencySlaMs": 60, "packetLossSlaPct": 0.5, "currency": "USD",
	}, token)
	require.Equal(t, http.StatusCreated, rec.Code)
	var circuit models.LineCircuit
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &circuit))

	endpoint := map[string]any{
		"circuitId": circuit.ID, "side": "a", "siteId": site.ID, "deviceGroupId": group.ID,
		"interface": "eth1", "vlan": 101, "ipCidrs": "10.0.0.1/30, 2001:db8::1/126",
	}
	rec = jsonRequest(t, router, http.MethodPost, "/api/v1/line-endpoints", endpoint, token)
	require.Equal(t, http.StatusCreated, rec.Code)
	var lineEndpoint models.LineEndpoint
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &lineEndpoint))
	require.Contains(t, lineEndpoint.IPCIDRs, "10.0.0.0/30")

	rec = jsonRequest(t, router, http.MethodPost, "/api/v1/line-endpoints", endpoint, token)
	require.Equal(t, http.StatusBadRequest, rec.Code)

	rec = jsonRequest(t, router, http.MethodDelete, fmt.Sprintf("/api/v1/line-circuits/%d", circuit.ID), nil, token)
	require.Equal(t, http.StatusBadRequest, rec.Code)
	rec = jsonRequest(t, router, http.MethodDelete, fmt.Sprintf("/api/v1/line-endpoints/%d", lineEndpoint.ID), nil, token)
	require.Equal(t, http.StatusNoContent, rec.Code)
	rec = jsonRequest(t, router, http.MethodDelete, fmt.Sprintf("/api/v1/line-circuits/%d", circuit.ID), nil, token)
	require.Equal(t, http.StatusNoContent, rec.Code)
}

func TestLineProbeConfigAndAgentResult(t *testing.T) {
	s := testServer(t)
	admin := adminToken(t, s)
	router := testRouter(t, s)
	provider := models.LineProvider{Name: "Carrier", Status: "active"}
	require.NoError(t, s.db.Create(&provider).Error)
	circuit := models.LineCircuit{ProviderID: provider.ID, Name: "IEPL", ServiceType: "iepl", Status: "active", BandwidthMbps: 100}
	require.NoError(t, s.db.Create(&circuit).Error)
	group := models.DeviceGroup{Name: "entry", Role: "entry", PortStart: 20000, PortEnd: 30000, TrafficRatio: 1}
	require.NoError(t, s.db.Create(&group).Error)
	nodeToken := "probe-node-token"
	node := models.Node{
		DeviceGroupID: group.ID, Name: "probe-node", UUID: "probe-node", TokenHash: auth.TokenHash(nodeToken),
		Status: "online", Capabilities: []string{"line_probe_v1"},
	}
	require.NoError(t, s.db.Create(&node).Error)

	rec := jsonRequest(t, router, http.MethodPost, "/api/v1/line-probes", map[string]any{
		"circuitId": circuit.ID, "nodeId": node.ID, "name": "TCP SLA", "type": "tcp",
		"target": "127.0.0.1:443", "intervalSeconds": 15, "timeoutMs": 1000, "enabled": true,
	}, admin)
	require.Equal(t, http.StatusCreated, rec.Code)
	var probe models.LineProbe
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &probe))
	require.Greater(t, probe.ID, uint(0))
	require.NoError(t, s.db.First(&node, node.ID).Error)
	require.Greater(t, node.DesiredRevision, int64(0))

	rec = jsonRequest(t, router, http.MethodGet, "/api/v1/agent/config", nil, nodeToken)
	require.Equal(t, http.StatusOK, rec.Code)
	var configPayload struct {
		LineProbes []models.LineProbe `json:"lineProbes"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &configPayload))
	require.Len(t, configPayload.LineProbes, 1)
	require.Equal(t, probe.ID, configPayload.LineProbes[0].ID)

	rec = jsonRequest(t, router, http.MethodPost, "/api/v1/agent/probes", map[string]any{
		"probeId": probe.ID, "revision": probe.Revision, "success": true, "latencyMs": 12.5,
	}, nodeToken)
	require.Equal(t, http.StatusNoContent, rec.Code)
	require.NoError(t, s.db.First(&probe, probe.ID).Error)
	require.Equal(t, "up", probe.Status)
	require.Equal(t, 12.5, probe.LastLatencyMs)
	require.NotNil(t, probe.LastCheckedAt)

	var sample models.LineProbeSample
	require.NoError(t, s.db.Where("probe_id = ?", probe.ID).First(&sample).Error)
	require.True(t, sample.Success)
	var event models.AgentEvent
	require.NoError(t, s.db.Where("node_id = ? AND type = ?", node.ID, "line_probe.up").First(&event).Error)
	legacyNode := models.Node{
		DeviceGroupID: group.ID, Name: "legacy-node", UUID: "legacy-probe-node", TokenHash: "legacy-token", Status: "online",
	}
	require.NoError(t, s.db.Create(&legacyNode).Error)
	rec = jsonRequest(t, router, http.MethodPost, "/api/v1/line-probes", map[string]any{
		"circuitId": circuit.ID, "nodeId": legacyNode.ID, "name": "unsupported probe", "type": "tcp",
		"target": "127.0.0.1:443", "intervalSeconds": 15, "timeoutMs": 1000, "enabled": true,
	}, admin)
	require.Equal(t, http.StatusBadRequest, rec.Code)
	require.Contains(t, rec.Body.String(), "line_probe_v1")
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

func TestAgentConfigFiltersInactiveAndExpiredUsers(t *testing.T) {
	s := testServer(t)
	admin := adminToken(t, s)
	user, entry, tunnel, _ := seedForwardFixture(t, s)
	rule := models.ForwardRule{
		UserID: user.ID, TunnelID: tunnel.ID, Name: "effective-user-rule", Protocol: "tcp", Strategy: "least_conn",
		ListenPort: 20001, RemoteHost: "127.0.0.1", RemotePort: 8081, Status: "active", Revision: 1,
	}
	require.NoError(t, s.db.Create(&rule).Error)
	nodeToken := "effective-user-node-token"
	node := models.Node{
		DeviceGroupID: entry.ID, Name: "node", UUID: "effective-user-node",
		TokenHash: auth.TokenHash(nodeToken), Status: "online",
	}
	require.NoError(t, s.db.Create(&node).Error)
	router := testRouter(t, s)

	readConfig := func() (int64, []models.ForwardRule) {
		rec := jsonRequest(t, router, http.MethodGet, "/api/v1/agent/config", nil, nodeToken)
		require.Equal(t, http.StatusOK, rec.Code)
		var payload struct {
			Revision     int64                `json:"revision"`
			ForwardRules []models.ForwardRule `json:"forwardRules"`
		}
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &payload))
		return payload.Revision, payload.ForwardRules
	}

	activeRevision, rules := readConfig()
	require.Len(t, rules, 1)
	rec := jsonRequest(t, router, http.MethodPut, fmt.Sprintf("/api/v1/users/%d", user.ID), map[string]any{
		"username": user.Username, "displayName": user.DisplayName, "role": user.Role, "status": "disabled",
		"flowLimitBytes": user.FlowLimitBytes, "forwardLimit": user.ForwardLimit,
	}, admin)
	require.Equal(t, http.StatusOK, rec.Code)
	disabledRevision, rules := readConfig()
	require.Empty(t, rules)
	require.Greater(t, disabledRevision, activeRevision)

	expiredAt := time.Now().Add(-time.Second).UTC()
	rec = jsonRequest(t, router, http.MethodPut, fmt.Sprintf("/api/v1/users/%d", user.ID), map[string]any{
		"username": user.Username, "displayName": user.DisplayName, "role": user.Role, "status": "active",
		"flowLimitBytes": user.FlowLimitBytes, "forwardLimit": user.ForwardLimit, "expiresAt": expiredAt,
	}, admin)
	require.Equal(t, http.StatusOK, rec.Code)
	expiredRevision, rules := readConfig()
	require.Empty(t, rules)
	require.Greater(t, expiredRevision, disabledRevision)
}

func TestAgentConfigOnlyStartsRulesOnEntryNodes(t *testing.T) {
	s := testServer(t)
	user, entry, tunnel, _ := seedForwardFixture(t, s)
	exit := models.DeviceGroup{Name: "exit", Role: "exit", PortStart: 20000, PortEnd: 30000, TrafficRatio: 1}
	require.NoError(t, s.db.Create(&exit).Error)
	tunnel.ExitGroupID = &exit.ID
	require.NoError(t, s.db.Save(&tunnel).Error)
	rule := models.ForwardRule{
		UserID: user.ID, TunnelID: tunnel.ID, Name: "entry-only-rule", Protocol: "tcp", Strategy: "least_conn",
		ListenPort: 20001, RemoteHost: "127.0.0.1", RemotePort: 8081, Status: "active", Revision: 1,
	}
	require.NoError(t, s.db.Create(&rule).Error)
	entryToken := "entry-config-token"
	exitToken := "exit-config-token"
	require.NoError(t, s.db.Create(&models.Node{
		DeviceGroupID: entry.ID, Name: "entry-node", UUID: "entry-config-node", TokenHash: auth.TokenHash(entryToken), Status: "online",
	}).Error)
	require.NoError(t, s.db.Create(&models.Node{
		DeviceGroupID: exit.ID, Name: "exit-node", UUID: "exit-config-node", TokenHash: auth.TokenHash(exitToken), Status: "online",
	}).Error)
	router := testRouter(t, s)
	readRules := func(token string) []models.ForwardRule {
		rec := jsonRequest(t, router, http.MethodGet, "/api/v1/agent/config", nil, token)
		require.Equal(t, http.StatusOK, rec.Code)
		var payload struct {
			ForwardRules []models.ForwardRule `json:"forwardRules"`
		}
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &payload))
		return payload.ForwardRules
	}
	require.Len(t, readRules(entryToken), 1)
	require.Empty(t, readRules(exitToken))
}

func TestResourceMovesBumpOldAndNewNodeRevisions(t *testing.T) {
	s := testServer(t)
	token := adminToken(t, s)
	router := testRouter(t, s)
	groups := []models.DeviceGroup{
		{Name: "entry-a", Role: "entry", PortStart: 20000, PortEnd: 20999, TrafficRatio: 1},
		{Name: "entry-b", Role: "entry", PortStart: 21000, PortEnd: 21999, TrafficRatio: 1},
		{Name: "entry-c", Role: "entry", PortStart: 22000, PortEnd: 22999, TrafficRatio: 1},
	}
	for index := range groups {
		require.NoError(t, s.db.Create(&groups[index]).Error)
	}
	nodes := []models.Node{
		{DeviceGroupID: groups[0].ID, Name: "node-a", UUID: "move-node-a", TokenHash: "a", Status: "online"},
		{DeviceGroupID: groups[1].ID, Name: "node-b", UUID: "move-node-b", TokenHash: "b", Status: "online"},
		{DeviceGroupID: groups[2].ID, Name: "node-c", UUID: "move-node-c", TokenHash: "c", Status: "online"},
	}
	for index := range nodes {
		require.NoError(t, s.db.Create(&nodes[index]).Error)
	}
	tunnelA := models.Tunnel{
		Name: "tunnel-a", Mode: "single", EntryGroupID: groups[0].ID, Protocol: "direct",
		FlowAccounting: "single", EntryTrafficRatio: 1, ExitTrafficRatio: 1,
	}
	require.NoError(t, s.db.Create(&tunnelA).Error)
	rec := jsonRequest(t, router, http.MethodPut, fmt.Sprintf("/api/v1/tunnels/%d", tunnelA.ID), map[string]any{
		"name": "tunnel-a", "mode": "single", "entryGroupId": groups[1].ID, "protocol": "direct",
		"flowAccounting": "single", "entryTrafficRatio": 1, "exitTrafficRatio": 1,
	}, token)
	require.Equal(t, http.StatusOK, rec.Code)
	require.NoError(t, s.db.First(&nodes[0], nodes[0].ID).Error)
	require.NoError(t, s.db.First(&nodes[1], nodes[1].ID).Error)
	require.Greater(t, nodes[0].DesiredRevision, int64(0))
	require.Greater(t, nodes[1].DesiredRevision, int64(0))

	user := models.User{Username: "move-user", PasswordHash: "hash", Role: "user", Status: "active", ForwardLimit: 10}
	require.NoError(t, s.db.Create(&user).Error)
	tunnelB := models.Tunnel{
		Name: "tunnel-b", Mode: "single", EntryGroupID: groups[2].ID, Protocol: "direct",
		FlowAccounting: "single", EntryTrafficRatio: 1, ExitTrafficRatio: 1,
	}
	require.NoError(t, s.db.Create(&tunnelB).Error)
	require.NoError(t, s.db.Create(&models.UserTunnelGrant{UserID: user.ID, TunnelID: tunnelB.ID}).Error)
	rule := models.ForwardRule{
		UserID: user.ID, TunnelID: tunnelA.ID, Name: "move-rule", Protocol: "tcp", ListenPort: 21500,
		RemoteHost: "198.51.100.10", RemotePort: 443, Status: "active", Strategy: "least_conn",
	}
	require.NoError(t, s.db.Create(&rule).Error)
	require.NoError(t, s.db.Model(&models.Node{}).Where("id IN ?", []uint{nodes[1].ID, nodes[2].ID}).Update("desired_revision", 0).Error)
	rec = jsonRequest(t, router, http.MethodPut, fmt.Sprintf("/api/v1/forward-rules/%d", rule.ID), map[string]any{
		"userId": user.ID, "tunnelId": tunnelB.ID, "name": "move-rule", "protocol": "tcp",
		"listenPort": 22500, "remoteHost": "198.51.100.10", "remotePort": 443, "status": "active", "strategy": "least_conn",
	}, token)
	require.Equal(t, http.StatusOK, rec.Code)
	require.NoError(t, s.db.First(&nodes[1], nodes[1].ID).Error)
	require.NoError(t, s.db.First(&nodes[2], nodes[2].ID).Error)
	require.Greater(t, nodes[1].DesiredRevision, int64(0))
	require.Greater(t, nodes[2].DesiredRevision, int64(0))

	previousRevision := nodes[0].DesiredRevision
	rec = jsonRequest(t, router, http.MethodPut, fmt.Sprintf("/api/v1/nodes/%d", nodes[0].ID), map[string]any{
		"deviceGroupId": groups[2].ID, "name": nodes[0].Name, "status": "online",
	}, token)
	require.Equal(t, http.StatusOK, rec.Code)
	require.NoError(t, s.db.First(&nodes[0], nodes[0].ID).Error)
	require.Equal(t, groups[2].ID, nodes[0].DeviceGroupID)
	require.Greater(t, nodes[0].DesiredRevision, previousRevision)
}

func TestDesiredRevisionBumpsNeverRegress(t *testing.T) {
	s := testServer(t)
	group := models.DeviceGroup{Name: "revision-group", Role: "entry", TrafficRatio: 1}
	require.NoError(t, s.db.Create(&group).Error)
	node := models.Node{
		DeviceGroupID: group.ID, Name: "revision-node", UUID: "revision-node", TokenHash: "revision-token",
		Status: "online", DesiredRevision: 200,
	}
	require.NoError(t, s.db.Create(&node).Error)
	require.NoError(t, bumpNodesByGroupWithDB(s.db, []uint{group.ID}, 100))
	require.NoError(t, bumpNodeRevisionWithDB(s.db, node.ID, 150))
	require.NoError(t, s.db.First(&node, node.ID).Error)
	require.Equal(t, int64(200), node.DesiredRevision)
	require.NoError(t, bumpNodeRevisionWithDB(s.db, node.ID, 250))
	require.NoError(t, s.db.First(&node, node.ID).Error)
	require.Equal(t, int64(250), node.DesiredRevision)
}

func TestAgentCapabilitiesAndConfigAcknowledgement(t *testing.T) {
	s := testServer(t)
	group := models.DeviceGroup{Name: "entry", Role: "entry", PortStart: 20000, PortEnd: 30000, TrafficRatio: 1}
	require.NoError(t, s.db.Create(&group).Error)
	nodeToken := "capability-node-token"
	node := models.Node{
		DeviceGroupID: group.ID, Name: "capable", UUID: "capability-node",
		TokenHash: auth.TokenHash(nodeToken), Status: "online", Version: "dev", DesiredRevision: 42,
	}
	require.NoError(t, s.db.Create(&node).Error)
	router := testRouter(t, s)

	rec := jsonRequest(t, router, http.MethodPost, "/api/v1/agent/heartbeat", map[string]any{
		"version": "dev", "appliedRevision": 0,
		"capabilities": []string{"tcp_runtime", "final_uninstall_ack", "tcp_runtime"},
		"system":       map[string]any{"runtime": map[string]any{"listeners": 1}},
	}, nodeToken)
	require.Equal(t, http.StatusOK, rec.Code)
	require.NoError(t, s.db.First(&node, node.ID).Error)
	require.Equal(t, []string{"tcp_runtime", "final_uninstall_ack"}, node.Capabilities)
	require.True(t, nodeSupportsFinalUninstallAck(node))

	rec = jsonRequest(t, router, http.MethodGet, "/api/v1/agent/config", nil, nodeToken)
	require.Equal(t, http.StatusOK, rec.Code)
	var configPayload struct {
		Revision int64  `json:"revision"`
		Nonce    string `json:"nonce"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &configPayload))
	require.GreaterOrEqual(t, configPayload.Revision, int64(42))
	require.NotEmpty(t, configPayload.Nonce)

	rec = jsonRequest(t, router, http.MethodPost, "/api/v1/agent/config/ack", map[string]any{
		"revision": configPayload.Revision, "nonce": configPayload.Nonce, "status": "applied",
		"runtime": map[string]any{"listeners": 1},
	}, nodeToken)
	require.Equal(t, http.StatusNoContent, rec.Code)
	require.NoError(t, s.db.First(&node, node.ID).Error)
	require.Equal(t, "applied", node.ConfigStatus)
	require.Equal(t, configPayload.Revision, node.AppliedRevision)
	require.Equal(t, configPayload.Revision, node.LastGoodRevision)
	require.NotNil(t, node.ConfigAckAt)

	rec = jsonRequest(t, router, http.MethodPost, "/api/v1/agent/config/ack", map[string]any{
		"revision": configPayload.Revision - 1, "nonce": configNonce(node, configPayload.Revision-1), "status": "rejected", "message": "stale error",
	}, nodeToken)
	require.Equal(t, http.StatusNoContent, rec.Code)
	require.NoError(t, s.db.First(&node, node.ID).Error)
	require.Equal(t, "applied", node.ConfigStatus, "stale ack must not replace newer state")
	require.Equal(t, configPayload.Revision, node.ConfigAckRevision)

	var events []models.AgentEvent
	require.NoError(t, s.db.Where("node_id = ?", node.ID).Order("id asc").Find(&events).Error)
	require.Len(t, events, 2)
	require.Equal(t, "config.applied", events[0].Type)
	require.Equal(t, "config.rejected", events[1].Type)
}

func TestConfigAckRejectsMismatchedNonce(t *testing.T) {
	s := testServer(t)
	nodeToken := "nonce-node-token"
	node := models.Node{DeviceGroupID: 1, Name: "node", UUID: "nonce-node", TokenHash: auth.TokenHash(nodeToken), Status: "online"}
	require.NoError(t, s.db.Create(&node).Error)
	rec := jsonRequest(t, testRouter(t, s), http.MethodPost, "/api/v1/agent/config/ack", map[string]any{
		"revision": 1, "nonce": "wrong", "status": "applied",
	}, nodeToken)
	require.Equal(t, http.StatusBadRequest, rec.Code)
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
	readRevision := func() int64 {
		rec := jsonRequest(t, router, http.MethodGet, "/api/v1/agent/config", nil, nodeToken)
		require.Equal(t, http.StatusOK, rec.Code)
		var payload struct {
			Revision int64 `json:"revision"`
		}
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &payload))
		return payload.Revision
	}
	configRevision := readRevision()
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
	require.Equal(t, configRevision, readRevision(), "usage accounting must not churn the agent configuration revision")
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

func TestTenantTrafficQuotaIsIdempotentAndStopsAgentConfig(t *testing.T) {
	s := testServer(t)
	user, entry, tunnel, _ := seedForwardFixture(t, s)
	now := time.Now().UTC()
	nextReset := now.Add(30 * 24 * time.Hour)
	tenant := models.Tenant{
		Name: "Game Team", Code: "game-team", Status: "active", TrafficLimitBytes: 20,
		ResetIntervalDays: 30, PeriodStartedAt: &now, NextResetAt: &nextReset,
	}
	require.NoError(t, s.db.Create(&tenant).Error)
	user.TenantID = &tenant.ID
	user.FlowLimitBytes = 1 << 30
	require.NoError(t, s.db.Save(&user).Error)
	require.NoError(t, s.db.Create(&models.TenantTunnelGrant{TenantID: tenant.ID, TunnelID: tunnel.ID}).Error)
	rule := models.ForwardRule{
		TenantID: &tenant.ID, UserID: user.ID, TunnelID: tunnel.ID, Name: "tenant-quota-rule",
		Protocol: "tcp", Strategy: "least_conn", ListenPort: 20001,
		RemoteHost: "127.0.0.1", RemotePort: 8081, Status: "active", Revision: 1,
	}
	require.NoError(t, s.db.Create(&rule).Error)
	nodeToken := "tenant-quota-node-token"
	node := models.Node{
		DeviceGroupID: entry.ID, Name: "tenant-node", UUID: "tenant-quota-node",
		TokenHash: auth.TokenHash(nodeToken), Status: "online",
	}
	require.NoError(t, s.db.Create(&node).Error)
	router := testRouter(t, s)
	body := map[string]any{
		"reportId": "tenant-report-1",
		"samples":  []map[string]any{{"ruleId": rule.ID, "inBytes": 6, "outBytes": 5}},
	}
	rec := jsonRequest(t, router, http.MethodPost, "/api/v1/agent/traffic", body, nodeToken)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	rec = jsonRequest(t, router, http.MethodPost, "/api/v1/agent/traffic", body, nodeToken)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	require.Contains(t, rec.Body.String(), "duplicate")
	rec = jsonRequest(t, router, http.MethodPost, "/api/v1/agent/traffic", map[string]any{
		"reportId": "tenant-report-2",
		"samples":  []map[string]any{{"ruleId": rule.ID, "inBytes": 6, "outBytes": 5}},
	}, nodeToken)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

	require.NoError(t, s.db.First(&tenant, tenant.ID).Error)
	require.Equal(t, int64(22), tenant.UsedBytes)
	require.True(t, tenant.QuotaBlocked)
	require.NoError(t, s.db.First(&rule, rule.ID).Error)
	require.Equal(t, "quota_exhausted", rule.Status)
	require.Equal(t, "tenant", rule.QuotaSource)
	var buckets []models.TenantTrafficHourlyBucket
	require.NoError(t, s.db.Where("tenant_id = ?", tenant.ID).Find(&buckets).Error)
	require.Len(t, buckets, 1)
	require.Equal(t, int64(22), buckets[0].BilledBytes)

	rec = jsonRequest(t, router, http.MethodGet, "/api/v1/agent/config", nil, nodeToken)
	require.Equal(t, http.StatusOK, rec.Code)
	var configPayload struct {
		ForwardRules []models.ForwardRule `json:"forwardRules"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &configPayload))
	require.Empty(t, configPayload.ForwardRules)

	admin := adminToken(t, s)
	rec = jsonRequest(t, router, http.MethodPost, fmt.Sprintf("/api/v1/tenants/%d/traffic/reset", tenant.ID), map[string]any{}, admin)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	require.NoError(t, s.db.First(&tenant, tenant.ID).Error)
	require.Zero(t, tenant.UsedBytes)
	require.False(t, tenant.QuotaBlocked)
	require.NoError(t, s.db.First(&rule, rule.ID).Error)
	require.Equal(t, "unsynced", rule.Status)
	require.Empty(t, rule.QuotaSource)
}

func TestTenantQuotaResetKeepsUserQuotaExhausted(t *testing.T) {
	s := testServer(t)
	user, entry, tunnel, _ := seedForwardFixture(t, s)
	now := time.Now().UTC()
	tenant := models.Tenant{
		Name: "Layered Quota", Code: "layered-quota", Status: "active", TrafficLimitBytes: 10,
		PeriodStartedAt: &now,
	}
	require.NoError(t, s.db.Create(&tenant).Error)
	user.TenantID = &tenant.ID
	user.FlowLimitBytes = 10
	require.NoError(t, s.db.Save(&user).Error)
	require.NoError(t, s.db.Create(&models.TenantTunnelGrant{TenantID: tenant.ID, TunnelID: tunnel.ID}).Error)
	rule := models.ForwardRule{
		TenantID: &tenant.ID, UserID: user.ID, TunnelID: tunnel.ID, Name: "layered-quota-rule",
		Protocol: "tcp", Strategy: "least_conn", ListenPort: 20001,
		RemoteHost: "127.0.0.1", RemotePort: 8081, Status: "active", Revision: 1,
	}
	require.NoError(t, s.db.Create(&rule).Error)
	nodeToken := "layered-quota-node-token"
	node := models.Node{
		DeviceGroupID: entry.ID, Name: "layered-node", UUID: "layered-quota-node",
		TokenHash: auth.TokenHash(nodeToken), Status: "online",
	}
	require.NoError(t, s.db.Create(&node).Error)
	router := testRouter(t, s)
	rec := jsonRequest(t, router, http.MethodPost, "/api/v1/agent/traffic", map[string]any{
		"reportId": "layered-report-1",
		"samples":  []map[string]any{{"ruleId": rule.ID, "inBytes": 6, "outBytes": 5}},
	}, nodeToken)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

	require.NoError(t, s.db.First(&rule, rule.ID).Error)
	require.Equal(t, "quota_exhausted", rule.Status)
	require.Equal(t, "tenant", rule.QuotaSource)

	admin := adminToken(t, s)
	rec = jsonRequest(t, router, http.MethodPost, fmt.Sprintf("/api/v1/tenants/%d/traffic/reset", tenant.ID), map[string]any{}, admin)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	require.NoError(t, s.db.First(&rule, rule.ID).Error)
	require.Equal(t, "quota_exhausted", rule.Status)
	require.Equal(t, "user", rule.QuotaSource)

	rec = jsonRequest(t, router, http.MethodGet, "/api/v1/agent/config", nil, nodeToken)
	require.Equal(t, http.StatusOK, rec.Code)
	var configPayload struct {
		ForwardRules []models.ForwardRule `json:"forwardRules"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &configPayload))
	require.Empty(t, configPayload.ForwardRules)

	rec = jsonRequest(t, router, http.MethodPost, fmt.Sprintf("/api/v1/users/%d/traffic/reset", user.ID), map[string]any{}, admin)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	require.NoError(t, s.db.First(&rule, rule.ID).Error)
	require.Equal(t, "unsynced", rule.Status)
	require.Empty(t, rule.QuotaSource)
}

func TestTenantStatusUpdateBumpsNodeRevisionAndStopsConfig(t *testing.T) {
	s := testServer(t)
	user, entry, tunnel, _ := seedForwardFixture(t, s)
	tenant := models.Tenant{Name: "Revision Tenant", Code: "revision-tenant", Status: "active"}
	require.NoError(t, s.db.Create(&tenant).Error)
	user.TenantID = &tenant.ID
	require.NoError(t, s.db.Save(&user).Error)
	rule := models.ForwardRule{
		TenantID: &tenant.ID, UserID: user.ID, TunnelID: tunnel.ID, Name: "tenant-status-rule",
		Protocol: "tcp", ListenPort: 20001, RemoteHost: "127.0.0.1", RemotePort: 8081, Status: "active",
	}
	require.NoError(t, s.db.Create(&rule).Error)
	node := models.Node{DeviceGroupID: entry.ID, Name: "tenant-status-node", UUID: "tenant-status-node", TokenHash: "hash", DesiredRevision: 1}
	require.NoError(t, s.db.Create(&node).Error)
	router := testRouter(t, s)
	rec := jsonRequest(t, router, http.MethodPut, fmt.Sprintf("/api/v1/tenants/%d", tenant.ID), map[string]any{
		"name": tenant.Name, "code": tenant.Code, "status": "suspended",
	}, adminToken(t, s))
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	require.NoError(t, s.db.First(&node, node.ID).Error)
	require.Greater(t, node.DesiredRevision, int64(1))
	active, _, err := s.activeAgentRules([]models.ForwardRule{rule}, time.Now().UTC())
	require.NoError(t, err)
	require.Empty(t, active)
}

func TestTenantTunnelGrantRejectsBreakingChangesAndBumpsRevision(t *testing.T) {
	s := testServer(t)
	user, entry, tunnel, _ := seedForwardFixture(t, s)
	tenant := models.Tenant{Name: "Grant Tenant", Code: "grant-tenant", Status: "active"}
	require.NoError(t, s.db.Create(&tenant).Error)
	user.TenantID = &tenant.ID
	require.NoError(t, s.db.Save(&user).Error)
	grant := models.TenantTunnelGrant{TenantID: tenant.ID, TunnelID: tunnel.ID, ForwardLimit: 2, PortStart: 20000, PortEnd: 20002}
	require.NoError(t, s.db.Create(&grant).Error)
	rule := models.ForwardRule{
		TenantID: &tenant.ID, UserID: user.ID, TunnelID: tunnel.ID, Name: "grant-rule",
		Protocol: "tcp", ListenPort: 20001, RemoteHost: "127.0.0.1", RemotePort: 8081, Status: "active",
	}
	require.NoError(t, s.db.Create(&rule).Error)
	node := models.Node{DeviceGroupID: entry.ID, Name: "grant-node", UUID: "grant-node", TokenHash: "hash", DesiredRevision: 1}
	require.NoError(t, s.db.Create(&node).Error)
	router := testRouter(t, s)
	admin := adminToken(t, s)

	rec := jsonRequest(t, router, http.MethodPut, fmt.Sprintf("/api/v1/tenant-tunnel-grants/%d", grant.ID), map[string]any{
		"tenantId": tenant.ID, "tunnelId": tunnel.ID, "forwardLimit": 2, "portStart": 20002, "portEnd": 20002,
	}, admin)
	require.Equal(t, http.StatusBadRequest, rec.Code, rec.Body.String())
	require.Contains(t, rec.Body.String(), "existing rule")

	rec = jsonRequest(t, router, http.MethodPut, fmt.Sprintf("/api/v1/tenant-tunnel-grants/%d", grant.ID), map[string]any{
		"tenantId": tenant.ID, "tunnelId": tunnel.ID, "forwardLimit": 1, "portStart": 20001, "portEnd": 20002,
	}, admin)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	require.NoError(t, s.db.First(&node, node.ID).Error)
	require.Greater(t, node.DesiredRevision, int64(1))
}

func TestTenantTunnelGrantControlsPortRangeAndRuleCount(t *testing.T) {
	s := testServer(t)
	user, _, tunnel, _ := seedForwardFixture(t, s)
	tenant := models.Tenant{Name: "Port Tenant", Code: "port-tenant", Status: "active", ForwardLimit: 5}
	require.NoError(t, s.db.Create(&tenant).Error)
	user.TenantID = &tenant.ID
	user.ForwardLimit = 10
	require.NoError(t, s.db.Save(&user).Error)
	require.NoError(t, s.db.Where("user_id = ?", user.ID).Delete(&models.UserTunnelGrant{}).Error)
	rule := models.ForwardRule{
		UserID: user.ID, TunnelID: tunnel.ID, Name: "tenant-port", Protocol: "tcp",
		RemoteHost: "198.51.100.10", RemotePort: 443,
	}
	require.ErrorContains(t, s.prepareForwardRule(&rule, 0), "not authorized")
	require.NoError(t, s.db.Create(&models.TenantTunnelGrant{
		TenantID: tenant.ID, TunnelID: tunnel.ID, ForwardLimit: 1, PortStart: 20001, PortEnd: 20002,
	}).Error)
	rule.ListenPort = 20000
	require.ErrorContains(t, s.prepareForwardRule(&rule, 0), "authorized range")
	rule.ListenPort = 0
	require.NoError(t, s.prepareForwardRule(&rule, 0))
	require.Equal(t, 20001, rule.ListenPort)
	rule.TenantID = &tenant.ID
	rule.Status = "active"
	require.NoError(t, s.db.Create(&rule).Error)
	second := rule
	second.ID = 0
	second.Name = "tenant-port-2"
	second.ListenPort = 20002
	require.ErrorContains(t, s.prepareForwardRule(&second, 0), "tenant tunnel forward rule limit")
}

func TestUserTunnelGrantControlsVisibilityPortRangeAndRuleCount(t *testing.T) {
	s := testServer(t)
	user, entry, tunnel, _ := seedForwardFixture(t, s)
	user.ForwardLimit = 10
	require.NoError(t, s.db.Save(&user).Error)
	hiddenTunnel := models.Tunnel{
		Name: "hidden-user-tunnel", Mode: "single", EntryGroupID: entry.ID, Protocol: "direct",
		FlowAccounting: "single", EntryTrafficRatio: 1, ExitTrafficRatio: 1,
	}
	require.NoError(t, s.db.Create(&hiddenTunnel).Error)
	userToken, err := auth.GenerateToken(user.ID, user.Role, auth.TokenTypeAccess, "test-secret-for-unit-tests", time.Hour)
	require.NoError(t, err)
	router := testRouter(t, s)
	admin := adminToken(t, s)
	rec := jsonRequest(t, router, http.MethodGet, "/api/v1/tunnels?pageSize=20", nil, userToken)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	require.Contains(t, rec.Body.String(), tunnel.Name)
	require.NotContains(t, rec.Body.String(), hiddenTunnel.Name)

	var grant models.UserTunnelGrant
	require.NoError(t, s.db.Where("user_id = ? AND tunnel_id = ?", user.ID, tunnel.ID).First(&grant).Error)
	node := models.Node{DeviceGroupID: entry.ID, Name: "user-grant-node", UUID: "user-grant-node", TokenHash: "hash", DesiredRevision: 1}
	require.NoError(t, s.db.Create(&node).Error)
	rec = jsonRequest(t, router, http.MethodPut, fmt.Sprintf("/api/v1/user-tunnel-grants/%d", grant.ID), map[string]any{
		"userId": user.ID, "tunnelId": tunnel.ID, "forwardLimit": 1, "portStart": 20001, "portEnd": 20002,
	}, admin)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	require.NoError(t, s.db.First(&node, node.ID).Error)
	require.Greater(t, node.DesiredRevision, int64(1))

	rule := models.ForwardRule{
		UserID: user.ID, TunnelID: tunnel.ID, Name: "direct-user-rule", Protocol: "tcp",
		ListenPort: 20000, RemoteHost: "198.51.100.10", RemotePort: 443,
	}
	require.ErrorContains(t, s.prepareForwardRule(&rule, 0), "authorized range")
	rule.ListenPort = 0
	require.NoError(t, s.prepareForwardRule(&rule, 0))
	require.Equal(t, 20001, rule.ListenPort)
	rule.Status = "active"
	require.NoError(t, s.db.Create(&rule).Error)

	second := rule
	second.ID = 0
	second.Name = "direct-user-rule-2"
	second.ListenPort = 20002
	require.ErrorContains(t, s.prepareForwardRule(&second, 0), "user tunnel forward rule limit")

	rec = jsonRequest(t, router, http.MethodPut, fmt.Sprintf("/api/v1/user-tunnel-grants/%d", grant.ID), map[string]any{
		"userId": user.ID, "tunnelId": tunnel.ID, "forwardLimit": 1, "portStart": 20002, "portEnd": 20002,
	}, admin)
	require.Equal(t, http.StatusBadRequest, rec.Code, rec.Body.String())
	require.Contains(t, rec.Body.String(), "existing rule")
	rec = jsonRequest(t, router, http.MethodDelete, fmt.Sprintf("/api/v1/user-tunnel-grants/%d", grant.ID), nil, admin)
	require.Equal(t, http.StatusBadRequest, rec.Code, rec.Body.String())
}

func TestTenantlessUserCreationAndDirectGrant(t *testing.T) {
	s := testServer(t)
	entry := models.DeviceGroup{Name: "direct-entry", Role: "entry", PortStart: 24000, PortEnd: 24010, TrafficRatio: 1}
	require.NoError(t, s.db.Create(&entry).Error)
	tunnel := models.Tunnel{
		Name: "direct-line", Mode: "single", EntryGroupID: entry.ID, Protocol: "direct",
		FlowAccounting: "single", EntryTrafficRatio: 1, ExitTrafficRatio: 1,
	}
	require.NoError(t, s.db.Create(&tunnel).Error)
	router := testRouter(t, s)
	admin := adminToken(t, s)
	rec := jsonRequest(t, router, http.MethodPost, "/api/v1/users", map[string]any{
		"username": "direct-user", "password": "secret", "status": "active", "flowLimitBytes": 1024, "forwardLimit": 2,
	}, admin)
	require.Equal(t, http.StatusCreated, rec.Code, rec.Body.String())
	var user models.User
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &user))
	require.Equal(t, "user", user.Role)
	require.Nil(t, user.TenantID)

	userToken, err := auth.GenerateToken(user.ID, user.Role, auth.TokenTypeAccess, "test-secret-for-unit-tests", time.Hour)
	require.NoError(t, err)
	rec = jsonRequest(t, router, http.MethodGet, "/api/v1/tunnels?pageSize=20", nil, userToken)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	require.NotContains(t, rec.Body.String(), tunnel.Name)
	rec = jsonRequest(t, router, http.MethodPost, "/api/v1/user-tunnel-grants", map[string]any{
		"userId": user.ID, "tunnelId": tunnel.ID, "forwardLimit": 2, "portStart": 24001, "portEnd": 24005,
	}, admin)
	require.Equal(t, http.StatusCreated, rec.Code, rec.Body.String())
	rec = jsonRequest(t, router, http.MethodGet, "/api/v1/tunnels?pageSize=20", nil, userToken)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	require.Contains(t, rec.Body.String(), tunnel.Name)
}

func TestUserGrantProtectsTunnelAndIsCleanedWithUnusedUser(t *testing.T) {
	s := testServer(t)
	user, _, tunnel, _ := seedForwardFixture(t, s)
	router := testRouter(t, s)
	admin := adminToken(t, s)
	rec := jsonRequest(t, router, http.MethodDelete, fmt.Sprintf("/api/v1/tunnels/%d", tunnel.ID), nil, admin)
	require.Equal(t, http.StatusBadRequest, rec.Code, rec.Body.String())
	require.Contains(t, rec.Body.String(), "line grants")

	rec = jsonRequest(t, router, http.MethodDelete, fmt.Sprintf("/api/v1/users/%d", user.ID), nil, admin)
	require.Equal(t, http.StatusNoContent, rec.Code, rec.Body.String())
	var grants int64
	require.NoError(t, s.db.Model(&models.UserTunnelGrant{}).Where("user_id = ?", user.ID).Count(&grants).Error)
	require.Zero(t, grants)
	rec = jsonRequest(t, router, http.MethodDelete, fmt.Sprintf("/api/v1/tunnels/%d", tunnel.ID), nil, admin)
	require.Equal(t, http.StatusNoContent, rec.Code, rec.Body.String())
}

func TestLegacyTenantGrantFallbackForRegularUser(t *testing.T) {
	s := testServer(t)
	user, _, tunnel, _ := seedForwardFixture(t, s)
	require.NoError(t, s.db.Where("user_id = ?", user.ID).Delete(&models.UserTunnelGrant{}).Error)
	tenant := models.Tenant{Name: "Legacy Tenant", Code: "legacy-tenant", Status: "active"}
	require.NoError(t, s.db.Create(&tenant).Error)
	user.TenantID = &tenant.ID
	require.NoError(t, s.db.Save(&user).Error)
	require.NoError(t, s.db.Create(&models.TenantTunnelGrant{TenantID: tenant.ID, TunnelID: tunnel.ID}).Error)
	token, err := auth.GenerateToken(user.ID, user.Role, auth.TokenTypeAccess, "test-secret-for-unit-tests", time.Hour)
	require.NoError(t, err)
	rec := jsonRequest(t, testRouter(t, s), http.MethodGet, "/api/v1/tunnels?pageSize=20", nil, token)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	require.Contains(t, rec.Body.String(), tunnel.Name)
}

func TestDirectUserGrantTakesPrecedenceAndStopsLegacyRules(t *testing.T) {
	s := testServer(t)
	user, entry, legacyTunnel, _ := seedForwardFixture(t, s)
	require.NoError(t, s.db.Where("user_id = ?", user.ID).Delete(&models.UserTunnelGrant{}).Error)
	tenant := models.Tenant{Name: "Transition Tenant", Code: "transition-tenant", Status: "active"}
	require.NoError(t, s.db.Create(&tenant).Error)
	user.TenantID = &tenant.ID
	require.NoError(t, s.db.Save(&user).Error)
	require.NoError(t, s.db.Create(&models.TenantTunnelGrant{TenantID: tenant.ID, TunnelID: legacyTunnel.ID}).Error)
	legacyRule := models.ForwardRule{
		TenantID: &tenant.ID, UserID: user.ID, TunnelID: legacyTunnel.ID, Name: "legacy-rule",
		Protocol: "tcp", ListenPort: 20001, RemoteHost: "198.51.100.10", RemotePort: 443, Status: "active",
	}
	require.NoError(t, s.db.Create(&legacyRule).Error)
	active, _, err := s.activeAgentRules([]models.ForwardRule{legacyRule}, time.Now().UTC())
	require.NoError(t, err)
	require.Len(t, active, 1)

	directEntry := models.DeviceGroup{Name: "direct-transition-entry", Role: "entry", PortStart: 25000, PortEnd: 25010, TrafficRatio: 1}
	require.NoError(t, s.db.Create(&directEntry).Error)
	directTunnel := models.Tunnel{
		Name: "direct-transition-line", Mode: "single", EntryGroupID: directEntry.ID, Protocol: "direct",
		FlowAccounting: "single", EntryTrafficRatio: 1, ExitTrafficRatio: 1,
	}
	require.NoError(t, s.db.Create(&directTunnel).Error)
	legacyNode := models.Node{DeviceGroupID: entry.ID, Name: "legacy-transition-node", UUID: "legacy-transition-node", TokenHash: "hash", DesiredRevision: 1}
	require.NoError(t, s.db.Create(&legacyNode).Error)
	router := testRouter(t, s)
	rec := jsonRequest(t, router, http.MethodPost, "/api/v1/user-tunnel-grants", map[string]any{
		"userId": user.ID, "tunnelId": directTunnel.ID, "portStart": 25000, "portEnd": 25010,
	}, adminToken(t, s))
	require.Equal(t, http.StatusCreated, rec.Code, rec.Body.String())
	require.NoError(t, s.db.First(&legacyNode, legacyNode.ID).Error)
	require.Greater(t, legacyNode.DesiredRevision, int64(1))

	active, _, err = s.activeAgentRules([]models.ForwardRule{legacyRule}, time.Now().UTC())
	require.NoError(t, err)
	require.Empty(t, active)
	token, err := auth.GenerateToken(user.ID, user.Role, auth.TokenTypeAccess, "test-secret-for-unit-tests", time.Hour)
	require.NoError(t, err)
	rec = jsonRequest(t, router, http.MethodGet, "/api/v1/tunnels?pageSize=20", nil, token)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	var tunnelPage pageResponse[models.Tunnel]
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &tunnelPage))
	require.Len(t, tunnelPage.Items, 1)
	require.Equal(t, directTunnel.ID, tunnelPage.Items[0].ID)
}

func TestTenantAdministratorUserScope(t *testing.T) {
	s := testServer(t)
	tenantA := models.Tenant{Name: "Tenant A", Code: "tenant-a", Status: "active"}
	tenantB := models.Tenant{Name: "Tenant B", Code: "tenant-b", Status: "active"}
	require.NoError(t, s.db.Create(&tenantA).Error)
	require.NoError(t, s.db.Create(&tenantB).Error)
	hash, err := auth.HashPassword("secret")
	require.NoError(t, err)
	manager := models.User{TenantID: &tenantA.ID, Username: "tenant-manager", PasswordHash: hash, Role: "tenant_admin", Status: "active"}
	ownUser := models.User{TenantID: &tenantA.ID, Username: "tenant-user", PasswordHash: hash, Role: "user", Status: "active"}
	otherUser := models.User{TenantID: &tenantB.ID, Username: "other-user", PasswordHash: hash, Role: "user", Status: "active"}
	require.NoError(t, s.db.Create(&manager).Error)
	require.NoError(t, s.db.Create(&ownUser).Error)
	require.NoError(t, s.db.Create(&otherUser).Error)
	entry := models.DeviceGroup{Name: "tenant-entry", Role: "entry", PortStart: 20000, PortEnd: 21000, TrafficRatio: 1}
	require.NoError(t, s.db.Create(&entry).Error)
	authorizedTunnel := models.Tunnel{Name: "tenant-authorized", Mode: "single", EntryGroupID: entry.ID, Protocol: "direct", FlowAccounting: "single", EntryTrafficRatio: 1, ExitTrafficRatio: 1}
	hiddenTunnel := models.Tunnel{Name: "tenant-hidden", Mode: "single", EntryGroupID: entry.ID, Protocol: "direct", FlowAccounting: "single", EntryTrafficRatio: 1, ExitTrafficRatio: 1}
	require.NoError(t, s.db.Create(&authorizedTunnel).Error)
	require.NoError(t, s.db.Create(&hiddenTunnel).Error)
	require.NoError(t, s.db.Create(&models.TenantTunnelGrant{TenantID: tenantA.ID, TunnelID: authorizedTunnel.ID}).Error)
	token, err := auth.GenerateToken(manager.ID, manager.Role, auth.TokenTypeAccess, "test-secret-for-unit-tests", time.Hour)
	require.NoError(t, err)
	router := testRouter(t, s)
	rec := jsonRequest(t, router, http.MethodGet, "/api/v1/users?pageSize=20", nil, token)
	require.Equal(t, http.StatusOK, rec.Code)
	require.Contains(t, rec.Body.String(), "tenant-user")
	require.NotContains(t, rec.Body.String(), "other-user")
	rec = jsonRequest(t, router, http.MethodPost, "/api/v1/users", map[string]any{
		"username": "escalation", "password": "secret", "role": "admin", "status": "active",
	}, token)
	require.Equal(t, http.StatusBadRequest, rec.Code)
	rec = jsonRequest(t, router, http.MethodGet, "/api/v1/tenant/traffic", nil, token)
	require.Equal(t, http.StatusOK, rec.Code)
	require.Contains(t, rec.Body.String(), `"code":"tenant-a"`)
	rec = jsonRequest(t, router, http.MethodGet, "/api/v1/tunnels?pageSize=20", nil, token)
	require.Equal(t, http.StatusOK, rec.Code)
	require.Contains(t, rec.Body.String(), "tenant-authorized")
	require.NotContains(t, rec.Body.String(), "tenant-hidden")
}

func TestTenantUserLimitIsEnforcedInsideUserWrite(t *testing.T) {
	s := testServer(t)
	tenant := models.Tenant{Name: "Limited Tenant", Code: "limited-tenant", Status: "active", UserLimit: 1}
	require.NoError(t, s.db.Create(&tenant).Error)
	router := testRouter(t, s)
	admin := adminToken(t, s)
	for index, expected := range []int{http.StatusCreated, http.StatusBadRequest} {
		rec := jsonRequest(t, router, http.MethodPost, "/api/v1/users", map[string]any{
			"tenantId": tenant.ID, "username": fmt.Sprintf("limited-user-%d", index), "password": "secret", "role": "user", "status": "active",
		}, admin)
		require.Equal(t, expected, rec.Code, rec.Body.String())
	}
	var count int64
	require.NoError(t, s.db.Model(&models.User{}).Where("tenant_id = ?", tenant.ID).Count(&count).Error)
	require.Equal(t, int64(1), count)
}

func TestTenantAdministratorCannotOverrideRuleProtocolPolicy(t *testing.T) {
	s := testServer(t)
	user, _, tunnel, policy := seedForwardFixture(t, s)
	tenant := models.Tenant{Name: "Policy Tenant", Code: "policy-tenant", Status: "active"}
	require.NoError(t, s.db.Create(&tenant).Error)
	user.TenantID = &tenant.ID
	require.NoError(t, s.db.Save(&user).Error)
	require.NoError(t, s.db.Where("user_id = ?", user.ID).Delete(&models.UserTunnelGrant{}).Error)
	require.NoError(t, s.db.Create(&models.TenantTunnelGrant{TenantID: tenant.ID, TunnelID: tunnel.ID}).Error)
	hash, err := auth.HashPassword("secret")
	require.NoError(t, err)
	manager := models.User{TenantID: &tenant.ID, Username: "policy-manager", PasswordHash: hash, Role: "tenant_admin", Status: "active"}
	require.NoError(t, s.db.Create(&manager).Error)
	token, err := auth.GenerateToken(manager.ID, manager.Role, auth.TokenTypeAccess, "test-secret-for-unit-tests", time.Hour)
	require.NoError(t, err)
	router := testRouter(t, s)
	payload := map[string]any{
		"userId": user.ID, "tunnelId": tunnel.ID, "name": "managed-rule", "protocol": "tcp",
		"listenPort": 0, "remoteHost": "8.8.8.8", "remotePort": 53, "strategy": "least_conn",
	}
	payload["protocolPolicyId"] = policy.ID
	rec := jsonRequest(t, router, http.MethodPost, "/api/v1/forward-rules", payload, token)
	require.Equal(t, http.StatusBadRequest, rec.Code, rec.Body.String())
	require.Contains(t, rec.Body.String(), "only be managed by administrators")

	delete(payload, "protocolPolicyId")
	rec = jsonRequest(t, router, http.MethodPost, "/api/v1/forward-rules", payload, token)
	require.Equal(t, http.StatusCreated, rec.Code, rec.Body.String())
	var rule models.ForwardRule
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &rule))
	require.NoError(t, s.db.Model(&rule).Update("protocol_policy_id", policy.ID).Error)
	payload["listenPort"] = rule.ListenPort
	rec = jsonRequest(t, router, http.MethodPut, fmt.Sprintf("/api/v1/forward-rules/%d", rule.ID), payload, token)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	require.NoError(t, s.db.First(&rule, rule.ID).Error)
	require.NotNil(t, rule.ProtocolPolicyID)
	require.Equal(t, policy.ID, *rule.ProtocolPolicyID)

	payload["protocolPolicyId"] = policy.ID
	rec = jsonRequest(t, router, http.MethodPost, "/api/v1/forward-rules/batch/preview", map[string]any{"rules": []any{payload}}, token)
	require.Equal(t, http.StatusBadRequest, rec.Code, rec.Body.String())
}

func TestForwardRuleBatchPreviewAndCreateAreAtomic(t *testing.T) {
	s := testServer(t)
	user, _, tunnel, _ := seedForwardFixture(t, s)
	user.ForwardLimit = 10
	require.NoError(t, s.db.Save(&user).Error)
	token := adminToken(t, s)
	router := testRouter(t, s)
	rules := []map[string]any{
		{"userId": user.ID, "tunnelId": tunnel.ID, "name": "batch-a", "protocol": "tcp", "listenPort": 0, "remoteHost": "127.0.0.1", "remotePort": 8081},
		{"userId": user.ID, "tunnelId": tunnel.ID, "name": "batch-b", "protocol": "tcp", "listenPort": 0, "remoteHost": "127.0.0.1", "remotePort": 8082},
	}
	rec := jsonRequest(t, router, http.MethodPost, "/api/v1/forward-rules/batch/preview", map[string]any{"rules": rules}, token)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	var preview struct {
		Items []models.ForwardRule `json:"items"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &preview))
	require.Len(t, preview.Items, 2)
	require.NotEqual(t, preview.Items[0].ListenPort, preview.Items[1].ListenPort)
	var count int64
	require.NoError(t, s.db.Model(&models.ForwardRule{}).Where("name LIKE ?", "batch-%").Count(&count).Error)
	require.Zero(t, count)

	rec = jsonRequest(t, router, http.MethodPost, "/api/v1/forward-rules/batch", map[string]any{"rules": rules}, token)
	require.Equal(t, http.StatusCreated, rec.Code, rec.Body.String())
	var created struct {
		Items []models.ForwardRule `json:"items"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &created))
	require.Len(t, created.Items, 2)
	require.NotEqual(t, created.Items[0].ListenPort, created.Items[1].ListenPort)
	var leases int64
	require.NoError(t, s.db.Model(&models.PortLease{}).Where("rule_id IN ?", []uint{created.Items[0].ID, created.Items[1].ID}).Count(&leases).Error)
	require.Equal(t, int64(2), leases)
}

func ptrTime(value time.Time) *time.Time {
	return &value
}
