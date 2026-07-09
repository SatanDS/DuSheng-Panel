package app

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"dusheng-panel/apps/api/internal/auth"
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
