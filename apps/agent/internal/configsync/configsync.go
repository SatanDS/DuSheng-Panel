package configsync

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"dusheng-panel/apps/agent/internal/client"
)

const (
	renderedFile       = "rendered-gost.json"
	defaultConfigLease = 2 * time.Minute
)

type Supervisor interface {
	Apply(ctx context.Context, configPath string) error
	Running() bool
}

type Runtime interface {
	Apply(ctx context.Context, cfg client.AgentConfig) error
	Running() bool
	Status() map[string]any
	Stop(ctx context.Context) error
}

type statusReporter interface {
	Status() string
}

type Syncer struct {
	api      *client.Client
	renderer *Renderer
	runtime  Runtime
	logger   *log.Logger

	mu              sync.RWMutex
	appliedRevision int64
	hasSynced       bool
	leaseValidUntil time.Time
	failClosed      bool
}

func New(api *client.Client, dataDir string, runtime Runtime, logger *log.Logger) *Syncer {
	if logger == nil {
		logger = log.Default()
	}
	return &Syncer{
		api:      api,
		renderer: NewRenderer(dataDir),
		runtime:  runtime,
		logger:   logger,
	}
}

func (s *Syncer) SyncOnce(ctx context.Context) error {
	cfg, err := s.api.GetConfig(ctx)
	if err != nil {
		s.failClosedIfLeaseExpired(ctx)
		return err
	}

	result, err := s.renderer.Render(cfg)
	if err != nil {
		return err
	}

	if result.Changed {
		s.logger.Printf("rendered compatibility gost config path=%s revision=%d services=%d", result.Path, cfg.Revision, result.ServiceCount)
	}
	if s.runtime != nil {
		if err := s.runtime.Apply(ctx, cfg); err != nil {
			return err
		}
	}

	s.mu.Lock()
	s.appliedRevision = cfg.Revision
	s.hasSynced = true
	s.failClosed = false
	s.leaseValidUntil = cfg.ValidUntil
	if s.leaseValidUntil.IsZero() {
		s.leaseValidUntil = time.Now().Add(defaultConfigLease)
	}
	s.mu.Unlock()

	return nil
}

func (s *Syncer) AppliedRevision() int64 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.appliedRevision
}

func (s *Syncer) RuntimeActive() bool {
	if s.runtime == nil {
		return false
	}
	return s.runtime.Running()
}

func (s *Syncer) RuntimeStatus() map[string]any {
	if s.runtime == nil {
		return map[string]any{"running": false}
	}
	status := s.runtime.Status()
	s.mu.RLock()
	status["configLeaseValidUntil"] = s.leaseValidUntil
	status["configFailClosed"] = s.failClosed
	s.mu.RUnlock()
	return status
}

func (s *Syncer) failClosedIfLeaseExpired(ctx context.Context) {
	s.mu.Lock()
	expired := s.hasSynced && !s.leaseValidUntil.IsZero() && time.Now().After(s.leaseValidUntil) && !s.failClosed
	validUntil := s.leaseValidUntil
	if expired {
		s.failClosed = true
	}
	s.mu.Unlock()
	if !expired || s.runtime == nil {
		return
	}
	s.logger.Printf("config lease expired at %s; stopping runtime listeners until config sync recovers", validUntil.Format(time.RFC3339))
	stopCfg := client.AgentConfig{
		Revision:    s.AppliedRevision(),
		GeneratedAt: time.Now().UTC(),
		ValidUntil:  time.Now().UTC(),
	}
	if err := s.runtime.Apply(ctx, stopCfg); err != nil {
		s.logger.Printf("runtime fail-closed apply failed: %v", err)
	}
}

type Renderer struct {
	dataDir string
}

func NewRenderer(dataDir string) *Renderer {
	return &Renderer{dataDir: dataDir}
}

type RenderResult struct {
	Path         string
	Changed      bool
	ServiceCount int
}

type GostConfig struct {
	Services []GostService    `json:"services"`
	Metadata GostMetadata     `json:"metadata"`
	Limits   []RenderedLimit  `json:"limits,omitempty"`
	Policies []RenderedPolicy `json:"policies,omitempty"`
}

type GostMetadata struct {
	Revision    int64     `json:"revision"`
	GeneratedAt time.Time `json:"generatedAt"`
	NodeID      uint      `json:"nodeId,omitempty"`
	NodeName    string    `json:"nodeName,omitempty"`
	GroupID     uint      `json:"groupId,omitempty"`
	GroupName   string    `json:"groupName,omitempty"`
	Source      string    `json:"source"`
}

type GostService struct {
	Name      string         `json:"name"`
	Addr      string         `json:"addr"`
	Handler   GostTypedBlock `json:"handler"`
	Listener  GostTypedBlock `json:"listener"`
	Forwarder GostForwarder  `json:"forwarder"`
	Metadata  ServiceMeta    `json:"metadata"`
}

type GostTypedBlock struct {
	Type string `json:"type"`
}

type GostForwarder struct {
	Nodes []GostNode `json:"nodes"`
}

type GostNode struct {
	Name string `json:"name"`
	Addr string `json:"addr"`
}

type ServiceMeta struct {
	RuleID           uint   `json:"ruleId"`
	TunnelID         uint   `json:"tunnelId"`
	UserID           uint   `json:"userId"`
	Strategy         string `json:"strategy,omitempty"`
	ProtocolPolicyID *uint  `json:"protocolPolicyId,omitempty"`
}

type RenderedLimit struct {
	ID          uint   `json:"id"`
	Name        string `json:"name"`
	UserID      *uint  `json:"userId,omitempty"`
	TunnelID    *uint  `json:"tunnelId,omitempty"`
	RuleID      *uint  `json:"ruleId,omitempty"`
	UploadBps   int64  `json:"uploadBps,omitempty"`
	DownloadBps int64  `json:"downloadBps,omitempty"`
	MaxConns    int    `json:"maxConns,omitempty"`
	MaxIPs      int    `json:"maxIps,omitempty"`
}

type RenderedPolicy struct {
	ID                      uint   `json:"id"`
	Name                    string `json:"name"`
	Template                string `json:"template"`
	Purpose                 string `json:"purpose"`
	InspectionLevel         string `json:"inspectionLevel"`
	Mode                    string `json:"mode"`
	BlockTLS                bool   `json:"blockTls"`
	BlockQUIC               bool   `json:"blockQuic"`
	AllowPlainTCPOnly       bool   `json:"allowPlainTcpOnly"`
	AllowHTTPOnly           bool   `json:"allowHttpOnly"`
	BlockProxyLike          bool   `json:"blockProxyLike"`
	BlockEncryptedTunnel    bool   `json:"blockEncryptedTunnel"`
	ObservationMinutes      int    `json:"observationMinutes"`
	AuthorizedProtocols     string `json:"authorizedProtocols"`
	BlockedProtocolGroups   string `json:"blockedProtocolGroups"`
	HostAllowlist           string `json:"hostAllowlist"`
	HostBlocklist           string `json:"hostBlocklist"`
	SNIAllowlist            string `json:"sniAllowlist"`
	SNIBlocklist            string `json:"sniBlocklist"`
	ALPNAllowlist           string `json:"alpnAllowlist"`
	ALPNBlocklist           string `json:"alpnBlocklist"`
	TLSNoSNIAction          string `json:"tlsNoSniAction"`
	QUICAction              string `json:"quicAction"`
	SSHAction               string `json:"sshAction"`
	UnknownTCPAction        string `json:"unknownTcpAction"`
	UnknownUDPAction        string `json:"unknownUdpAction"`
	NDPILowConfidenceAction string `json:"ndpiLowConfidenceAction"`
	DPITimeoutMs            int    `json:"dpiTimeoutMs"`
}

func (r *Renderer) Render(cfg client.AgentConfig) (RenderResult, error) {
	if err := os.MkdirAll(r.dataDir, 0o755); err != nil {
		return RenderResult{}, err
	}

	gostCfg := buildGostConfig(cfg)
	content, err := json.MarshalIndent(gostCfg, "", "  ")
	if err != nil {
		return RenderResult{}, err
	}
	content = append(content, '\n')

	path := filepath.Join(r.dataDir, renderedFile)
	existing, err := os.ReadFile(path)
	if err == nil && bytes.Equal(existing, content) {
		return RenderResult{Path: path, Changed: false, ServiceCount: len(gostCfg.Services)}, nil
	}
	if err != nil && !os.IsNotExist(err) {
		return RenderResult{}, err
	}
	if err := os.WriteFile(path, content, 0o644); err != nil {
		return RenderResult{}, err
	}
	return RenderResult{Path: path, Changed: true, ServiceCount: len(gostCfg.Services)}, nil
}

func buildGostConfig(cfg client.AgentConfig) GostConfig {
	rules := append([]client.ForwardRule(nil), cfg.ForwardRules...)
	sort.SliceStable(rules, func(i, j int) bool {
		if rules[i].ListenPort == rules[j].ListenPort {
			return rules[i].ID < rules[j].ID
		}
		return rules[i].ListenPort < rules[j].ListenPort
	})

	services := make([]GostService, 0, len(rules))
	for _, rule := range rules {
		if shouldSkipRule(rule) {
			continue
		}
		proto := normalizeProtocol(rule.Protocol)
		services = append(services, GostService{
			Name:     serviceName(rule),
			Addr:     fmt.Sprintf(":%d", rule.ListenPort),
			Handler:  GostTypedBlock{Type: proto},
			Listener: GostTypedBlock{Type: proto},
			Forwarder: GostForwarder{Nodes: []GostNode{{
				Name: "target",
				Addr: net.JoinHostPort(rule.RemoteHost, fmt.Sprint(rule.RemotePort)),
			}}},
			Metadata: ServiceMeta{
				RuleID:           rule.ID,
				TunnelID:         rule.TunnelID,
				UserID:           rule.UserID,
				Strategy:         rule.Strategy,
				ProtocolPolicyID: rule.ProtocolPolicyID,
			},
		})
	}

	policies := make([]RenderedPolicy, 0, len(cfg.ProtocolPolicies))
	for _, policy := range cfg.ProtocolPolicies {
		policies = append(policies, RenderedPolicy{
			ID:                      policy.ID,
			Name:                    policy.Name,
			Template:                policy.Template,
			Purpose:                 policy.Purpose,
			InspectionLevel:         policy.InspectionLevel,
			Mode:                    policy.Mode,
			BlockTLS:                policy.BlockTLS,
			BlockQUIC:               policy.BlockQUIC,
			AllowPlainTCPOnly:       policy.AllowPlainTCPOnly,
			AllowHTTPOnly:           policy.AllowHTTPOnly,
			BlockProxyLike:          policy.BlockProxyLike,
			BlockEncryptedTunnel:    policy.BlockEncryptedTunnel,
			ObservationMinutes:      policy.ObservationMinutes,
			AuthorizedProtocols:     policy.AuthorizedProtocols,
			BlockedProtocolGroups:   policy.BlockedProtocolGroups,
			HostAllowlist:           policy.HostAllowlist,
			HostBlocklist:           policy.HostBlocklist,
			SNIAllowlist:            policy.SNIAllowlist,
			SNIBlocklist:            policy.SNIBlocklist,
			ALPNAllowlist:           policy.ALPNAllowlist,
			ALPNBlocklist:           policy.ALPNBlocklist,
			TLSNoSNIAction:          policy.TLSNoSNIAction,
			QUICAction:              policy.QUICAction,
			SSHAction:               policy.SSHAction,
			UnknownTCPAction:        policy.UnknownTCPAction,
			UnknownUDPAction:        policy.UnknownUDPAction,
			NDPILowConfidenceAction: policy.NDPILowConfidenceAction,
			DPITimeoutMs:            policy.DPITimeoutMs,
		})
	}

	limits := make([]RenderedLimit, 0, len(cfg.SpeedLimits))
	for _, limit := range cfg.SpeedLimits {
		limits = append(limits, RenderedLimit{
			ID:          limit.ID,
			Name:        limit.Name,
			UserID:      limit.UserID,
			TunnelID:    limit.TunnelID,
			RuleID:      limit.RuleID,
			UploadBps:   limit.UploadBps,
			DownloadBps: limit.DownloadBps,
			MaxConns:    limit.MaxConns,
			MaxIPs:      limit.MaxIPs,
		})
	}

	generatedAt := cfg.GeneratedAt
	if generatedAt.IsZero() {
		generatedAt = time.Now().UTC()
	}

	return GostConfig{
		Services: services,
		Metadata: GostMetadata{
			Revision:    cfg.Revision,
			GeneratedAt: generatedAt,
			NodeID:      cfg.Node.ID,
			NodeName:    cfg.Node.Name,
			GroupID:     cfg.DeviceGroup.ID,
			GroupName:   cfg.DeviceGroup.Name,
			Source:      "dusheng-agent",
		},
		Limits:   limits,
		Policies: policies,
	}
}

func shouldSkipRule(rule client.ForwardRule) bool {
	status := strings.ToLower(strings.TrimSpace(rule.Status))
	if status == "paused" || status == "disabled" || status == "deleted" {
		return true
	}
	return rule.ListenPort <= 0 || rule.RemoteHost == "" || rule.RemotePort <= 0
}

func normalizeProtocol(protocol string) string {
	switch strings.ToLower(strings.TrimSpace(protocol)) {
	case "udp":
		return "udp"
	default:
		return "tcp"
	}
}

func serviceName(rule client.ForwardRule) string {
	name := strings.TrimSpace(rule.Name)
	if name == "" {
		name = "forward"
	}
	return fmt.Sprintf("rule-%d-%s", rule.ID, sanitizeName(name))
}

func sanitizeName(value string) string {
	value = strings.ToLower(value)
	var b strings.Builder
	lastDash := false
	for _, r := range value {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
			lastDash = false
			continue
		}
		if !lastDash {
			b.WriteByte('-')
			lastDash = true
		}
	}
	result := strings.Trim(b.String(), "-")
	if result == "" {
		return "forward"
	}
	return result
}
