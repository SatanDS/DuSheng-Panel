package client

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const credentialsFile = "node-credentials.json"

type Client struct {
	baseURL   string
	nodeToken string
	http      *http.Client
}

func New(baseURL, nodeToken string) *Client {
	return &Client{
		baseURL:   strings.TrimRight(strings.TrimSpace(baseURL), "/"),
		nodeToken: strings.TrimSpace(nodeToken),
		http: &http.Client{
			Timeout: 15 * time.Second,
		},
	}
}

func (c *Client) SetNodeToken(token string) {
	c.nodeToken = strings.TrimSpace(token)
}

type Credentials struct {
	NodeID    uint   `json:"nodeId"`
	NodeToken string `json:"nodeToken"`
	UUID      string `json:"uuid"`
}

type RegisterRequest struct {
	InstallToken string `json:"installToken"`
	Name         string `json:"name,omitempty"`
	UUID         string `json:"uuid,omitempty"`
	Version      string `json:"version,omitempty"`
	PublicIP     string `json:"publicIp,omitempty"`
	ConnectHost  string `json:"connectHost,omitempty"`
}

type HeartbeatRequest struct {
	Version         string         `json:"version"`
	PublicIP        string         `json:"publicIp,omitempty"`
	ConnectHost     string         `json:"connectHost,omitempty"`
	AppliedRevision int64          `json:"appliedRevision"`
	System          map[string]any `json:"system"`
}

type HeartbeatResponse struct {
	DesiredRevision int64     `json:"desiredRevision"`
	ServerTime      time.Time `json:"serverTime"`
}

type AgentConfig struct {
	Node             Node             `json:"node"`
	DeviceGroup      DeviceGroup      `json:"deviceGroup"`
	Tunnels          []Tunnel         `json:"tunnels"`
	ForwardRules     []ForwardRule    `json:"forwardRules"`
	ProtocolPolicies []ProtocolPolicy `json:"protocolPolicies"`
	SpeedLimits      []SpeedLimit     `json:"speedLimits"`
	Revision         int64            `json:"revision"`
	GeneratedAt      time.Time        `json:"generatedAt"`
}

type Node struct {
	ID              uint   `json:"id"`
	DeviceGroupID   uint   `json:"deviceGroupId"`
	Name            string `json:"name"`
	UUID            string `json:"uuid"`
	Status          string `json:"status"`
	Version         string `json:"version"`
	PublicIP        string `json:"publicIp"`
	ConnectHost     string `json:"connectHost"`
	AppliedRevision int64  `json:"appliedRevision"`
	DesiredRevision int64  `json:"desiredRevision"`
}

type DeviceGroup struct {
	ID               uint    `json:"id"`
	Name             string  `json:"name"`
	Role             string  `json:"role"`
	BindIPs          string  `json:"bindIPs"`
	PortStart        int     `json:"portStart"`
	PortEnd          int     `json:"portEnd"`
	TrafficRatio     float64 `json:"trafficRatio"`
	ProtocolPolicyID *uint   `json:"protocolPolicyId"`
	FailoverGroupID  *uint   `json:"failoverGroupId"`
	AdvancedJSON     string  `json:"advancedJson"`
}

type Tunnel struct {
	ID                uint    `json:"id"`
	Name              string  `json:"name"`
	Mode              string  `json:"mode"`
	EntryGroupID      uint    `json:"entryGroupId"`
	ExitGroupID       *uint   `json:"exitGroupId"`
	Protocol          string  `json:"protocol"`
	FlowAccounting    string  `json:"flowAccounting"`
	EntryTrafficRatio float64 `json:"entryTrafficRatio"`
	ExitTrafficRatio  float64 `json:"exitTrafficRatio"`
	ProtocolPolicyID  *uint   `json:"protocolPolicyId"`
	AdvancedJSON      string  `json:"advancedJson"`
}

type ForwardRule struct {
	ID               uint   `json:"id"`
	UserID           uint   `json:"userId"`
	TunnelID         uint   `json:"tunnelId"`
	Name             string `json:"name"`
	Protocol         string `json:"protocol"`
	ListenPort       int    `json:"listenPort"`
	RemoteHost       string `json:"remoteHost"`
	RemotePort       int    `json:"remotePort"`
	Status           string `json:"status"`
	Strategy         string `json:"strategy"`
	ProtocolPolicyID *uint  `json:"protocolPolicyId"`
	InBytes          int64  `json:"inBytes"`
	OutBytes         int64  `json:"outBytes"`
	Revision         int64  `json:"revision"`
	LastSyncError    string `json:"lastSyncError"`
	ViolationCount   int    `json:"violationCount"`
}

type ProtocolPolicy struct {
	ID                   uint   `json:"id"`
	Name                 string `json:"name"`
	Template             string `json:"template"`
	Mode                 string `json:"mode"`
	BlockTLS             bool   `json:"blockTls"`
	BlockQUIC            bool   `json:"blockQuic"`
	AllowPlainTCPOnly    bool   `json:"allowPlainTcpOnly"`
	AllowHTTPOnly        bool   `json:"allowHttpOnly"`
	BlockProxyLike       bool   `json:"blockProxyLike"`
	BlockEncryptedTunnel bool   `json:"blockEncryptedTunnel"`
	Description          string `json:"description"`
}

type SpeedLimit struct {
	ID          uint   `json:"id"`
	Name        string `json:"name"`
	UserID      *uint  `json:"userId"`
	TunnelID    *uint  `json:"tunnelId"`
	RuleID      *uint  `json:"ruleId"`
	UploadBps   int64  `json:"uploadBps"`
	DownloadBps int64  `json:"downloadBps"`
	MaxConns    int    `json:"maxConns"`
	MaxIPs      int    `json:"maxIps"`
}

type TrafficSample struct {
	RuleID   uint  `json:"ruleId"`
	InBytes  int64 `json:"inBytes,omitempty"`
	OutBytes int64 `json:"outBytes,omitempty"`
}

type TrafficReport struct {
	Samples []TrafficSample `json:"samples"`
}

type AcceptedResponse struct {
	Accepted int `json:"accepted"`
}

type ViolationReport struct {
	RuleID   uint   `json:"ruleId"`
	PolicyID uint   `json:"policyId"`
	Protocol string `json:"protocol"`
	SourceIP string `json:"sourceIp,omitempty"`
	Action   string `json:"action,omitempty"`
	Detail   string `json:"detail,omitempty"`
}

type ProtocolViolation struct {
	ID         uint      `json:"id"`
	RuleID     uint      `json:"ruleId"`
	NodeID     uint      `json:"nodeId"`
	PolicyID   uint      `json:"policyId"`
	Protocol   string    `json:"protocol"`
	SourceIP   string    `json:"sourceIp"`
	Action     string    `json:"action"`
	Detail     string    `json:"detail"`
	OccurredAt time.Time `json:"occurredAt"`
}

func LoadCredentials(dataDir string) (Credentials, bool, error) {
	path := filepath.Join(dataDir, credentialsFile)
	content, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return Credentials{}, false, nil
		}
		return Credentials{}, false, err
	}

	var creds Credentials
	if err := json.Unmarshal(content, &creds); err != nil {
		return Credentials{}, false, err
	}
	return creds, creds.NodeToken != "", nil
}

func SaveCredentials(dataDir string, creds Credentials) error {
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		return err
	}
	content, err := json.MarshalIndent(creds, "", "  ")
	if err != nil {
		return err
	}
	content = append(content, '\n')
	return os.WriteFile(filepath.Join(dataDir, credentialsFile), content, 0o600)
}

func (c *Client) Register(ctx context.Context, req RegisterRequest) (Credentials, error) {
	var resp Credentials
	if err := c.doJSON(ctx, http.MethodPost, "/agent/register", req, &resp, false); err != nil {
		return Credentials{}, err
	}
	return resp, nil
}

func (c *Client) Heartbeat(ctx context.Context, req HeartbeatRequest) (HeartbeatResponse, error) {
	var resp HeartbeatResponse
	if err := c.doJSON(ctx, http.MethodPost, "/agent/heartbeat", req, &resp, true); err != nil {
		return HeartbeatResponse{}, err
	}
	return resp, nil
}

func (c *Client) GetConfig(ctx context.Context) (AgentConfig, error) {
	var resp AgentConfig
	if err := c.doJSON(ctx, http.MethodGet, "/agent/config", nil, &resp, true); err != nil {
		return AgentConfig{}, err
	}
	return resp, nil
}

func (c *Client) ReportTraffic(ctx context.Context, req TrafficReport) (AcceptedResponse, error) {
	var resp AcceptedResponse
	if err := c.doJSON(ctx, http.MethodPost, "/agent/traffic", req, &resp, true); err != nil {
		return AcceptedResponse{}, err
	}
	return resp, nil
}

func (c *Client) ReportViolation(ctx context.Context, req ViolationReport) (ProtocolViolation, error) {
	var resp ProtocolViolation
	if err := c.doJSON(ctx, http.MethodPost, "/agent/violations", req, &resp, true); err != nil {
		return ProtocolViolation{}, err
	}
	return resp, nil
}

func (c *Client) doJSON(ctx context.Context, method, path string, input, output any, authenticated bool) error {
	if c.baseURL == "" {
		return fmt.Errorf("base URL is empty")
	}
	if authenticated && c.nodeToken == "" {
		return fmt.Errorf("node token is empty")
	}

	var body io.Reader
	if input != nil {
		content, err := json.Marshal(input)
		if err != nil {
			return err
		}
		body = bytes.NewReader(content)
	}

	req, err := http.NewRequestWithContext(ctx, method, c.endpoint(path), body)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	if input != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if authenticated {
		req.Header.Set("Authorization", "Bearer "+c.nodeToken)
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		content, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("%s %s returned %s: %s", method, path, resp.Status, strings.TrimSpace(string(content)))
	}
	if output == nil {
		io.Copy(io.Discard, resp.Body)
		return nil
	}
	return json.NewDecoder(resp.Body).Decode(output)
}

func (c *Client) endpoint(path string) string {
	base := strings.TrimRight(c.baseURL, "/")
	if strings.HasSuffix(base, "/api/v1") {
		return base + path
	}
	return base + "/api/v1" + path
}
