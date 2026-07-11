package dpi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

type Client struct {
	endpoint string
	http     *http.Client
	mu       sync.RWMutex
	status   Status
}

type ClassifyRequest struct {
	Network         string   `json:"network"`
	Payload         []byte   `json:"payload"`
	BuiltinProtocol string   `json:"builtinProtocol,omitempty"`
	Host            string   `json:"host,omitempty"`
	ALPN            []string `json:"alpn,omitempty"`
	RuleID          uint     `json:"ruleId,omitempty"`
	FlowID          string   `json:"flowId,omitempty"`
	Direction       string   `json:"direction,omitempty"`
	SourceIP        string   `json:"sourceIp,omitempty"`
	DestinationIP   string   `json:"destinationIp,omitempty"`
	SourcePort      int      `json:"sourcePort,omitempty"`
	DestinationPort int      `json:"destinationPort,omitempty"`
	TimestampMs     int64    `json:"timestampMs,omitempty"`
}

type ClassifyResponse struct {
	Protocol   string   `json:"protocol"`
	Category   string   `json:"category"`
	Confidence int      `json:"confidence"`
	RiskScore  int      `json:"riskScore"`
	RiskLevel  string   `json:"riskLevel"`
	Tags       []string `json:"tags,omitempty"`
	Engine     string   `json:"engine"`
	Final      bool     `json:"final"`
	Packets    int      `json:"packets"`
}

type Status struct {
	Healthy       bool           `json:"healthy"`
	Engine        string         `json:"engine,omitempty"`
	EngineVersion string         `json:"engineVersion,omitempty"`
	Version       string         `json:"version,omitempty"`
	LastError     string         `json:"lastError,omitempty"`
	LastCheckedAt time.Time      `json:"lastCheckedAt,omitempty"`
	Stats         map[string]any `json:"stats,omitempty"`
}

func New(address string, timeout time.Duration) *Client {
	address = strings.TrimSpace(address)
	if address == "" {
		return nil
	}
	if timeout <= 0 {
		timeout = 300 * time.Millisecond
	}
	client := &Client{endpoint: address, http: &http.Client{Timeout: timeout}}
	if strings.HasPrefix(address, "unix:") {
		socketPath := strings.TrimPrefix(address, "unix:")
		client.endpoint = "http://dusheng-dpi"
		client.http.Transport = &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, "unix", socketPath)
			},
		}
	}
	return client
}

func (c *Client) Enabled() bool {
	return c != nil && strings.TrimSpace(c.endpoint) != ""
}

func (c *Client) Classify(ctx context.Context, req ClassifyRequest) (ClassifyResponse, error) {
	if !c.Enabled() {
		return ClassifyResponse{}, errors.New("dpi client is disabled")
	}
	body, err := json.Marshal(req)
	if err != nil {
		return ClassifyResponse{}, err
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(c.endpoint, "/")+"/classify", bytes.NewReader(body))
	if err != nil {
		return ClassifyResponse{}, err
	}
	httpReq.Header.Set("Accept", "application/json")
	httpReq.Header.Set("Content-Type", "application/json")
	resp, err := c.http.Do(httpReq)
	if err != nil {
		c.setError(err)
		return ClassifyResponse{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		err := fmt.Errorf("dpi classify returned %s", resp.Status)
		c.setError(err)
		return ClassifyResponse{}, err
	}
	var out ClassifyResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		c.setError(err)
		return ClassifyResponse{}, err
	}
	c.mu.Lock()
	c.status.Healthy = true
	c.status.Engine = out.Engine
	c.status.LastError = ""
	c.status.LastCheckedAt = time.Now().UTC()
	c.mu.Unlock()
	return out, nil
}

func (c *Client) Probe(ctx context.Context) error {
	if !c.Enabled() {
		return errors.New("dpi client is disabled")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(c.endpoint, "/")+"/healthz", nil)
	if err != nil {
		return err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		c.setError(err)
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		err := fmt.Errorf("dpi health returned %s", resp.Status)
		c.setError(err)
		return err
	}
	var health struct {
		Version       string         `json:"version"`
		Engine        string         `json:"engine"`
		EngineVersion string         `json:"engineVersion"`
		Stats         map[string]any `json:"stats"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&health); err != nil {
		c.setError(err)
		return err
	}
	c.mu.Lock()
	c.status = Status{Healthy: true, Engine: health.Engine, EngineVersion: health.EngineVersion, Version: health.Version, Stats: health.Stats, LastCheckedAt: time.Now().UTC()}
	c.mu.Unlock()
	return nil
}

func (c *Client) CloseFlow(ctx context.Context, flowID string) error {
	if !c.Enabled() || strings.TrimSpace(flowID) == "" {
		return nil
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, strings.TrimRight(c.endpoint, "/")+"/flows/"+url.PathEscape(flowID), nil)
	if err != nil {
		return err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		c.setError(err)
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("dpi close flow returned %s", resp.Status)
	}
	return nil
}

func (c *Client) Status() Status {
	if c == nil {
		return Status{}
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.status
}

func (c *Client) setError(err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.status.Healthy = false
	c.status.LastError = err.Error()
	c.status.LastCheckedAt = time.Now().UTC()
}
