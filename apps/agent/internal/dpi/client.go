package dpi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"
)

type Client struct {
	endpoint string
	http     *http.Client
}

type ClassifyRequest struct {
	Network         string   `json:"network"`
	Payload         []byte   `json:"payload"`
	BuiltinProtocol string   `json:"builtinProtocol,omitempty"`
	Host            string   `json:"host,omitempty"`
	ALPN            []string `json:"alpn,omitempty"`
	RuleID          uint     `json:"ruleId,omitempty"`
}

type ClassifyResponse struct {
	Protocol   string   `json:"protocol"`
	Category   string   `json:"category"`
	Confidence int      `json:"confidence"`
	RiskScore  int      `json:"riskScore"`
	RiskLevel  string   `json:"riskLevel"`
	Tags       []string `json:"tags,omitempty"`
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
		return ClassifyResponse{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return ClassifyResponse{}, fmt.Errorf("dpi classify returned %s", resp.Status)
	}
	var out ClassifyResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return ClassifyResponse{}, err
	}
	return out, nil
}
