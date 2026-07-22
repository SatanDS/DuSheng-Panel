package client

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestAgentIdentityRequestsOnlyContainAgentOwnedFields(t *testing.T) {
	tests := []struct {
		name    string
		request any
		allowed map[string]bool
	}{
		{
			name: "register",
			request: RegisterRequest{
				InstallToken: "install-token",
				Name:         "node-a",
				UUID:         "node-uuid",
				Version:      "v1.0.0",
				Capabilities: []string{"tcp_runtime"},
			},
			allowed: map[string]bool{
				"installToken": true,
				"name":         true,
				"uuid":         true,
				"version":      true,
				"capabilities": true,
			},
		},
		{
			name: "heartbeat",
			request: HeartbeatRequest{
				Version:         "v1.0.0",
				AppliedRevision: 42,
				System:          map[string]any{"hostname": "node-a"},
				Capabilities:    []string{"tcp_runtime"},
			},
			allowed: map[string]bool{
				"version":         true,
				"appliedRevision": true,
				"system":          true,
				"capabilities":    true,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			payload, err := json.Marshal(tt.request)
			if err != nil {
				t.Fatalf("marshal request: %v", err)
			}

			var fields map[string]json.RawMessage
			if err := json.Unmarshal(payload, &fields); err != nil {
				t.Fatalf("unmarshal request: %v", err)
			}
			for field := range fields {
				if !tt.allowed[field] {
					t.Errorf("request contains server-owned field %q", field)
				}
			}
		})
	}
}

func TestGetConfigBypassesIntermediateCaches(t *testing.T) {
	var requestID string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.URL.Path != "/api/v1/agent/config" {
			t.Errorf("request path = %q", req.URL.Path)
		}
		requestID = req.URL.Query().Get("requestId")
		if req.Header.Get("Cache-Control") != "no-cache" {
			t.Errorf("Cache-Control = %q", req.Header.Get("Cache-Control"))
		}
		if req.Header.Get("Pragma") != "no-cache" {
			t.Errorf("Pragma = %q", req.Header.Get("Pragma"))
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"revision":1}`))
	}))
	defer server.Close()

	client := New(server.URL, "node-token")
	config, err := client.GetConfig(context.Background())
	if err != nil {
		t.Fatalf("GetConfig() error = %v", err)
	}
	if config.Revision != 1 {
		t.Fatalf("revision = %d, want 1", config.Revision)
	}
	if requestID == "" {
		t.Fatal("requestId query parameter is missing")
	}
}
