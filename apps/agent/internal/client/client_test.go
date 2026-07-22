package client

import (
	"encoding/json"
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
