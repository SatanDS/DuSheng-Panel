package configsync

import (
	"testing"
	"time"

	"dusheng-panel/apps/agent/internal/client"
)

func TestRendererDetectsConfigChanges(t *testing.T) {
	renderer := NewRenderer(t.TempDir())
	cfg := client.AgentConfig{
		Node:        client.Node{ID: 1, Name: "node"},
		DeviceGroup: client.DeviceGroup{ID: 1, Name: "entry"},
		ForwardRules: []client.ForwardRule{
			{
				ID:         1,
				UserID:     1,
				TunnelID:   1,
				Name:       "web",
				Protocol:   "tcp",
				ListenPort: 20000,
				RemoteHost: "127.0.0.1",
				RemotePort: 8080,
				Status:     "active",
				Strategy:   "least_conn",
			},
		},
		Revision:    1,
		GeneratedAt: time.Unix(1, 0).UTC(),
	}

	first, err := renderer.Render(cfg)
	if err != nil {
		t.Fatalf("first Render() error = %v", err)
	}
	if !first.Changed || first.ServiceCount != 1 {
		t.Fatalf("first Render() = changed %v services %d, want changed true services 1", first.Changed, first.ServiceCount)
	}

	second, err := renderer.Render(cfg)
	if err != nil {
		t.Fatalf("second Render() error = %v", err)
	}
	if second.Changed || second.ServiceCount != 1 {
		t.Fatalf("second Render() = changed %v services %d, want changed false services 1", second.Changed, second.ServiceCount)
	}
}
