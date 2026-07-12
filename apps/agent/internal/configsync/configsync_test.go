package configsync

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"dusheng-panel/apps/agent/internal/client"
)

type recordingRuntime struct {
	applies      int
	failRevision int64
	configs      []client.AgentConfig
}

func (r *recordingRuntime) Apply(_ context.Context, cfg client.AgentConfig) error {
	r.applies++
	r.configs = append(r.configs, cfg)
	if cfg.Revision == r.failRevision {
		return errors.New("listener warming failed")
	}
	return nil
}

func (r *recordingRuntime) Running() bool { return true }
func (r *recordingRuntime) Status() map[string]any {
	return map[string]any{"running": true, "listeners": 1}
}
func (r *recordingRuntime) Stop(context.Context) error { return nil }

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

func TestSyncerAcknowledgesAndSkipsUnchangedRevision(t *testing.T) {
	cfg := client.AgentConfig{
		Node: client.Node{ID: 1, Name: "node"}, DeviceGroup: client.DeviceGroup{ID: 1, Name: "entry"},
		Revision: 1, Nonce: "nonce-1", GeneratedAt: time.Now().UTC(), ValidUntil: time.Now().Add(time.Minute),
	}
	var acknowledgements []client.ConfigAck
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		switch req.URL.Path {
		case "/api/v1/agent/config":
			_ = json.NewEncoder(w).Encode(cfg)
		case "/api/v1/agent/config/ack":
			var ack client.ConfigAck
			if err := json.NewDecoder(req.Body).Decode(&ack); err != nil {
				t.Errorf("decode ack: %v", err)
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			acknowledgements = append(acknowledgements, ack)
			w.WriteHeader(http.StatusNoContent)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	runtime := &recordingRuntime{}
	dataDir := t.TempDir()
	syncer := New(client.New(server.URL, "node-token"), dataDir, runtime, nil)
	if err := syncer.SyncOnce(context.Background()); err != nil {
		t.Fatalf("first SyncOnce() error = %v", err)
	}
	if runtime.applies != 1 || len(acknowledgements) != 1 || acknowledgements[0].Status != "applied" {
		t.Fatalf("first sync applies=%d acks=%#v", runtime.applies, acknowledgements)
	}
	cfg.ValidUntil = time.Now().Add(2 * time.Minute)
	if err := syncer.SyncOnce(context.Background()); err != nil {
		t.Fatalf("unchanged SyncOnce() error = %v", err)
	}
	if runtime.applies != 1 || len(acknowledgements) != 1 {
		t.Fatalf("unchanged config reapplied: applies=%d acks=%d", runtime.applies, len(acknowledgements))
	}

	runtime.failRevision = 2
	cfg.Revision = 2
	cfg.Nonce = "nonce-2"
	if err := syncer.SyncOnce(context.Background()); err == nil {
		t.Fatal("failed runtime apply returned nil")
	}
	if got := acknowledgements[len(acknowledgements)-1]; got.Status != "rolled_back" || got.Revision != 2 {
		t.Fatalf("failure ack = %#v, want rolled_back revision 2", got)
	}
	if syncer.AppliedRevision() != 1 {
		t.Fatalf("applied revision = %d, want previous revision 1", syncer.AppliedRevision())
	}
	content, err := os.ReadFile(filepath.Join(dataDir, renderedFile))
	if err != nil {
		t.Fatalf("read rolled-back rendered config: %v", err)
	}
	var rendered GostConfig
	if err := json.Unmarshal(content, &rendered); err != nil {
		t.Fatalf("decode rolled-back rendered config: %v", err)
	}
	if rendered.Metadata.Revision != 1 {
		t.Fatalf("rendered revision = %d, want previous revision 1", rendered.Metadata.Revision)
	}
}

func TestSyncerStopsRuntimeWhenReplacementKeepsFailingPastLease(t *testing.T) {
	cfg := client.AgentConfig{
		Node: client.Node{ID: 1, Name: "node"}, DeviceGroup: client.DeviceGroup{ID: 1, Name: "entry"},
		Revision: 1, Nonce: "nonce-1", GeneratedAt: time.Now().UTC(), ValidUntil: time.Now().Add(time.Minute),
	}
	var acknowledgements []client.ConfigAck
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		switch req.URL.Path {
		case "/api/v1/agent/config":
			_ = json.NewEncoder(w).Encode(cfg)
		case "/api/v1/agent/config/ack":
			var ack client.ConfigAck
			if err := json.NewDecoder(req.Body).Decode(&ack); err != nil {
				t.Errorf("decode ack: %v", err)
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			acknowledgements = append(acknowledgements, ack)
			w.WriteHeader(http.StatusNoContent)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	runtime := &recordingRuntime{}
	syncer := New(client.New(server.URL, "node-token"), t.TempDir(), runtime, nil)
	if err := syncer.SyncOnce(context.Background()); err != nil {
		t.Fatalf("initial SyncOnce() error = %v", err)
	}
	syncer.mu.Lock()
	syncer.leaseValidUntil = time.Now().Add(-time.Second)
	syncer.mu.Unlock()
	runtime.failRevision = 2
	cfg.Revision = 2
	cfg.Nonce = "nonce-2"
	if err := syncer.SyncOnce(context.Background()); err == nil {
		t.Fatal("failed replacement config returned nil")
	}
	if runtime.applies != 3 {
		t.Fatalf("runtime applies = %d, want initial, failed replacement, and fail-closed apply", runtime.applies)
	}
	if last := runtime.configs[len(runtime.configs)-1]; len(last.ForwardRules) != 0 || !last.ValidUntil.Before(time.Now().Add(time.Second)) {
		t.Fatalf("fail-closed config = %#v, want an immediately expired empty config", last)
	}
	if len(acknowledgements) < 3 || acknowledgements[len(acknowledgements)-2].Status != "rolled_back" || acknowledgements[len(acknowledgements)-1].Status != "lease_expired" {
		t.Fatalf("acknowledgements = %#v, want rolled_back followed by lease_expired", acknowledgements)
	}
	if status := syncer.RuntimeStatus(); status["configFailClosed"] != true || status["configStatus"] != "lease_expired" {
		t.Fatalf("runtime status = %#v, want fail-closed lease_expired", status)
	}
}
