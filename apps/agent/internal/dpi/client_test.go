package dpi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestClientFlowLifecycleAndStatus(t *testing.T) {
	var got ClassifyRequest
	closed := make(chan string, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/healthz":
			_ = json.NewEncoder(w).Encode(map[string]any{"status": "ok", "version": "test", "engine": "ndpi", "engineVersion": "5.0"})
		case r.Method == http.MethodPost && r.URL.Path == "/classify":
			if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
				t.Errorf("decode request: %v", err)
			}
			_ = json.NewEncoder(w).Encode(ClassifyResponse{Protocol: "bittorrent", Category: "p2p", Confidence: 95, Engine: "ndpi", Final: true, Packets: 2})
		case r.Method == http.MethodDelete:
			closed <- r.URL.Path
			w.WriteHeader(http.StatusNoContent)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	client := New(server.URL, time.Second)
	if err := client.Probe(context.Background()); err != nil {
		t.Fatalf("Probe() error = %v", err)
	}
	request := ClassifyRequest{
		Network: "udp", Payload: []byte("packet"), FlowID: "rule-1/flow", Direction: "client_to_server",
		SourceIP: "192.0.2.10", DestinationIP: "198.51.100.20", SourcePort: 41000, DestinationPort: 443,
	}
	response, err := client.Classify(context.Background(), request)
	if err != nil {
		t.Fatalf("Classify() error = %v", err)
	}
	if got.FlowID != request.FlowID || got.SourcePort != request.SourcePort || !response.Final || response.Engine != "ndpi" {
		t.Fatalf("flow request/response mismatch: got=%#v response=%#v", got, response)
	}
	if err := client.CloseFlow(context.Background(), request.FlowID); err != nil {
		t.Fatalf("CloseFlow() error = %v", err)
	}
	select {
	case path := <-closed:
		if path != "/flows/rule-1/flow" {
			t.Fatalf("close path = %q", path)
		}
	case <-time.After(time.Second):
		t.Fatal("flow close request was not received")
	}
	status := client.Status()
	if !status.Healthy || status.Engine != "ndpi" || status.EngineVersion != "5.0" {
		t.Fatalf("Status() = %#v", status)
	}
}
