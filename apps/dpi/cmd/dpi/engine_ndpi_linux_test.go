//go:build linux && cgo && ndpi

package main

import (
	"context"
	"testing"
	"time"
)

func TestNDPIEngineClassifiesHTTPWithoutTreatingGenericFlowRiskAsAbuse(t *testing.T) {
	engineValue, err := newNDPIEngine(engineOptions{MaxFlows: 8, FlowTTL: time.Minute, MaxPackets: 8})
	if err != nil {
		t.Fatalf("newNDPIEngine() error = %v", err)
	}
	engine := engineValue.(*ndpiEngine)
	defer engine.Close()

	result, err := engine.Classify(context.Background(), classifyRequest{
		Network: "tcp", Payload: []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"), FlowID: "http-test",
		Direction: "client_to_server", SourceIP: "192.0.2.10", DestinationIP: "198.51.100.20", SourcePort: 41000, DestinationPort: 80,
	})
	if err != nil {
		t.Fatalf("Classify() error = %v", err)
	}
	if result.Engine != "ndpi" || result.Protocol != "http" || result.Category != "web" || result.Confidence < 80 {
		t.Fatalf("Classify() = %#v, want high-confidence nDPI HTTP", result)
	}
	if result.RiskScore >= 50 {
		t.Fatalf("HTTP generic flow risk was promoted to abuse risk: %#v", result)
	}
}

func TestNDPIEngineEvictsOldestFlowAtCapacity(t *testing.T) {
	engineValue, err := newNDPIEngine(engineOptions{MaxFlows: 1, FlowTTL: time.Minute, MaxPackets: 8})
	if err != nil {
		t.Fatalf("newNDPIEngine() error = %v", err)
	}
	engine := engineValue.(*ndpiEngine)
	defer engine.Close()

	for _, flowID := range []string{"first", "second"} {
		if _, err := engine.Classify(context.Background(), classifyRequest{
			Network: "udp", Payload: []byte{1, 2, 3, 4}, FlowID: flowID,
			Direction: "client_to_server", SourcePort: 40000, DestinationPort: 40001,
		}); err != nil {
			t.Fatalf("Classify(%s) error = %v", flowID, err)
		}
	}
	stats := engine.Stats()
	if stats["flows"] != 1 || stats["evicted"] != uint64(1) {
		t.Fatalf("Stats() = %#v, want one flow and one eviction", stats)
	}
}

func TestNDPICategoryMappingDoesNotConfuseBitTorrentWithTor(t *testing.T) {
	category := protocolCategory("bittorrent", "download")
	risk, tags := ndpiRisk("bittorrent", category, 100)
	if category != "p2p" || risk != 90 || containsString(tags, "vpn") || !containsString(tags, "p2p") {
		t.Fatalf("mapping = category=%s risk=%d tags=%v", category, risk, tags)
	}
}

func TestNDPIEngineExpiresIdleFlowsWithoutNewTraffic(t *testing.T) {
	engineValue, err := newNDPIEngine(engineOptions{MaxFlows: 8, FlowTTL: 20 * time.Millisecond, MaxPackets: 8})
	if err != nil {
		t.Fatalf("newNDPIEngine() error = %v", err)
	}
	engine := engineValue.(*ndpiEngine)
	defer engine.Close()
	if _, err := engine.Classify(context.Background(), classifyRequest{
		Network: "udp", Payload: []byte{1, 2, 3, 4}, FlowID: "expires",
		Direction: "client_to_server", SourcePort: 40000, DestinationPort: 40001,
	}); err != nil {
		t.Fatalf("Classify() error = %v", err)
	}
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if engine.Stats()["flows"] == 0 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("idle flow was not expired: %#v", engine.Stats())
}

func containsString(values []string, expected string) bool {
	for _, value := range values {
		if value == expected {
			return true
		}
	}
	return false
}
