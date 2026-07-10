package main

import "testing"

func TestClassifyHighRiskProtocols(t *testing.T) {
	tests := []struct {
		name     string
		req      classifyRequest
		protocol string
		category string
	}{
		{
			name:     "bittorrent",
			req:      classifyRequest{Network: "tcp", Payload: []byte("\x13BitTorrent protocol")},
			protocol: "bittorrent",
			category: "p2p",
		},
		{
			name:     "wireguard handshake",
			req:      classifyRequest{Network: "udp", Payload: append([]byte{0x01, 0x00, 0x00, 0x00}, make([]byte, 144)...)},
			protocol: "wireguard",
			category: "vpn",
		},
		{
			name:     "ssh",
			req:      classifyRequest{Network: "tcp", Payload: []byte("SSH-2.0-OpenSSH_9.6\r\n")},
			protocol: "ssh",
			category: "remote_access",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := classify(tt.req)
			if got.Protocol != tt.protocol || got.Category != tt.category {
				t.Fatalf("classify() = %s/%s, want %s/%s", got.Protocol, got.Category, tt.protocol, tt.category)
			}
			if got.RiskScore <= 0 || got.Confidence <= 0 {
				t.Fatalf("risk/confidence not populated: %#v", got)
			}
		})
	}
}
