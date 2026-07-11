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

func TestClassifyOpenVPNLikeStaysLowConfidence(t *testing.T) {
	got := classify(classifyRequest{Network: "udp", Payload: []byte{0x38, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c}})
	if got.Protocol != "openvpn_like" || got.Confidence >= 50 || got.RiskScore >= 50 {
		t.Fatalf("classify() = %#v, want low-confidence openvpn_like candidate", got)
	}
}
