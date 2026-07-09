package protocol

import "testing"

func TestIdentify(t *testing.T) {
	tests := []struct {
		name   string
		packet []byte
		want   string
	}{
		{
			name:   "TLS ClientHello",
			packet: []byte{0x16, 0x03, 0x01, 0x00, 0x2f, 0x01, 0x00, 0x00, 0x2b},
			want:   NameTLS,
		},
		{
			name:   "QUIC HTTP3 initial",
			packet: []byte{0xc3, 0x00, 0x00, 0x00, 0x01, 0x08, 0x83, 0x94, 0xc8, 0xf0},
			want:   NameQUIC,
		},
		{
			name:   "HTTP",
			packet: []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"),
			want:   NameHTTP,
		},
		{
			name:   "SSH",
			packet: []byte("SSH-2.0-OpenSSH_9.6\r\n"),
			want:   NameSSH,
		},
		{
			name:   "random",
			packet: []byte{0x13, 0x37, 0x00, 0xff, 0x42},
			want:   NameUnknown,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Identify(tt.packet); got != tt.want {
				t.Fatalf("Identify() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestDetectPolicyModes(t *testing.T) {
	packet := []byte{0x16, 0x03, 0x01, 0x00, 0x2f, 0x01, 0x00, 0x00, 0x2b}
	for _, mode := range []string{ActionObserve, ActionAlert, ActionBlock} {
		t.Run(mode, func(t *testing.T) {
			result := Detect(packet, Policy{Mode: mode, BlockTLS: true})
			if result.Protocol != NameTLS {
				t.Fatalf("Protocol = %q, want %q", result.Protocol, NameTLS)
			}
			if result.Action != mode {
				t.Fatalf("Action = %q, want %q", result.Action, mode)
			}
			if result.Reason == "" {
				t.Fatal("Reason is empty")
			}
		})
	}
}

func TestDetectAllowsNonViolations(t *testing.T) {
	result := Detect([]byte("GET / HTTP/1.1\r\n\r\n"), Policy{Mode: ActionBlock, BlockTLS: true})
	if result.Action != ActionAllow {
		t.Fatalf("Action = %q, want %q", result.Action, ActionAllow)
	}
}
