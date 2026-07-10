package protocol

import (
	"crypto/tls"
	"net"
	"testing"
	"time"
)

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
	for _, mode := range []string{ActionObserve, ActionAlert, ActionLimit, ActionBlock} {
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

func TestAuthorizedSSAllowsUnknownEncryptedEntry(t *testing.T) {
	result := Detect([]byte{0x13, 0x37, 0x00, 0xff, 0x42, 0x99}, Policy{
		Purpose:             "authorized_ss",
		Network:             "tcp",
		AuthorizedProtocols: "ss,shadowsocks,ss2022",
		UnknownTCPAction:    ActionBlock,
	})
	if result.Action != ActionAllow {
		t.Fatalf("Action = %q, want allow: %#v", result.Action, result)
	}
}

func TestGamingPolicyBlocksSSHButAllowsUDPUnknown(t *testing.T) {
	ssh := Detect([]byte("SSH-2.0-OpenSSH_9.6\r\n"), Policy{Purpose: "gaming", Network: "tcp"})
	if ssh.Action != ActionBlock {
		t.Fatalf("SSH action = %q, want block", ssh.Action)
	}
	udp := Detect([]byte{0x01, 0x02, 0x03, 0x04}, Policy{Purpose: "gaming", Network: "udp"})
	if udp.Action != ActionAllow {
		t.Fatalf("UDP unknown action = %q, want allow", udp.Action)
	}
}

func TestSSHOpsAllowsSSH(t *testing.T) {
	result := Detect([]byte("SSH-2.0-OpenSSH_9.6\r\n"), Policy{Purpose: "ssh_ops", Network: "tcp"})
	if result.Action != ActionAllow {
		t.Fatalf("Action = %q, want allow", result.Action)
	}
}

func TestDPIBlockedGroup(t *testing.T) {
	result := Detect([]byte{0x01, 0x02, 0x03}, Policy{Purpose: "gaming", Network: "udp"})
	result = ApplyDPI(result, Policy{Purpose: "gaming", BlockedProtocolGroups: "vpn,p2p"}, DPIResult{
		Protocol:   "wireguard",
		Category:   "vpn",
		Confidence: 90,
		RiskScore:  85,
	})
	if result.Action != ActionBlock {
		t.Fatalf("Action = %q, want block", result.Action)
	}
	if result.NDPIProtocol != "wireguard" || result.NDPICategory != "vpn" {
		t.Fatalf("DPI fields not populated: %#v", result)
	}
}

func TestDPIRespectsAuthorizedSSHOperations(t *testing.T) {
	result := Detect([]byte("SSH-2.0-OpenSSH_9.6\r\n"), Policy{Purpose: "ssh_ops", Network: "tcp", Mode: ActionBlock})
	result = ApplyDPI(result, Policy{Purpose: "ssh_ops", Network: "tcp", Mode: ActionBlock, BlockedProtocolGroups: "proxy,p2p,vpn"}, DPIResult{
		Protocol:   "ssh",
		Category:   "remote_access",
		Confidence: 100,
		RiskScore:  60,
	})
	if result.Action != ActionAllow {
		t.Fatalf("Action = %q, want allow: %#v", result.Action, result)
	}
}

func TestDetectAllowsNonViolations(t *testing.T) {
	result := Detect([]byte("GET / HTTP/1.1\r\n\r\n"), Policy{Mode: ActionBlock, BlockTLS: true})
	if result.Action != ActionAllow {
		t.Fatalf("Action = %q, want %q", result.Action, ActionAllow)
	}
}

func TestInspectTLSClientHelloMetadata(t *testing.T) {
	packet := captureClientHello(t, "example.com", []string{"h2", "http/1.1"})
	result := Inspect(packet)
	if result.Protocol != NameTLS {
		t.Fatalf("Protocol = %q, want %q", result.Protocol, NameTLS)
	}
	if result.Host != "example.com" {
		t.Fatalf("Host = %q, want example.com", result.Host)
	}
	if len(result.ALPN) != 2 || result.ALPN[0] != "h2" || result.ALPN[1] != "http/1.1" {
		t.Fatalf("ALPN = %#v, want h2/http/1.1", result.ALPN)
	}
}

func TestInspectHTTPHost(t *testing.T) {
	result := Inspect([]byte("GET / HTTP/1.1\r\nHost: app.example.com\r\n\r\n"))
	if result.Protocol != NameHTTP {
		t.Fatalf("Protocol = %q, want %q", result.Protocol, NameHTTP)
	}
	if result.Host != "app.example.com" {
		t.Fatalf("Host = %q, want app.example.com", result.Host)
	}
}

func TestInspectHTTPConnectHost(t *testing.T) {
	result := Inspect([]byte("CONNECT tunnel.example.com:443 HTTP/1.1\r\nHost: tunnel.example.com\r\n\r\n"))
	if result.Protocol != NameHTTPConnect {
		t.Fatalf("Protocol = %q, want %q", result.Protocol, NameHTTPConnect)
	}
	if result.Host != "tunnel.example.com:443" {
		t.Fatalf("Host = %q, want tunnel.example.com:443", result.Host)
	}
}

func TestInspectShortPacket(t *testing.T) {
	result := Inspect([]byte{0x16, 0x03})
	if result.Protocol != NameUnknown {
		t.Fatalf("Protocol = %q, want %q", result.Protocol, NameUnknown)
	}
}

func captureClientHello(t *testing.T, serverName string, alpn []string) []byte {
	t.Helper()
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	errc := make(chan error, 1)
	go func() {
		tlsConn := tls.Client(clientConn, &tls.Config{
			ServerName:         serverName,
			NextProtos:         alpn,
			InsecureSkipVerify: true,
		})
		errc <- tlsConn.Handshake()
	}()

	if err := serverConn.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatalf("SetReadDeadline() error = %v", err)
	}
	buf := make([]byte, 4096)
	n, err := serverConn.Read(buf)
	if err != nil {
		t.Fatalf("Read() error = %v", err)
	}
	_ = serverConn.Close()
	<-errc
	return buf[:n]
}
