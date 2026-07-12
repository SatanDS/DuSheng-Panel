package probe

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"dusheng-panel/apps/agent/internal/client"
)

type recordingReporter struct{ reports chan client.ProbeReport }

func (r recordingReporter) ReportProbe(_ context.Context, report client.ProbeReport) error {
	r.reports <- report
	return nil
}

func TestManagerRunsTCPProbeAndReports(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer listener.Close()
	go func() {
		conn, acceptErr := listener.Accept()
		if acceptErr == nil {
			_ = conn.Close()
		}
	}()
	reporter := recordingReporter{reports: make(chan client.ProbeReport, 1)}
	manager := New(reporter, nil)
	defer manager.Stop()
	cfg := client.AgentConfig{LineProbes: []client.LineProbe{{
		ID: 1, CircuitID: 1, NodeID: 1, Name: "tcp", Type: "tcp", Target: listener.Addr().String(),
		IntervalSeconds: 5, TimeoutMs: 500, Enabled: true, Revision: 1,
	}}}
	if err := manager.Apply(cfg); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	select {
	case report := <-reporter.reports:
		if !report.Success || report.ProbeID != 1 || report.Revision != 1 || report.LatencyMs < 0 {
			t.Fatalf("report = %#v", report)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("probe report timeout")
	}
}

func TestExecuteHTTPAndUDPEcho(t *testing.T) {
	httpServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "ok")
	}))
	defer httpServer.Close()
	if err := execute(context.Background(), client.LineProbe{Type: "http", Target: httpServer.URL}); err != nil {
		t.Fatalf("http probe: %v", err)
	}

	udpConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatalf("udp listen: %v", err)
	}
	defer udpConn.Close()
	go func() {
		buffer := make([]byte, 2048)
		n, addr, readErr := udpConn.ReadFromUDP(buffer)
		if readErr == nil {
			_, _ = udpConn.WriteToUDP(buffer[:n], addr)
		}
	}()
	port := udpConn.LocalAddr().(*net.UDPAddr).Port
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := execute(ctx, client.LineProbe{Type: "udp_echo", Target: net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), Payload: "hello"}); err != nil {
		t.Fatalf("udp probe: %v", err)
	}
}

func TestValidateRejectsUnsafeProbeConfiguration(t *testing.T) {
	manager := New(nil, nil)
	err := manager.Validate(client.AgentConfig{LineProbes: []client.LineProbe{{
		ID: 1, Type: "http", Target: "file:///etc/passwd", IntervalSeconds: 5, TimeoutMs: 1000, Enabled: true, Revision: 1,
	}}})
	if err == nil {
		t.Fatal("Validate() accepted non-http target")
	}
}
