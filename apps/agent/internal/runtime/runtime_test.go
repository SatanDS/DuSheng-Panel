package runtime

import (
	"context"
	"io"
	"net"
	"strconv"
	"sync"
	"testing"
	"time"

	"dusheng-panel/apps/agent/internal/client"
)

type mockReporter struct {
	mu         sync.Mutex
	traffic    []client.TrafficReport
	violations []client.ViolationReport
}

func (m *mockReporter) ReportTraffic(ctx context.Context, req client.TrafficReport) (client.AcceptedResponse, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.traffic = append(m.traffic, req)
	return client.AcceptedResponse{Accepted: len(req.Samples)}, nil
}

func (m *mockReporter) ReportViolation(ctx context.Context, req client.ViolationReport) (client.ProtocolViolation, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.violations = append(m.violations, req)
	return client.ProtocolViolation{RuleID: req.RuleID, PolicyID: req.PolicyID, Protocol: req.Protocol, Action: req.Action}, nil
}

func (m *mockReporter) trafficTotals(ruleID uint) (int64, int64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var inBytes, outBytes int64
	for _, report := range m.traffic {
		for _, sample := range report.Samples {
			if sample.RuleID == ruleID {
				inBytes += sample.InBytes
				outBytes += sample.OutBytes
			}
		}
	}
	return inBytes, outBytes
}

func (m *mockReporter) violationCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.violations)
}

func (m *mockReporter) lastViolation() client.ViolationReport {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.violations[len(m.violations)-1]
}

func TestRuntimeApplyStartsAndStopsListeners(t *testing.T) {
	reporter := &mockReporter{}
	rt := New(reporter, nil, Options{ListenHost: "127.0.0.1", ReadTimeout: 50 * time.Millisecond})
	defer rt.Stop(context.Background())

	_, upstreamPort, stopUpstream := startEchoServer(t)
	defer stopUpstream()
	listenPort := freePort(t)
	cfg := testConfig(listenPort, upstreamPort)

	if err := rt.Apply(context.Background(), cfg); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	if status := rt.Status(); status["listeners"] != 1 {
		t.Fatalf("listeners = %v, want 1", status["listeners"])
	}

	cfg.ForwardRules = nil
	if err := rt.Apply(context.Background(), cfg); err != nil {
		t.Fatalf("Apply(empty) error = %v", err)
	}
	if status := rt.Status(); status["listeners"] != 0 {
		t.Fatalf("listeners = %v, want 0", status["listeners"])
	}
}

func TestRuntimeAllowsTCPAndReportsTraffic(t *testing.T) {
	reporter := &mockReporter{}
	rt := New(reporter, nil, Options{ListenHost: "127.0.0.1", ReadTimeout: time.Second, FlushInterval: time.Hour})

	_, upstreamPort, stopUpstream := startEchoServer(t)
	defer stopUpstream()
	listenPort := freePort(t)
	if err := rt.Apply(context.Background(), testConfig(listenPort, upstreamPort)); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}

	conn, err := net.Dial("tcp", net.JoinHostPort("127.0.0.1", itoa(listenPort)))
	if err != nil {
		t.Fatalf("Dial() error = %v", err)
	}
	message := []byte("hello runtime")
	if _, err := conn.Write(message); err != nil {
		t.Fatalf("Write() error = %v", err)
	}
	got := make([]byte, len(message))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("ReadFull() error = %v", err)
	}
	if string(got) != string(message) {
		t.Fatalf("echo = %q, want %q", got, message)
	}
	_ = conn.Close()
	if err := rt.Stop(context.Background()); err != nil {
		t.Fatalf("Stop() error = %v", err)
	}

	inBytes, outBytes := reporter.trafficTotals(1)
	if inBytes < int64(len(message)) || outBytes < int64(len(message)) {
		t.Fatalf("traffic in=%d out=%d, want at least %d", inBytes, outBytes, len(message))
	}
}

func TestRuntimeBlocksTLSPolicy(t *testing.T) {
	reporter := &mockReporter{}
	rt := New(reporter, nil, Options{ListenHost: "127.0.0.1", ReadTimeout: time.Second})
	defer rt.Stop(context.Background())

	listenPort := freePort(t)
	cfg := testConfig(listenPort, freePort(t))
	policyID := uint(7)
	cfg.ForwardRules[0].ProtocolPolicyID = &policyID
	cfg.ProtocolPolicies = []client.ProtocolPolicy{{ID: policyID, Mode: "block", BlockTLS: true}}
	if err := rt.Apply(context.Background(), cfg); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}

	conn, err := net.Dial("tcp", net.JoinHostPort("127.0.0.1", itoa(listenPort)))
	if err != nil {
		t.Fatalf("Dial() error = %v", err)
	}
	defer conn.Close()
	if _, err := conn.Write(testTLSClientHello()); err != nil {
		t.Fatalf("Write() error = %v", err)
	}
	waitFor(t, func() bool { return reporter.violationCount() == 1 })
	violation := reporter.lastViolation()
	if violation.Action != "block" || violation.Protocol != "tls" {
		t.Fatalf("violation = action %q protocol %q, want block/tls", violation.Action, violation.Protocol)
	}
}

func TestRuntimeAlertsTLSPolicyAndAllowsTraffic(t *testing.T) {
	reporter := &mockReporter{}
	rt := New(reporter, nil, Options{ListenHost: "127.0.0.1", ReadTimeout: time.Second})
	defer rt.Stop(context.Background())

	_, upstreamPort, stopUpstream := startEchoServer(t)
	defer stopUpstream()
	listenPort := freePort(t)
	cfg := testConfig(listenPort, upstreamPort)
	policyID := uint(8)
	cfg.ForwardRules[0].ProtocolPolicyID = &policyID
	cfg.ProtocolPolicies = []client.ProtocolPolicy{{ID: policyID, Mode: "alert", BlockTLS: true}}
	if err := rt.Apply(context.Background(), cfg); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}

	conn, err := net.Dial("tcp", net.JoinHostPort("127.0.0.1", itoa(listenPort)))
	if err != nil {
		t.Fatalf("Dial() error = %v", err)
	}
	defer conn.Close()
	packet := testTLSClientHello()
	if _, err := conn.Write(packet); err != nil {
		t.Fatalf("Write() error = %v", err)
	}
	got := make([]byte, len(packet))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("ReadFull() error = %v", err)
	}
	waitFor(t, func() bool { return reporter.violationCount() == 1 })
	if violation := reporter.lastViolation(); violation.Action != "alert" {
		t.Fatalf("violation action = %q, want alert", violation.Action)
	}
}

func TestRuleListenerConnectionAndIPLimits(t *testing.T) {
	listener := &ruleListener{
		cfg:     ruleRuntimeConfig{limit: effectiveSpeedLimit{MaxConns: 1, MaxIPs: 1}},
		ipCount: map[string]int{},
	}
	if !listener.acquire("10.0.0.1") {
		t.Fatal("first acquire failed")
	}
	if listener.acquire("10.0.0.2") {
		t.Fatal("second IP acquire succeeded, want limit rejection")
	}
	if listener.acquire("10.0.0.1") {
		t.Fatal("second connection acquire succeeded, want maxConns rejection")
	}
	listener.release("10.0.0.1")
	if !listener.acquire("10.0.0.2") {
		t.Fatal("acquire after release failed")
	}
}

func TestTokenBucketLimitsThroughput(t *testing.T) {
	bucket := newTokenBucket(1000)
	start := time.Now()
	bucket.wait(1500)
	elapsed := time.Since(start)
	if elapsed < 300*time.Millisecond {
		t.Fatalf("elapsed = %v, want visible throttling", elapsed)
	}
}

func testConfig(listenPort, upstreamPort int) client.AgentConfig {
	return client.AgentConfig{
		DeviceGroup: client.DeviceGroup{ID: 1, Name: "entry"},
		Tunnels: []client.Tunnel{
			{ID: 1, Name: "direct", EntryGroupID: 1},
		},
		ForwardRules: []client.ForwardRule{
			{
				ID:         1,
				UserID:     1,
				TunnelID:   1,
				Name:       "rule",
				Protocol:   "tcp",
				ListenPort: listenPort,
				RemoteHost: "127.0.0.1",
				RemotePort: upstreamPort,
				Status:     "active",
				Strategy:   "least_conn",
			},
		},
	}
}

func startEchoServer(t *testing.T) (string, int, func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen() error = %v", err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				_, _ = io.Copy(conn, conn)
			}()
		}
	}()
	_, portText, _ := net.SplitHostPort(ln.Addr().String())
	port, _ := strconv.Atoi(portText)
	return "127.0.0.1", port, func() {
		_ = ln.Close()
		<-done
	}
}

func freePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen() error = %v", err)
	}
	_, portText, _ := net.SplitHostPort(ln.Addr().String())
	port, _ := strconv.Atoi(portText)
	_ = ln.Close()
	return port
}

func waitFor(t *testing.T, fn func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if fn() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("condition did not become true")
}

func testTLSClientHello() []byte {
	return []byte{0x16, 0x03, 0x01, 0x00, 0x2f, 0x01, 0x00, 0x00, 0x2b}
}

func itoa(value int) string {
	return strconv.Itoa(value)
}
