package runtime

import (
	"context"
	"io"
	"net"
	"strconv"
	"strings"
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

func TestRuntimeStartsAndStopsUDPListeners(t *testing.T) {
	reporter := &mockReporter{}
	rt := New(reporter, nil, Options{ListenHost: "127.0.0.1", ReadTimeout: 50 * time.Millisecond})
	defer rt.Stop(context.Background())

	_, upstreamPort, stopUpstream := startUDPEchoServer(t)
	defer stopUpstream()
	listenPort := freeUDPPort(t)
	cfg := testConfig(listenPort, upstreamPort)
	cfg.ForwardRules[0].Protocol = "udp"

	if err := rt.Apply(context.Background(), cfg); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	status := rt.Status()
	if status["listeners"] != 1 || status["udpListeners"] != 1 {
		t.Fatalf("status = %#v, want one udp listener", status)
	}

	cfg.ForwardRules = nil
	if err := rt.Apply(context.Background(), cfg); err != nil {
		t.Fatalf("Apply(empty) error = %v", err)
	}
	if status := rt.Status(); status["listeners"] != 0 {
		t.Fatalf("listeners = %v, want 0", status["listeners"])
	}
}

func TestRuntimeAllowsUDPAndReportsTraffic(t *testing.T) {
	reporter := &mockReporter{}
	rt := New(reporter, nil, Options{ListenHost: "127.0.0.1", FlushInterval: time.Hour})

	_, upstreamPort, stopUpstream := startUDPEchoServer(t)
	defer stopUpstream()
	listenPort := freeUDPPort(t)
	cfg := testConfig(listenPort, upstreamPort)
	cfg.ForwardRules[0].Protocol = "udp"
	if err := rt.Apply(context.Background(), cfg); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}

	message := []byte("hello udp runtime")
	got, err := udpRoundTrip(listenPort, message, time.Second)
	if err != nil {
		t.Fatalf("udpRoundTrip() error = %v", err)
	}
	if string(got) != string(message) {
		t.Fatalf("echo = %q, want %q", got, message)
	}
	if err := rt.Stop(context.Background()); err != nil {
		t.Fatalf("Stop() error = %v", err)
	}

	inBytes, outBytes := reporter.trafficTotals(1)
	if inBytes < int64(len(message)) || outBytes < int64(len(message)) {
		t.Fatalf("traffic in=%d out=%d, want at least %d", inBytes, outBytes, len(message))
	}
}

func TestRuntimeTCPUDPStartsBothOnSamePort(t *testing.T) {
	reporter := &mockReporter{}
	rt := New(reporter, nil, Options{ListenHost: "127.0.0.1", ReadTimeout: time.Second})
	defer rt.Stop(context.Background())

	_, upstreamPort, stopTCPUpstream := startEchoServer(t)
	defer stopTCPUpstream()
	stopUDPUpstream := startUDPEchoServerOnPort(t, upstreamPort)
	defer stopUDPUpstream()
	listenPort := freeTCPUDPPort(t)
	cfg := testConfig(listenPort, upstreamPort)
	cfg.ForwardRules[0].Protocol = "tcp_udp"
	if err := rt.Apply(context.Background(), cfg); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	status := rt.Status()
	if status["listeners"] != 2 || status["tcpListeners"] != 1 || status["udpListeners"] != 1 {
		t.Fatalf("status = %#v, want tcp and udp listeners", status)
	}

	conn, err := net.Dial("tcp", net.JoinHostPort("127.0.0.1", itoa(listenPort)))
	if err != nil {
		t.Fatalf("Dial() error = %v", err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte("tcp")); err != nil {
		t.Fatalf("tcp Write() error = %v", err)
	}
	gotTCP := make([]byte, 3)
	if _, err := io.ReadFull(conn, gotTCP); err != nil {
		t.Fatalf("tcp ReadFull() error = %v", err)
	}
	gotUDP, err := udpRoundTrip(listenPort, []byte("udp"), time.Second)
	if err != nil {
		t.Fatalf("udpRoundTrip() error = %v", err)
	}
	if string(gotTCP) != "tcp" || string(gotUDP) != "udp" {
		t.Fatalf("tcp=%q udp=%q, want echoes", gotTCP, gotUDP)
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

func TestRuntimeBlocksQUICPolicy(t *testing.T) {
	reporter := &mockReporter{}
	rt := New(reporter, nil, Options{ListenHost: "127.0.0.1"})
	defer rt.Stop(context.Background())

	_, upstreamPort, stopUpstream := startUDPEchoServer(t)
	defer stopUpstream()
	listenPort := freeUDPPort(t)
	cfg := testConfig(listenPort, upstreamPort)
	cfg.ForwardRules[0].Protocol = "udp"
	policyID := uint(9)
	cfg.ForwardRules[0].ProtocolPolicyID = &policyID
	cfg.ProtocolPolicies = []client.ProtocolPolicy{{ID: policyID, Mode: "block", BlockQUIC: true}}
	if err := rt.Apply(context.Background(), cfg); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}

	conn, err := net.Dial("udp", net.JoinHostPort("127.0.0.1", itoa(listenPort)))
	if err != nil {
		t.Fatalf("Dial() error = %v", err)
	}
	defer conn.Close()
	if _, err := conn.Write(testQUICInitial()); err != nil {
		t.Fatalf("Write() error = %v", err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(150 * time.Millisecond))
	buf := make([]byte, 64)
	if n, err := conn.Read(buf); err == nil || n > 0 {
		t.Fatalf("Read() = n %d err %v, want timeout or no response", n, err)
	}
	waitFor(t, func() bool { return reporter.violationCount() == 1 })
	violation := reporter.lastViolation()
	if violation.Action != "block" || violation.Protocol != "quic" || !strings.Contains(violation.Detail, "udp_runtime") {
		t.Fatalf("violation = %#v, want udp quic block", violation)
	}
}

func TestRuntimeAlertsQUICPolicyAndAllowsUDP(t *testing.T) {
	reporter := &mockReporter{}
	rt := New(reporter, nil, Options{ListenHost: "127.0.0.1"})
	defer rt.Stop(context.Background())

	_, upstreamPort, stopUpstream := startUDPEchoServer(t)
	defer stopUpstream()
	listenPort := freeUDPPort(t)
	cfg := testConfig(listenPort, upstreamPort)
	cfg.ForwardRules[0].Protocol = "udp"
	policyID := uint(10)
	cfg.ForwardRules[0].ProtocolPolicyID = &policyID
	cfg.ProtocolPolicies = []client.ProtocolPolicy{{ID: policyID, Mode: "alert", BlockQUIC: true}}
	if err := rt.Apply(context.Background(), cfg); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}

	packet := testQUICInitial()
	got, err := udpRoundTrip(listenPort, packet, time.Second)
	if err != nil {
		t.Fatalf("udpRoundTrip() error = %v", err)
	}
	if string(got) != string(packet) {
		t.Fatalf("echo = %q, want %q", got, packet)
	}
	waitFor(t, func() bool { return reporter.violationCount() == 1 })
	if violation := reporter.lastViolation(); violation.Action != "alert" || violation.Protocol != "quic" {
		t.Fatalf("violation = %#v, want quic alert", violation)
	}
}

func TestUDPSessionIdleReleasesLimits(t *testing.T) {
	reporter := &mockReporter{}
	rt := New(reporter, nil, Options{ListenHost: "127.0.0.1", UDPIdleTimeout: 50 * time.Millisecond})
	defer rt.Stop(context.Background())

	_, upstreamPort, stopUpstream := startUDPEchoServer(t)
	defer stopUpstream()
	listenPort := freeUDPPort(t)
	cfg := testConfig(listenPort, upstreamPort)
	cfg.ForwardRules[0].Protocol = "udp"
	ruleID := cfg.ForwardRules[0].ID
	cfg.SpeedLimits = []client.SpeedLimit{{RuleID: &ruleID, MaxConns: 1}}
	if err := rt.Apply(context.Background(), cfg); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}

	first, err := net.Dial("udp", net.JoinHostPort("127.0.0.1", itoa(listenPort)))
	if err != nil {
		t.Fatalf("Dial(first) error = %v", err)
	}
	defer first.Close()
	if _, err := udpRoundTripConn(first, []byte("first"), time.Second); err != nil {
		t.Fatalf("first udpRoundTripConn() error = %v", err)
	}

	second, err := net.Dial("udp", net.JoinHostPort("127.0.0.1", itoa(listenPort)))
	if err != nil {
		t.Fatalf("Dial(second) error = %v", err)
	}
	defer second.Close()
	if _, err := udpRoundTripConn(second, []byte("blocked"), 150*time.Millisecond); err == nil {
		t.Fatal("second session succeeded while maxConns was occupied")
	}

	waitFor(t, func() bool {
		return rt.Status()["activeUDPSessions"] == int64(0)
	})
	if got, err := udpRoundTripConn(second, []byte("after"), time.Second); err != nil || string(got) != "after" {
		t.Fatalf("second after idle got %q err %v, want echo", got, err)
	}
}

func TestUDPTokenBucketLimitsThroughput(t *testing.T) {
	reporter := &mockReporter{}
	rt := New(reporter, nil, Options{ListenHost: "127.0.0.1"})
	defer rt.Stop(context.Background())

	_, upstreamPort, stopUpstream := startUDPEchoServer(t)
	defer stopUpstream()
	listenPort := freeUDPPort(t)
	cfg := testConfig(listenPort, upstreamPort)
	cfg.ForwardRules[0].Protocol = "udp"
	ruleID := cfg.ForwardRules[0].ID
	cfg.SpeedLimits = []client.SpeedLimit{{RuleID: &ruleID, UploadBps: 1000}}
	if err := rt.Apply(context.Background(), cfg); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}

	message := make([]byte, 1500)
	start := time.Now()
	if _, err := udpRoundTrip(listenPort, message, 2*time.Second); err != nil {
		t.Fatalf("udpRoundTrip() error = %v", err)
	}
	if elapsed := time.Since(start); elapsed < 300*time.Millisecond {
		t.Fatalf("elapsed = %v, want visible UDP throttling", elapsed)
	}
}

func TestTCPUDPSharedLimitTracker(t *testing.T) {
	reporter := &mockReporter{}
	rt := New(reporter, nil, Options{ListenHost: "127.0.0.1", ReadTimeout: 50 * time.Millisecond})
	defer rt.Stop(context.Background())

	_, upstreamPort, stopTCPUpstream := startEchoServer(t)
	defer stopTCPUpstream()
	stopUDPUpstream := startUDPEchoServerOnPort(t, upstreamPort)
	defer stopUDPUpstream()
	listenPort := freeTCPUDPPort(t)
	cfg := testConfig(listenPort, upstreamPort)
	cfg.ForwardRules[0].Protocol = "tcp_udp"
	ruleID := cfg.ForwardRules[0].ID
	cfg.SpeedLimits = []client.SpeedLimit{{RuleID: &ruleID, MaxConns: 1}}
	if err := rt.Apply(context.Background(), cfg); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}

	tcpConn, err := net.Dial("tcp", net.JoinHostPort("127.0.0.1", itoa(listenPort)))
	if err != nil {
		t.Fatalf("tcp Dial() error = %v", err)
	}
	defer tcpConn.Close()
	waitFor(t, func() bool { return rt.Status()["activeConnections"] == int64(1) })

	if _, err := udpRoundTrip(listenPort, []byte("blocked"), 150*time.Millisecond); err == nil {
		t.Fatal("udp session succeeded while tcp connection occupied shared maxConns")
	}
	_ = tcpConn.Close()
	waitFor(t, func() bool { return rt.Status()["activeConnections"] == int64(0) })
	if got, err := udpRoundTrip(listenPort, []byte("after"), time.Second); err != nil || string(got) != "after" {
		t.Fatalf("udp after tcp close got %q err %v, want echo", got, err)
	}
}

func TestRuleListenerConnectionAndIPLimits(t *testing.T) {
	limit := effectiveSpeedLimit{MaxConns: 1, MaxIPs: 1}
	listener := &ruleListener{
		cfg: ruleRuntimeConfig{limit: limit, tracker: newLimitTracker(limit)},
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
	return startEchoServerOnPort(t, 0)
}

func startEchoServerOnPort(t *testing.T, port int) (string, int, func()) {
	t.Helper()
	ln, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", itoa(port)))
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
	port, _ = strconv.Atoi(portText)
	return "127.0.0.1", port, func() {
		_ = ln.Close()
		<-done
	}
}

func startUDPEchoServer(t *testing.T) (string, int, func()) {
	port := freeUDPPort(t)
	stop := startUDPEchoServerOnPort(t, port)
	return "127.0.0.1", port, stop
}

func startUDPEchoServerOnPort(t *testing.T, port int) func() {
	t.Helper()
	conn, err := net.ListenPacket("udp", net.JoinHostPort("127.0.0.1", itoa(port)))
	if err != nil {
		t.Fatalf("ListenPacket() error = %v", err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 64*1024)
		for {
			n, addr, err := conn.ReadFrom(buf)
			if err != nil {
				return
			}
			_, _ = conn.WriteTo(buf[:n], addr)
		}
	}()
	return func() {
		_ = conn.Close()
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

func freeUDPPort(t *testing.T) int {
	t.Helper()
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket() error = %v", err)
	}
	_, portText, _ := net.SplitHostPort(conn.LocalAddr().String())
	port, _ := strconv.Atoi(portText)
	_ = conn.Close()
	return port
}

func freeTCPUDPPort(t *testing.T) int {
	t.Helper()
	for i := 0; i < 20; i++ {
		port := freePort(t)
		conn, err := net.ListenPacket("udp", net.JoinHostPort("127.0.0.1", itoa(port)))
		if err == nil {
			_ = conn.Close()
			return port
		}
	}
	t.Fatal("could not find free tcp/udp port")
	return 0
}

func udpRoundTrip(port int, message []byte, timeout time.Duration) ([]byte, error) {
	conn, err := net.Dial("udp", net.JoinHostPort("127.0.0.1", itoa(port)))
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	return udpRoundTripConn(conn, message, timeout)
}

func udpRoundTripConn(conn net.Conn, message []byte, timeout time.Duration) ([]byte, error) {
	if deadline := time.Now().Add(timeout); timeout > 0 {
		_ = conn.SetDeadline(deadline)
		defer conn.SetDeadline(time.Time{})
	}
	if _, err := conn.Write(message); err != nil {
		return nil, err
	}
	got := make([]byte, len(message))
	n, err := io.ReadFull(conn, got)
	if err != nil {
		return got[:n], err
	}
	return got, nil
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

func testQUICInitial() []byte {
	return []byte{0xc3, 0x00, 0x00, 0x00, 0x01, 0x08, 0x01, 0x02, 0x03, 0x04}
}

func itoa(value int) string {
	return strconv.Itoa(value)
}
