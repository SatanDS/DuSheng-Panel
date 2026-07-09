package runtime

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"dusheng-panel/apps/agent/internal/client"
	"dusheng-panel/apps/agent/internal/protocol"
)

const (
	defaultFirstPacketBytes = 2048
	defaultReadTimeout      = time.Second
	defaultFlushInterval    = 15 * time.Second
)

type Reporter interface {
	ReportTraffic(context.Context, client.TrafficReport) (client.AcceptedResponse, error)
	ReportViolation(context.Context, client.ViolationReport) (client.ProtocolViolation, error)
}

type Options struct {
	ListenHost       string
	FirstPacketBytes int
	ReadTimeout      time.Duration
	FlushInterval    time.Duration
}

type Runtime struct {
	reporter Reporter
	logger   *log.Logger
	options  Options
	traffic  *trafficBuffer

	mu           sync.Mutex
	listeners    map[uint]*ruleListener
	running      bool
	lastApplyErr string
	closed       bool
	stopFlush    chan struct{}
}

func New(reporter Reporter, logger *log.Logger, options Options) *Runtime {
	if logger == nil {
		logger = log.Default()
	}
	if options.FirstPacketBytes <= 0 {
		options.FirstPacketBytes = defaultFirstPacketBytes
	}
	if options.ReadTimeout <= 0 {
		options.ReadTimeout = defaultReadTimeout
	}
	if options.FlushInterval <= 0 {
		options.FlushInterval = defaultFlushInterval
	}
	rt := &Runtime{
		reporter:  reporter,
		logger:    logger,
		options:   options,
		traffic:   newTrafficBuffer(reporter, logger),
		listeners: map[uint]*ruleListener{},
		stopFlush: make(chan struct{}),
	}
	go rt.flushLoop()
	return rt
}

func (r *Runtime) Apply(ctx context.Context, cfg client.AgentConfig) error {
	desired, err := r.desiredListeners(cfg)
	if err != nil {
		r.setApplyError(err)
		return err
	}

	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return errors.New("runtime is stopped")
	}
	r.running = true
	current := r.listeners
	next := make(map[uint]*ruleListener, len(desired))
	var toStop []*ruleListener
	var startErr error

	for ruleID, desiredCfg := range desired {
		if existing := current[ruleID]; existing != nil && existing.cfg.fingerprint == desiredCfg.fingerprint {
			next[ruleID] = existing
			continue
		}
		if existing := current[ruleID]; existing != nil {
			toStop = append(toStop, existing)
		}
		listener, err := r.startListener(ctx, desiredCfg)
		if err != nil {
			startErr = errors.Join(startErr, err)
			continue
		}
		next[ruleID] = listener
	}
	for ruleID, existing := range current {
		if _, ok := desired[ruleID]; !ok {
			toStop = append(toStop, existing)
		}
	}
	r.listeners = next
	r.lastApplyErr = errorString(startErr)
	r.mu.Unlock()

	for _, listener := range toStop {
		listener.stop()
	}
	if startErr != nil {
		return startErr
	}
	return nil
}

func (r *Runtime) Running() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.running && !r.closed
}

func (r *Runtime) Status() map[string]any {
	r.mu.Lock()
	defer r.mu.Unlock()
	var active int64
	for _, listener := range r.listeners {
		active += listener.active()
	}
	return map[string]any{
		"running":           r.running && !r.closed,
		"listeners":         len(r.listeners),
		"activeConnections": active,
		"lastApplyError":    r.lastApplyErr,
	}
}

func (r *Runtime) Stop(ctx context.Context) error {
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return nil
	}
	r.closed = true
	r.running = false
	close(r.stopFlush)
	listeners := make([]*ruleListener, 0, len(r.listeners))
	for _, listener := range r.listeners {
		listeners = append(listeners, listener)
	}
	r.listeners = map[uint]*ruleListener{}
	r.mu.Unlock()

	done := make(chan struct{})
	go func() {
		for _, listener := range listeners {
			listener.stop()
		}
		r.traffic.flush(context.Background())
		close(done)
	}()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-done:
		return nil
	}
}

func (r *Runtime) desiredListeners(cfg client.AgentConfig) (map[uint]ruleRuntimeConfig, error) {
	tunnels := map[uint]client.Tunnel{}
	for _, tunnel := range cfg.Tunnels {
		tunnels[tunnel.ID] = tunnel
	}
	policies := map[uint]client.ProtocolPolicy{}
	for _, policy := range cfg.ProtocolPolicies {
		policies[policy.ID] = policy
	}

	desired := map[uint]ruleRuntimeConfig{}
	for _, rule := range cfg.ForwardRules {
		if skipRule(rule) || !isTCPRule(rule) {
			continue
		}
		tunnel, ok := tunnels[rule.TunnelID]
		if !ok {
			return nil, fmt.Errorf("rule %d references missing tunnel %d", rule.ID, rule.TunnelID)
		}
		policy := effectivePolicy(rule, tunnel, cfg.DeviceGroup, policies)
		limit := effectiveLimit(rule, cfg.SpeedLimits)
		listenHost := r.listenHost(cfg.DeviceGroup)
		desired[rule.ID] = ruleRuntimeConfig{
			rule:        rule,
			tunnel:      tunnel,
			deviceGroup: cfg.DeviceGroup,
			policy:      policy,
			limit:       limit,
			listenAddr:  net.JoinHostPort(listenHost, strconv.Itoa(rule.ListenPort)),
			fingerprint: fingerprint(rule, tunnel, cfg.DeviceGroup, policy, limit, listenHost),
		}
	}
	return desired, nil
}

func (r *Runtime) listenHost(group client.DeviceGroup) string {
	if r.options.ListenHost != "" {
		return r.options.ListenHost
	}
	if group.BindIPs != "" {
		parts := strings.Split(group.BindIPs, ",")
		for _, part := range parts {
			if value := strings.TrimSpace(part); value != "" {
				return value
			}
		}
	}
	return ""
}

func (r *Runtime) startListener(ctx context.Context, cfg ruleRuntimeConfig) (*ruleListener, error) {
	ln, err := (&net.ListenConfig{}).Listen(ctx, "tcp", cfg.listenAddr)
	if err != nil {
		return nil, fmt.Errorf("listen rule %d on %s: %w", cfg.rule.ID, cfg.listenAddr, err)
	}
	listener := &ruleListener{
		runtime: r,
		cfg:     cfg,
		ln:      ln,
		stopCh:  make(chan struct{}),
		ipCount: map[string]int{},
		conns:   map[net.Conn]struct{}{},
	}
	listener.wg.Add(1)
	go listener.acceptLoop()
	r.logger.Printf("runtime listener started rule=%d addr=%s target=%s:%d", cfg.rule.ID, cfg.listenAddr, cfg.rule.RemoteHost, cfg.rule.RemotePort)
	return listener, nil
}

func (r *Runtime) setApplyError(err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.lastApplyErr = errorString(err)
}

func (r *Runtime) flushLoop() {
	ticker := time.NewTicker(r.options.FlushInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			r.traffic.flush(context.Background())
		case <-r.stopFlush:
			return
		}
	}
}

type ruleRuntimeConfig struct {
	rule        client.ForwardRule
	tunnel      client.Tunnel
	deviceGroup client.DeviceGroup
	policy      *client.ProtocolPolicy
	limit       effectiveSpeedLimit
	listenAddr  string
	fingerprint string
}

type ruleListener struct {
	runtime *Runtime
	cfg     ruleRuntimeConfig
	ln      net.Listener
	stopCh  chan struct{}
	wg      sync.WaitGroup

	activeConns int64
	mu          sync.Mutex
	ipCount     map[string]int
	conns       map[net.Conn]struct{}
}

func (l *ruleListener) acceptLoop() {
	defer l.wg.Done()
	for {
		conn, err := l.ln.Accept()
		if err != nil {
			select {
			case <-l.stopCh:
				return
			default:
				l.runtime.logger.Printf("runtime accept failed rule=%d: %v", l.cfg.rule.ID, err)
				continue
			}
		}
		l.wg.Add(1)
		go func() {
			defer l.wg.Done()
			l.handle(conn)
		}()
	}
}

func (l *ruleListener) handle(conn net.Conn) {
	sourceIP := remoteIP(conn.RemoteAddr())
	if !l.acquire(sourceIP) {
		_ = conn.Close()
		return
	}
	l.trackConn(conn)
	defer l.untrackConn(conn)
	defer l.release(sourceIP)
	defer conn.Close()

	firstPacket, err := readFirstPacket(conn, l.runtime.options.FirstPacketBytes, l.runtime.options.ReadTimeout)
	if err != nil && !isBenignFirstRead(err) {
		l.runtime.logger.Printf("runtime first packet read failed rule=%d source=%s: %v", l.cfg.rule.ID, sourceIP, err)
		return
	}

	result := protocol.Detect(firstPacket, policyFromClient(l.cfg.policy))
	if result.Action != protocol.ActionAllow {
		if result.Action == protocol.ActionBlock {
			l.reportViolation(context.Background(), result, sourceIP)
			return
		}
		go l.reportViolation(context.Background(), result, sourceIP)
	}

	target, err := net.DialTimeout("tcp", net.JoinHostPort(l.cfg.rule.RemoteHost, strconv.Itoa(l.cfg.rule.RemotePort)), 10*time.Second)
	if err != nil {
		l.runtime.logger.Printf("runtime dial failed rule=%d target=%s:%d: %v", l.cfg.rule.ID, l.cfg.rule.RemoteHost, l.cfg.rule.RemotePort, err)
		return
	}
	defer target.Close()

	if len(firstPacket) > 0 {
		if _, err := target.Write(firstPacket); err != nil {
			return
		}
		l.runtime.traffic.add(l.cfg.rule.ID, int64(len(firstPacket)), 0)
	}

	uploadLimiter := newTokenBucket(l.cfg.limit.UploadBps)
	downloadLimiter := newTokenBucket(l.cfg.limit.DownloadBps)
	errc := make(chan error, 2)
	go func() {
		errc <- copyWithLimit(target, conn, uploadLimiter, func(n int64) {
			l.runtime.traffic.add(l.cfg.rule.ID, n, 0)
		})
	}()
	go func() {
		errc <- copyWithLimit(conn, target, downloadLimiter, func(n int64) {
			l.runtime.traffic.add(l.cfg.rule.ID, 0, n)
		})
	}()
	<-errc
	_ = conn.Close()
	_ = target.Close()
	<-errc
}

func (l *ruleListener) acquire(sourceIP string) bool {
	limit := l.cfg.limit
	if limit.MaxConns > 0 && atomic.LoadInt64(&l.activeConns) >= int64(limit.MaxConns) {
		return false
	}

	l.mu.Lock()
	defer l.mu.Unlock()
	if limit.MaxIPs > 0 {
		if l.ipCount[sourceIP] == 0 && len(l.ipCount) >= limit.MaxIPs {
			return false
		}
	}
	l.ipCount[sourceIP]++
	atomic.AddInt64(&l.activeConns, 1)
	return true
}

func (l *ruleListener) release(sourceIP string) {
	l.mu.Lock()
	if count := l.ipCount[sourceIP]; count <= 1 {
		delete(l.ipCount, sourceIP)
	} else {
		l.ipCount[sourceIP] = count - 1
	}
	l.mu.Unlock()
	atomic.AddInt64(&l.activeConns, -1)
}

func (l *ruleListener) trackConn(conn net.Conn) {
	l.mu.Lock()
	l.conns[conn] = struct{}{}
	l.mu.Unlock()
}

func (l *ruleListener) untrackConn(conn net.Conn) {
	l.mu.Lock()
	delete(l.conns, conn)
	l.mu.Unlock()
}

func (l *ruleListener) active() int64 {
	return atomic.LoadInt64(&l.activeConns)
}

func (l *ruleListener) stop() {
	select {
	case <-l.stopCh:
		return
	default:
		close(l.stopCh)
		_ = l.ln.Close()
		l.mu.Lock()
		for conn := range l.conns {
			_ = conn.Close()
		}
		l.mu.Unlock()
		l.wg.Wait()
		l.runtime.logger.Printf("runtime listener stopped rule=%d addr=%s", l.cfg.rule.ID, l.cfg.listenAddr)
	}
}

func (l *ruleListener) reportViolation(ctx context.Context, result protocol.Result, sourceIP string) {
	if l.runtime.reporter == nil || l.cfg.policy == nil {
		return
	}
	detail, _ := json.Marshal(map[string]any{
		"reason":   result.Reason,
		"host":     result.Host,
		"alpn":     result.ALPN,
		"ruleId":   l.cfg.rule.ID,
		"tunnelId": l.cfg.tunnel.ID,
		"source":   "tcp_runtime",
	})
	_, err := l.runtime.reporter.ReportViolation(ctx, client.ViolationReport{
		RuleID:   l.cfg.rule.ID,
		PolicyID: l.cfg.policy.ID,
		Protocol: result.Protocol,
		SourceIP: sourceIP,
		Action:   result.Action,
		Detail:   string(detail),
	})
	if err != nil {
		l.runtime.logger.Printf("runtime violation report failed rule=%d: %v", l.cfg.rule.ID, err)
	}
}

type trafficBuffer struct {
	reporter Reporter
	logger   *log.Logger
	mu       sync.Mutex
	samples  map[uint]client.TrafficSample
}

func newTrafficBuffer(reporter Reporter, logger *log.Logger) *trafficBuffer {
	return &trafficBuffer{reporter: reporter, logger: logger, samples: map[uint]client.TrafficSample{}}
}

func (b *trafficBuffer) add(ruleID uint, inBytes, outBytes int64) {
	if inBytes <= 0 && outBytes <= 0 {
		return
	}
	b.mu.Lock()
	sample := b.samples[ruleID]
	sample.RuleID = ruleID
	sample.InBytes += inBytes
	sample.OutBytes += outBytes
	b.samples[ruleID] = sample
	flushNow := len(b.samples) >= 100
	b.mu.Unlock()
	if flushNow {
		go b.flush(context.Background())
	}
}

func (b *trafficBuffer) flush(ctx context.Context) {
	if b.reporter == nil {
		return
	}
	b.mu.Lock()
	if len(b.samples) == 0 {
		b.mu.Unlock()
		return
	}
	samples := make([]client.TrafficSample, 0, len(b.samples))
	for _, sample := range b.samples {
		samples = append(samples, sample)
	}
	b.samples = map[uint]client.TrafficSample{}
	b.mu.Unlock()

	if _, err := b.reporter.ReportTraffic(ctx, client.TrafficReport{Samples: samples}); err != nil {
		b.logger.Printf("runtime traffic report failed: %v", err)
		b.mu.Lock()
		for _, sample := range samples {
			existing := b.samples[sample.RuleID]
			existing.RuleID = sample.RuleID
			existing.InBytes += sample.InBytes
			existing.OutBytes += sample.OutBytes
			b.samples[sample.RuleID] = existing
		}
		b.mu.Unlock()
	}
}

type effectiveSpeedLimit struct {
	UploadBps   int64
	DownloadBps int64
	MaxConns    int
	MaxIPs      int
}

func effectiveLimit(rule client.ForwardRule, limits []client.SpeedLimit) effectiveSpeedLimit {
	levels := [][]client.SpeedLimit{{}, {}, {}}
	for _, limit := range limits {
		switch {
		case limit.RuleID != nil && *limit.RuleID == rule.ID:
			levels[0] = append(levels[0], limit)
		case limit.RuleID == nil && limit.TunnelID != nil && *limit.TunnelID == rule.TunnelID:
			levels[1] = append(levels[1], limit)
		case limit.RuleID == nil && limit.TunnelID == nil && limit.UserID != nil && *limit.UserID == rule.UserID:
			levels[2] = append(levels[2], limit)
		}
	}
	for _, level := range levels {
		if len(level) > 0 {
			return strictestLimit(level)
		}
	}
	return effectiveSpeedLimit{}
}

func strictestLimit(limits []client.SpeedLimit) effectiveSpeedLimit {
	var out effectiveSpeedLimit
	for _, limit := range limits {
		out.UploadBps = minPositive64(out.UploadBps, limit.UploadBps)
		out.DownloadBps = minPositive64(out.DownloadBps, limit.DownloadBps)
		out.MaxConns = minPositive(out.MaxConns, limit.MaxConns)
		out.MaxIPs = minPositive(out.MaxIPs, limit.MaxIPs)
	}
	return out
}

type tokenBucket struct {
	rate   int64
	mu     sync.Mutex
	tokens float64
	last   time.Time
}

func newTokenBucket(rate int64) *tokenBucket {
	if rate <= 0 {
		return nil
	}
	return &tokenBucket{rate: rate, tokens: float64(rate), last: time.Now()}
}

func (b *tokenBucket) wait(n int) {
	if b == nil || n <= 0 {
		return
	}
	need := float64(n)
	for {
		b.mu.Lock()
		now := time.Now()
		elapsed := now.Sub(b.last).Seconds()
		b.tokens += elapsed * float64(b.rate)
		if b.tokens > float64(b.rate) {
			b.tokens = float64(b.rate)
		}
		b.last = now
		if b.tokens > 0 {
			used := b.tokens
			if used > need {
				used = need
			}
			b.tokens -= used
			need -= used
		}
		if need <= 0 {
			b.mu.Unlock()
			return
		}
		missing := need
		if missing > float64(b.rate) {
			missing = float64(b.rate)
		}
		sleep := time.Duration(missing / float64(b.rate) * float64(time.Second))
		b.mu.Unlock()
		if sleep < time.Millisecond {
			sleep = time.Millisecond
		}
		time.Sleep(sleep)
	}
}

func copyWithLimit(dst net.Conn, src net.Conn, limiter *tokenBucket, count func(int64)) error {
	buf := make([]byte, 32*1024)
	for {
		n, readErr := src.Read(buf)
		if n > 0 {
			limiter.wait(n)
			if _, err := writeFull(dst, buf[:n]); err != nil {
				return err
			}
			count(int64(n))
		}
		if readErr != nil {
			if errors.Is(readErr, io.EOF) {
				return nil
			}
			return readErr
		}
	}
}

func writeFull(dst net.Conn, data []byte) (int, error) {
	total := 0
	for len(data) > 0 {
		n, err := dst.Write(data)
		total += n
		data = data[n:]
		if err != nil {
			return total, err
		}
	}
	return total, nil
}

func readFirstPacket(conn net.Conn, maxBytes int, timeout time.Duration) ([]byte, error) {
	if maxBytes <= 0 {
		maxBytes = defaultFirstPacketBytes
	}
	if timeout > 0 {
		_ = conn.SetReadDeadline(time.Now().Add(timeout))
		defer conn.SetReadDeadline(time.Time{})
	}
	buf := make([]byte, maxBytes)
	n, err := conn.Read(buf)
	if n > 0 {
		return buf[:n], nil
	}
	if err != nil {
		return nil, err
	}
	return nil, nil
}

func isBenignFirstRead(err error) bool {
	if err == nil || errors.Is(err, io.EOF) {
		return true
	}
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
}

func skipRule(rule client.ForwardRule) bool {
	status := strings.ToLower(strings.TrimSpace(rule.Status))
	if status == "paused" || status == "disabled" || status == "deleted" {
		return true
	}
	return rule.ListenPort <= 0 || rule.RemoteHost == "" || rule.RemotePort <= 0
}

func isTCPRule(rule client.ForwardRule) bool {
	switch strings.ToLower(strings.TrimSpace(rule.Protocol)) {
	case "tcp", "tcp_udp", "":
		return true
	default:
		return false
	}
}

func effectivePolicy(rule client.ForwardRule, tunnel client.Tunnel, group client.DeviceGroup, policies map[uint]client.ProtocolPolicy) *client.ProtocolPolicy {
	var id *uint
	switch {
	case rule.ProtocolPolicyID != nil:
		id = rule.ProtocolPolicyID
	case tunnel.ProtocolPolicyID != nil:
		id = tunnel.ProtocolPolicyID
	case group.ProtocolPolicyID != nil:
		id = group.ProtocolPolicyID
	}
	if id == nil {
		return nil
	}
	policy, ok := policies[*id]
	if !ok {
		return nil
	}
	return &policy
}

func policyFromClient(policy *client.ProtocolPolicy) protocol.Policy {
	if policy == nil {
		return protocol.Policy{}
	}
	return protocol.Policy{
		Mode:                 policy.Mode,
		BlockTLS:             policy.BlockTLS,
		BlockQUIC:            policy.BlockQUIC,
		AllowPlainTCPOnly:    policy.AllowPlainTCPOnly,
		AllowHTTPOnly:        policy.AllowHTTPOnly,
		BlockProxyLike:       policy.BlockProxyLike,
		BlockEncryptedTunnel: policy.BlockEncryptedTunnel,
	}
}

func fingerprint(rule client.ForwardRule, tunnel client.Tunnel, group client.DeviceGroup, policy *client.ProtocolPolicy, limit effectiveSpeedLimit, listenHost string) string {
	value := struct {
		Rule       client.ForwardRule
		Tunnel     client.Tunnel
		GroupID    uint
		Policy     *client.ProtocolPolicy
		Limit      effectiveSpeedLimit
		ListenHost string
	}{rule, tunnel, group.ID, policy, limit, listenHost}
	content, _ := json.Marshal(value)
	return string(content)
}

func remoteIP(addr net.Addr) string {
	if addr == nil {
		return ""
	}
	host, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		return addr.String()
	}
	return host
}

func minPositive(current, candidate int) int {
	if candidate <= 0 {
		return current
	}
	if current <= 0 || candidate < current {
		return candidate
	}
	return current
}

func minPositive64(current, candidate int64) int64 {
	if candidate <= 0 {
		return current
	}
	if current <= 0 || candidate < current {
		return candidate
	}
	return current
}

func errorString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}
