package runtime

import (
	"bytes"
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
	"dusheng-panel/apps/agent/internal/dpi"
	"dusheng-panel/apps/agent/internal/protocol"
)

const (
	defaultFirstPacketBytes      = 2048
	defaultReadTimeout           = time.Second
	defaultFlushInterval         = 15 * time.Second
	defaultUDPIdleTimeout        = 60 * time.Second
	defaultTrafficFlushSize      = 100
	defaultMaxTrafficSamples     = 1000
	defaultMaxTrafficBytes       = int64(1 << 40)
	defaultMaxTrafficFailures    = 5
	defaultMaxUDPSessionsPerRule = 4096
	defaultDPITimeout            = 300 * time.Millisecond
	defaultInspectionIdleTimeout = 50 * time.Millisecond
	defaultUDPInspectionPackets  = 12
	defaultDPIInspectionPackets  = 12
	defaultDPICloseQueueSize     = 1024
	maxUDPPacketBytes            = 64 * 1024
)

var errDPIBlocked = errors.New("connection blocked by DPI policy")

type Reporter interface {
	ReportTraffic(context.Context, client.TrafficReport) (client.AcceptedResponse, error)
	ReportViolation(context.Context, client.ViolationReport) (client.ProtocolViolation, error)
}

type Options struct {
	ListenHost            string
	FirstPacketBytes      int
	ReadTimeout           time.Duration
	FlushInterval         time.Duration
	UDPIdleTimeout        time.Duration
	MaxTrafficSamples     int
	MaxTrafficBytes       int64
	MaxTrafficFailures    int
	MaxUDPSessionsPerRule int
	DPIAddress            string
	DPITimeout            time.Duration
}

type Runtime struct {
	reporter Reporter
	logger   *log.Logger
	options  Options
	traffic  *trafficBuffer
	dpi      *dpi.Client

	mu           sync.Mutex
	listeners    map[listenerKey]managedListener
	trackers     map[uint]*limitTracker
	running      bool
	lastApplyErr string
	closed       bool
	stopFlush    chan struct{}
	dpiClose     chan string

	acceptErrors        int64
	dialErrors          int64
	udpReadErrors       int64
	udpDialErrors       int64
	udpRejectedSessions int64
	upstreamWriteErrors int64
	udpCleanedSessions  int64
	dpiErrors           int64
	dpiCloseDropped     int64
	nextDPIFlowID       uint64
}

type listenerKey struct {
	RuleID  uint
	Network string
}

type managedListener interface {
	stop()
	active() int64
	network() string
	fingerprint() string
	bind() string
	update(ruleRuntimeConfig)
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
	if options.UDPIdleTimeout <= 0 {
		options.UDPIdleTimeout = defaultUDPIdleTimeout
	}
	if options.MaxTrafficSamples <= 0 {
		options.MaxTrafficSamples = defaultMaxTrafficSamples
	}
	if options.MaxTrafficBytes <= 0 {
		options.MaxTrafficBytes = defaultMaxTrafficBytes
	}
	if options.MaxTrafficFailures <= 0 {
		options.MaxTrafficFailures = defaultMaxTrafficFailures
	}
	if options.MaxUDPSessionsPerRule <= 0 {
		options.MaxUDPSessionsPerRule = defaultMaxUDPSessionsPerRule
	}
	if options.DPITimeout <= 0 {
		options.DPITimeout = defaultDPITimeout
	}
	rt := &Runtime{
		reporter:  reporter,
		logger:    logger,
		options:   options,
		traffic:   newTrafficBuffer(reporter, logger, options),
		dpi:       dpi.New(options.DPIAddress, options.DPITimeout),
		listeners: map[listenerKey]managedListener{},
		trackers:  map[uint]*limitTracker{},
		stopFlush: make(chan struct{}),
		dpiClose:  make(chan string, defaultDPICloseQueueSize),
	}
	if rt.dpi != nil && rt.dpi.Enabled() {
		go rt.probeDPI()
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
	next := make(map[listenerKey]managedListener, len(desired))
	nextTrackers := make(map[uint]*limitTracker)
	var toStop []managedListener
	var startErr error

	for key, desiredCfg := range desired {
		tracker := nextTrackers[desiredCfg.rule.ID]
		if tracker == nil {
			if existing := r.trackers[desiredCfg.rule.ID]; existing != nil && existing.sameLimit(desiredCfg.limit) {
				tracker = existing
			} else {
				tracker = newLimitTracker(desiredCfg.limit)
			}
			nextTrackers[desiredCfg.rule.ID] = tracker
		}
		desiredCfg.tracker = tracker

		if existing := current[key]; existing != nil && existing.bind() == listenerBind(desiredCfg) {
			existing.update(desiredCfg)
			next[key] = existing
			continue
		}
		if existing := current[key]; existing != nil {
			toStop = append(toStop, existing)
		}
		listener, err := r.startListener(ctx, desiredCfg)
		if err != nil {
			startErr = errors.Join(startErr, err)
			continue
		}
		next[key] = listener
	}
	for key, existing := range current {
		if _, ok := desired[key]; !ok {
			toStop = append(toStop, existing)
		}
	}
	r.listeners = next
	r.trackers = nextTrackers
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
	var activeTCP, activeUDP int64
	var tcpListeners, udpListeners int
	for _, listener := range r.listeners {
		switch listener.network() {
		case "udp":
			udpListeners++
			activeUDP += listener.active()
		default:
			tcpListeners++
			activeTCP += listener.active()
		}
	}
	return map[string]any{
		"running":           r.running && !r.closed,
		"listeners":         len(r.listeners),
		"tcpListeners":      tcpListeners,
		"udpListeners":      udpListeners,
		"activeConnections": activeTCP + activeUDP,
		"activeUDPSessions": activeUDP,
		"lastApplyError":    r.lastApplyErr,
		"trafficBuffer":     r.traffic.status(),
		"listenerErrors": map[string]int64{
			"accept":              atomic.LoadInt64(&r.acceptErrors),
			"dial":                atomic.LoadInt64(&r.dialErrors),
			"udpRead":             atomic.LoadInt64(&r.udpReadErrors),
			"udpDial":             atomic.LoadInt64(&r.udpDialErrors),
			"udpRejectedSessions": atomic.LoadInt64(&r.udpRejectedSessions),
			"upstreamWrite":       atomic.LoadInt64(&r.upstreamWriteErrors),
			"udpCleanedSessions":  atomic.LoadInt64(&r.udpCleanedSessions),
			"dpi":                 atomic.LoadInt64(&r.dpiErrors),
			"dpiCloseDropped":     atomic.LoadInt64(&r.dpiCloseDropped),
		},
		"dpiEnabled": r.dpi != nil && r.dpi.Enabled(),
		"dpiStatus":  r.dpi.Status(),
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
	listeners := make([]managedListener, 0, len(r.listeners))
	for _, listener := range r.listeners {
		listeners = append(listeners, listener)
	}
	r.listeners = map[listenerKey]managedListener{}
	r.trackers = map[uint]*limitTracker{}
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

func (r *Runtime) desiredListeners(cfg client.AgentConfig) (map[listenerKey]ruleRuntimeConfig, error) {
	tunnels := map[uint]client.Tunnel{}
	for _, tunnel := range cfg.Tunnels {
		tunnels[tunnel.ID] = tunnel
	}
	policies := map[uint]client.ProtocolPolicy{}
	for _, policy := range cfg.ProtocolPolicies {
		policies[policy.ID] = policy
	}

	desired := map[listenerKey]ruleRuntimeConfig{}
	for _, rule := range cfg.ForwardRules {
		if skipRule(rule) || (!isTCPRule(rule) && !isUDPRule(rule)) {
			continue
		}
		tunnel, ok := tunnels[rule.TunnelID]
		if !ok {
			return nil, fmt.Errorf("rule %d references missing tunnel %d", rule.ID, rule.TunnelID)
		}
		policy := effectivePolicy(rule, tunnel, cfg.DeviceGroup, policies)
		limit := effectiveLimit(rule, cfg.SpeedLimits)
		listenHost := r.listenHost(cfg.DeviceGroup)
		base := ruleRuntimeConfig{
			rule:        rule,
			tunnel:      tunnel,
			deviceGroup: cfg.DeviceGroup,
			policy:      policy,
			limit:       limit,
			listenAddr:  net.JoinHostPort(listenHost, strconv.Itoa(rule.ListenPort)),
		}
		if isTCPRule(rule) {
			cfg := base
			cfg.network = "tcp"
			cfg.fingerprint = fingerprint(rule, tunnel, cfg.deviceGroup, policy, limit, listenHost, cfg.network)
			desired[listenerKey{RuleID: rule.ID, Network: cfg.network}] = cfg
		}
		if isUDPRule(rule) {
			cfg := base
			cfg.network = "udp"
			cfg.fingerprint = fingerprint(rule, tunnel, cfg.deviceGroup, policy, limit, listenHost, cfg.network)
			desired[listenerKey{RuleID: rule.ID, Network: cfg.network}] = cfg
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

func (r *Runtime) startListener(ctx context.Context, cfg ruleRuntimeConfig) (managedListener, error) {
	if cfg.network == "udp" {
		return r.startUDPListener(ctx, cfg)
	}
	ln, err := (&net.ListenConfig{}).Listen(ctx, "tcp", cfg.listenAddr)
	if err != nil {
		return nil, fmt.Errorf("listen rule %d on %s: %w", cfg.rule.ID, cfg.listenAddr, err)
	}
	listener := &ruleListener{
		runtime: r,
		cfg:     cfg,
		ln:      ln,
		stopCh:  make(chan struct{}),
		conns:   map[net.Conn]struct{}{},
	}
	listener.wg.Add(1)
	go listener.acceptLoop()
	r.logger.Printf("runtime tcp listener started rule=%d addr=%s target=%s:%d", cfg.rule.ID, cfg.listenAddr, cfg.rule.RemoteHost, cfg.rule.RemotePort)
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
	dpiTicker := time.NewTicker(30 * time.Second)
	defer dpiTicker.Stop()
	for {
		select {
		case <-ticker.C:
			r.traffic.flush(context.Background())
		case <-dpiTicker.C:
			r.probeDPI()
		case flowID := <-r.dpiClose:
			r.closeDPIFlow(flowID)
		case <-r.stopFlush:
			return
		}
	}
}

func (r *Runtime) closeDPIFlow(flowID string) {
	if r.dpi == nil || !r.dpi.Enabled() {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), r.options.DPITimeout)
	defer cancel()
	if err := r.dpi.CloseFlow(ctx, flowID); err != nil {
		atomic.AddInt64(&r.dpiErrors, 1)
	}
}

func (r *Runtime) probeDPI() {
	if r.dpi == nil || !r.dpi.Enabled() {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), r.options.DPITimeout)
	defer cancel()
	if err := r.dpi.Probe(ctx); err != nil {
		atomic.AddInt64(&r.dpiErrors, 1)
	}
}

type ruleRuntimeConfig struct {
	rule        client.ForwardRule
	tunnel      client.Tunnel
	deviceGroup client.DeviceGroup
	policy      *client.ProtocolPolicy
	limit       effectiveSpeedLimit
	tracker     *limitTracker
	network     string
	listenAddr  string
	fingerprint string
}

type dpiFlow struct {
	runtime         *Runtime
	cfg             ruleRuntimeConfig
	id              string
	network         string
	sourceIP        string
	destinationIP   string
	sourcePort      int
	destinationPort int

	mu            sync.Mutex
	packets       int
	final         bool
	finalResult   protocol.Result
	violationRank int
	closed        bool
}

func (r *Runtime) newDPIFlow(cfg ruleRuntimeConfig, network string, sourceAddr net.Addr, destination string, destinationPort int) *dpiFlow {
	sequence := atomic.AddUint64(&r.nextDPIFlowID, 1)
	sourceIP, sourcePort := addrIPPort(sourceAddr)
	return &dpiFlow{
		runtime: r, cfg: cfg, id: fmt.Sprintf("%d-%s-%d", cfg.rule.ID, network, sequence), network: network,
		sourceIP: sourceIP, destinationIP: destination, sourcePort: sourcePort, destinationPort: destinationPort,
	}
}

func (f *dpiFlow) inspect(ctx context.Context, packet []byte, direction string) protocol.Result {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.final {
		return f.finalResult
	}
	if len(packet) == 0 {
		return protocol.Detect(packet, policyFromClient(f.cfg.policy, f.network))
	}
	f.packets++
	result, final := f.runtime.detectProtocolFlow(ctx, packet, f.cfg, dpi.ClassifyRequest{
		Network: f.network, FlowID: f.id, Direction: direction,
		SourceIP: f.sourceIP, DestinationIP: f.destinationIP,
		SourcePort: f.sourcePort, DestinationPort: f.destinationPort,
		TimestampMs: time.Now().UnixMilli(),
	})
	if final || f.packets >= defaultDPIInspectionPackets {
		f.final = true
		f.finalResult = result
	}
	return result
}

func (f *dpiFlow) markViolation(action string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	rank := protocolActionRank(action)
	if rank <= f.violationRank {
		return false
	}
	f.violationRank = rank
	return true
}

func protocolActionRank(action string) int {
	switch action {
	case protocol.ActionBlock:
		return 4
	case protocol.ActionLimit:
		return 3
	case protocol.ActionAlert:
		return 2
	case protocol.ActionObserve:
		return 1
	default:
		return 0
	}
}

func (f *dpiFlow) close() {
	f.mu.Lock()
	if f.closed {
		f.mu.Unlock()
		return
	}
	f.closed = true
	f.mu.Unlock()
	if f.runtime.dpi == nil || !f.runtime.dpi.Enabled() {
		return
	}
	select {
	case f.runtime.dpiClose <- f.id:
	default:
		atomic.AddInt64(&f.runtime.dpiCloseDropped, 1)
	}
}

func addrIPPort(addr net.Addr) (string, int) {
	if addr == nil {
		return "", 0
	}
	host, portText, err := net.SplitHostPort(addr.String())
	if err != nil {
		return remoteIP(addr), 0
	}
	port, _ := strconv.Atoi(portText)
	return strings.Trim(host, "[]"), port
}

type ruleListener struct {
	runtime *Runtime
	cfgMu   sync.RWMutex
	cfg     ruleRuntimeConfig
	ln      net.Listener
	stopCh  chan struct{}
	wg      sync.WaitGroup

	activeConns int64
	mu          sync.Mutex
	conns       map[net.Conn]struct{}
}

func (l *ruleListener) config() ruleRuntimeConfig {
	l.cfgMu.RLock()
	defer l.cfgMu.RUnlock()
	return l.cfg
}

func (l *ruleListener) update(cfg ruleRuntimeConfig) {
	old := l.config()
	l.cfgMu.Lock()
	l.cfg = cfg
	l.cfgMu.Unlock()
	if old.fingerprint != "" && old.fingerprint != cfg.fingerprint {
		l.closeActiveConns()
	}
}

func (l *ruleListener) bind() string {
	cfg := l.config()
	return listenerBind(cfg)
}

func (l *ruleListener) closeActiveConns() {
	l.mu.Lock()
	for conn := range l.conns {
		_ = conn.Close()
	}
	l.mu.Unlock()
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
				atomic.AddInt64(&l.runtime.acceptErrors, 1)
				cfg := l.config()
				l.runtime.logger.Printf("runtime accept failed rule=%d: %v", cfg.rule.ID, err)
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
	cfg := l.config()
	sourceIP := remoteIP(conn.RemoteAddr())
	if !l.acquireConfig(cfg, sourceIP) {
		_ = conn.Close()
		return
	}
	l.trackConn(conn)
	defer l.untrackConn(conn)
	defer l.releaseConfig(cfg, sourceIP)
	defer conn.Close()
	dpiFlow := l.runtime.newDPIFlow(cfg, "tcp", conn.RemoteAddr(), cfg.rule.RemoteHost, cfg.rule.RemotePort)
	defer dpiFlow.close()

	firstPacket, err := readFirstPacket(conn, l.runtime.options.FirstPacketBytes, l.runtime.options.ReadTimeout)
	if err != nil && !isBenignFirstRead(err) {
		l.runtime.logger.Printf("runtime first packet read failed rule=%d source=%s: %v", cfg.rule.ID, sourceIP, err)
		return
	}

	result := dpiFlow.inspect(context.Background(), firstPacket, "client_to_server")
	if result.Action != protocol.ActionAllow {
		if result.Action == protocol.ActionBlock {
			if dpiFlow.markViolation(result.Action) {
				l.reportViolation(context.Background(), cfg, result, sourceIP)
			}
			return
		}
		if dpiFlow.markViolation(result.Action) {
			go l.reportViolation(context.Background(), cfg, result, sourceIP)
		}
	}

	target, err := net.DialTimeout("tcp", net.JoinHostPort(cfg.rule.RemoteHost, strconv.Itoa(cfg.rule.RemotePort)), 10*time.Second)
	if err != nil {
		atomic.AddInt64(&l.runtime.dialErrors, 1)
		l.runtime.logger.Printf("runtime dial failed rule=%d target=%s:%d: %v", cfg.rule.ID, cfg.rule.RemoteHost, cfg.rule.RemotePort, err)
		return
	}
	defer target.Close()

	var upstreamFirst []byte
	if shouldProbeServerFirstSSH(cfg, firstPacket) {
		upstreamFirst, err = readFirstPacket(target, l.runtime.options.FirstPacketBytes, minDuration(300*time.Millisecond, l.runtime.options.ReadTimeout))
		if err != nil && !isBenignFirstRead(err) {
			l.runtime.logger.Printf("runtime upstream first packet read failed rule=%d source=%s: %v", cfg.rule.ID, sourceIP, err)
			return
		}
		if len(upstreamFirst) > 0 {
			upstreamResult := dpiFlow.inspect(context.Background(), upstreamFirst, "server_to_client")
			if upstreamResult.Action != protocol.ActionAllow {
				if upstreamResult.Action == protocol.ActionBlock {
					if dpiFlow.markViolation(upstreamResult.Action) {
						l.reportViolation(context.Background(), cfg, upstreamResult, sourceIP)
					}
					return
				}
				if dpiFlow.markViolation(upstreamResult.Action) {
					go l.reportViolation(context.Background(), cfg, upstreamResult, sourceIP)
				}
			}
		}
	}

	if len(firstPacket) > 0 {
		if _, err := target.Write(firstPacket); err != nil {
			atomic.AddInt64(&l.runtime.upstreamWriteErrors, 1)
			return
		}
		l.runtime.traffic.add(cfg.rule.ID, int64(len(firstPacket)), 0)
	}
	if len(upstreamFirst) > 0 {
		if _, err := conn.Write(upstreamFirst); err != nil {
			atomic.AddInt64(&l.runtime.upstreamWriteErrors, 1)
			return
		}
		l.runtime.traffic.add(cfg.rule.ID, 0, int64(len(upstreamFirst)))
	}

	uploadLimiter := newTokenBucket(cfg.limit.UploadBps)
	downloadLimiter := newTokenBucket(cfg.limit.DownloadBps)
	errc := make(chan error, 2)
	go func() {
		err := copyWithLimit(target, conn, uploadLimiter, func(packet []byte) error {
			result := dpiFlow.inspect(context.Background(), packet, "client_to_server")
			if result.Action == protocol.ActionAllow {
				return nil
			}
			if dpiFlow.markViolation(result.Action) {
				go l.reportViolation(context.Background(), cfg, result, sourceIP)
			}
			if result.Action == protocol.ActionBlock {
				return errDPIBlocked
			}
			return nil
		}, func(n int64) {
			l.runtime.traffic.add(cfg.rule.ID, n, 0)
		})
		if err != nil && !errors.Is(err, net.ErrClosed) && !errors.Is(err, errDPIBlocked) {
			atomic.AddInt64(&l.runtime.upstreamWriteErrors, 1)
		}
		errc <- err
	}()
	go func() {
		err := copyWithLimit(conn, target, downloadLimiter, func(packet []byte) error {
			result := dpiFlow.inspect(context.Background(), packet, "server_to_client")
			if result.Action == protocol.ActionAllow {
				return nil
			}
			if dpiFlow.markViolation(result.Action) {
				go l.reportViolation(context.Background(), cfg, result, sourceIP)
			}
			if result.Action == protocol.ActionBlock {
				return errDPIBlocked
			}
			return nil
		}, func(n int64) {
			l.runtime.traffic.add(cfg.rule.ID, 0, n)
		})
		if err != nil && !errors.Is(err, net.ErrClosed) && !errors.Is(err, errDPIBlocked) {
			atomic.AddInt64(&l.runtime.upstreamWriteErrors, 1)
		}
		errc <- err
	}()
	<-errc
	_ = conn.Close()
	_ = target.Close()
	<-errc
}

func (l *ruleListener) acquire(sourceIP string) bool {
	return l.acquireConfig(l.config(), sourceIP)
}

func (l *ruleListener) acquireConfig(cfg ruleRuntimeConfig, sourceIP string) bool {
	if cfg.tracker != nil && !cfg.tracker.acquire(sourceIP) {
		return false
	}
	atomic.AddInt64(&l.activeConns, 1)
	return true
}

func (l *ruleListener) release(sourceIP string) {
	l.releaseConfig(l.config(), sourceIP)
}

func (l *ruleListener) releaseConfig(cfg ruleRuntimeConfig, sourceIP string) {
	atomic.AddInt64(&l.activeConns, -1)
	if cfg.tracker != nil {
		cfg.tracker.release(sourceIP)
	}
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

func (l *ruleListener) network() string {
	return "tcp"
}

func (l *ruleListener) fingerprint() string {
	cfg := l.config()
	return cfg.fingerprint
}

func (l *ruleListener) stop() {
	select {
	case <-l.stopCh:
		return
	default:
		close(l.stopCh)
		_ = l.ln.Close()
		l.closeActiveConns()
		l.wg.Wait()
		cfg := l.config()
		l.runtime.logger.Printf("runtime listener stopped rule=%d addr=%s", cfg.rule.ID, cfg.listenAddr)
	}
}

func (l *ruleListener) reportViolation(ctx context.Context, cfg ruleRuntimeConfig, result protocol.Result, sourceIP string) {
	if l.runtime.reporter == nil || cfg.policy == nil {
		return
	}
	detail, _ := json.Marshal(map[string]any{
		"reason":       result.Reason,
		"host":         result.Host,
		"alpn":         result.ALPN,
		"ruleId":       cfg.rule.ID,
		"tunnelId":     cfg.tunnel.ID,
		"source":       "tcp_runtime",
		"detector":     result.Source,
		"matchedRule":  result.MatchedRule,
		"confidence":   result.Confidence,
		"riskScore":    result.RiskScore,
		"riskLevel":    result.RiskLevel,
		"tags":         result.Tags,
		"ndpiProtocol": result.NDPIProtocol,
		"ndpiCategory": result.NDPICategory,
	})
	_, err := l.runtime.reporter.ReportViolation(ctx, client.ViolationReport{
		RuleID:   cfg.rule.ID,
		PolicyID: cfg.policy.ID,
		Protocol: result.Protocol,
		SourceIP: sourceIP,
		Action:   result.Action,
		Detail:   string(detail),
	})
	if err != nil {
		l.runtime.logger.Printf("runtime violation report failed rule=%d: %v", cfg.rule.ID, err)
	}
}

func (r *Runtime) startUDPListener(ctx context.Context, cfg ruleRuntimeConfig) (managedListener, error) {
	conn, err := (&net.ListenConfig{}).ListenPacket(ctx, "udp", cfg.listenAddr)
	if err != nil {
		return nil, fmt.Errorf("listen udp rule %d on %s: %w", cfg.rule.ID, cfg.listenAddr, err)
	}
	listener := &udpListener{
		runtime:  r,
		cfg:      cfg,
		conn:     conn,
		stopCh:   make(chan struct{}),
		sessions: map[string]*udpSession{},
	}
	listener.wg.Add(2)
	go listener.readLoop()
	go listener.cleanupLoop()
	r.logger.Printf("runtime udp listener started rule=%d addr=%s target=%s:%d", cfg.rule.ID, cfg.listenAddr, cfg.rule.RemoteHost, cfg.rule.RemotePort)
	return listener, nil
}

type udpListener struct {
	runtime *Runtime
	cfgMu   sync.RWMutex
	cfg     ruleRuntimeConfig
	conn    net.PacketConn
	stopCh  chan struct{}
	wg      sync.WaitGroup

	mu       sync.Mutex
	sessions map[string]*udpSession
}

type udpSession struct {
	listener         *udpListener
	cfg              ruleRuntimeConfig
	key              string
	clientAddr       net.Addr
	sourceIP         string
	upstream         net.Conn
	dpiFlow          *dpiFlow
	uploadLimiter    *tokenBucket
	downloadLimiter  *tokenBucket
	lastSeen         int64
	inspectedPackets int
	closeOnce        sync.Once
}

func (l *udpListener) config() ruleRuntimeConfig {
	l.cfgMu.RLock()
	defer l.cfgMu.RUnlock()
	return l.cfg
}

func (l *udpListener) update(cfg ruleRuntimeConfig) {
	old := l.config()
	l.cfgMu.Lock()
	l.cfg = cfg
	l.cfgMu.Unlock()
	if old.fingerprint != "" && old.fingerprint != cfg.fingerprint {
		l.closeAllSessions()
	}
}

func (l *udpListener) bind() string {
	cfg := l.config()
	return listenerBind(cfg)
}

func (l *udpListener) readLoop() {
	defer l.wg.Done()
	buf := make([]byte, maxUDPPacketBytes)
	for {
		n, addr, err := l.conn.ReadFrom(buf)
		if err != nil {
			select {
			case <-l.stopCh:
				return
			default:
				atomic.AddInt64(&l.runtime.udpReadErrors, 1)
				cfg := l.config()
				l.runtime.logger.Printf("runtime udp read failed rule=%d: %v", cfg.rule.ID, err)
				continue
			}
		}
		packet := append([]byte(nil), buf[:n]...)
		l.handleDatagram(addr, packet)
	}
}

func (l *udpListener) cleanupLoop() {
	defer l.wg.Done()
	interval := l.runtime.options.UDPIdleTimeout / 2
	if interval <= 0 {
		interval = time.Second
	}
	if interval > 30*time.Second {
		interval = 30 * time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			l.closeIdleSessions(time.Now())
		case <-l.stopCh:
			return
		}
	}
}

func (l *udpListener) handleDatagram(clientAddr net.Addr, packet []byte) {
	cfg := l.config()
	key := clientAddr.String()
	l.mu.Lock()
	session := l.sessions[key]
	if session == nil && l.runtime.options.MaxUDPSessionsPerRule > 0 && len(l.sessions) >= l.runtime.options.MaxUDPSessionsPerRule {
		l.mu.Unlock()
		atomic.AddInt64(&l.runtime.udpRejectedSessions, 1)
		l.runtime.logger.Printf("runtime udp session rejected by runtime cap rule=%d client=%s", cfg.rule.ID, clientAddr.String())
		return
	}
	l.mu.Unlock()
	if session != nil {
		if !session.inspectPacket(packet) {
			return
		}
		session.forwardClientPacket(packet)
		return
	}

	sourceIP := remoteIP(clientAddr)
	dpiFlow := l.runtime.newDPIFlow(cfg, "udp", clientAddr, cfg.rule.RemoteHost, cfg.rule.RemotePort)
	result := dpiFlow.inspect(context.Background(), packet, "client_to_server")
	if result.Action != protocol.ActionAllow {
		if result.Action == protocol.ActionBlock {
			if dpiFlow.markViolation(result.Action) {
				l.reportViolation(context.Background(), cfg, result, sourceIP, clientAddr.String())
			}
			dpiFlow.close()
			return
		}
		if dpiFlow.markViolation(result.Action) {
			go l.reportViolation(context.Background(), cfg, result, sourceIP, clientAddr.String())
		}
	}

	if cfg.tracker != nil && !cfg.tracker.acquire(sourceIP) {
		dpiFlow.close()
		atomic.AddInt64(&l.runtime.udpRejectedSessions, 1)
		l.runtime.logger.Printf("runtime udp session rejected by limit rule=%d client=%s", cfg.rule.ID, clientAddr.String())
		return
	}
	upstream, err := net.DialTimeout("udp", net.JoinHostPort(cfg.rule.RemoteHost, strconv.Itoa(cfg.rule.RemotePort)), 10*time.Second)
	if err != nil {
		dpiFlow.close()
		if cfg.tracker != nil {
			cfg.tracker.release(sourceIP)
		}
		atomic.AddInt64(&l.runtime.udpDialErrors, 1)
		l.runtime.logger.Printf("runtime udp dial failed rule=%d target=%s:%d: %v", cfg.rule.ID, cfg.rule.RemoteHost, cfg.rule.RemotePort, err)
		return
	}
	session = &udpSession{
		listener:         l,
		cfg:              cfg,
		key:              key,
		clientAddr:       clientAddr,
		sourceIP:         sourceIP,
		upstream:         upstream,
		dpiFlow:          dpiFlow,
		uploadLimiter:    newTokenBucket(cfg.limit.UploadBps),
		downloadLimiter:  newTokenBucket(cfg.limit.DownloadBps),
		lastSeen:         time.Now().UnixNano(),
		inspectedPackets: 1,
	}

	l.mu.Lock()
	if existing := l.sessions[key]; existing != nil {
		l.mu.Unlock()
		session.close()
		if cfg.tracker != nil {
			cfg.tracker.release(sourceIP)
		}
		if !existing.inspectPacket(packet) {
			return
		}
		existing.forwardClientPacket(packet)
		return
	}
	if l.runtime.options.MaxUDPSessionsPerRule > 0 && len(l.sessions) >= l.runtime.options.MaxUDPSessionsPerRule {
		l.mu.Unlock()
		session.close()
		if cfg.tracker != nil {
			cfg.tracker.release(sourceIP)
		}
		atomic.AddInt64(&l.runtime.udpRejectedSessions, 1)
		l.runtime.logger.Printf("runtime udp session rejected by runtime cap rule=%d client=%s", cfg.rule.ID, clientAddr.String())
		return
	}
	l.sessions[key] = session
	l.mu.Unlock()

	l.wg.Add(1)
	go session.readLoop()
	session.forwardClientPacket(packet)
}

func (l *udpListener) closeIdleSessions(now time.Time) {
	deadline := now.Add(-l.runtime.options.UDPIdleTimeout).UnixNano()
	var stale []*udpSession
	l.mu.Lock()
	for key, session := range l.sessions {
		if session.lastSeenAt() <= deadline {
			delete(l.sessions, key)
			stale = append(stale, session)
		}
	}
	l.mu.Unlock()
	for _, session := range stale {
		session.close()
		if session.cfg.tracker != nil {
			session.cfg.tracker.release(session.sourceIP)
		}
	}
	if len(stale) > 0 {
		atomic.AddInt64(&l.runtime.udpCleanedSessions, int64(len(stale)))
	}
}

func (l *udpListener) removeSession(session *udpSession) {
	l.mu.Lock()
	if existing := l.sessions[session.key]; existing == session {
		delete(l.sessions, session.key)
		l.mu.Unlock()
		session.close()
		if session.cfg.tracker != nil {
			session.cfg.tracker.release(session.sourceIP)
		}
		return
	}
	l.mu.Unlock()
}

func (l *udpListener) reportViolation(ctx context.Context, cfg ruleRuntimeConfig, result protocol.Result, sourceIP, clientAddr string) {
	if l.runtime.reporter == nil || cfg.policy == nil {
		return
	}
	detail, _ := json.Marshal(map[string]any{
		"reason":       result.Reason,
		"host":         result.Host,
		"alpn":         result.ALPN,
		"protocol":     result.Protocol,
		"ruleId":       cfg.rule.ID,
		"tunnelId":     cfg.tunnel.ID,
		"clientAddr":   clientAddr,
		"source":       "udp_runtime",
		"detector":     result.Source,
		"matchedRule":  result.MatchedRule,
		"confidence":   result.Confidence,
		"riskScore":    result.RiskScore,
		"riskLevel":    result.RiskLevel,
		"tags":         result.Tags,
		"ndpiProtocol": result.NDPIProtocol,
		"ndpiCategory": result.NDPICategory,
	})
	_, err := l.runtime.reporter.ReportViolation(ctx, client.ViolationReport{
		RuleID:   cfg.rule.ID,
		PolicyID: cfg.policy.ID,
		Protocol: result.Protocol,
		SourceIP: sourceIP,
		Action:   result.Action,
		Detail:   string(detail),
	})
	if err != nil {
		l.runtime.logger.Printf("runtime udp violation report failed rule=%d: %v", cfg.rule.ID, err)
	}
}

func (l *udpListener) active() int64 {
	l.mu.Lock()
	defer l.mu.Unlock()
	return int64(len(l.sessions))
}

func (l *udpListener) network() string {
	return "udp"
}

func (l *udpListener) fingerprint() string {
	cfg := l.config()
	return cfg.fingerprint
}

func (l *udpListener) closeAllSessions() {
	l.mu.Lock()
	sessions := make([]*udpSession, 0, len(l.sessions))
	for key, session := range l.sessions {
		delete(l.sessions, key)
		sessions = append(sessions, session)
	}
	l.mu.Unlock()
	for _, session := range sessions {
		session.close()
		if session.cfg.tracker != nil {
			session.cfg.tracker.release(session.sourceIP)
		}
	}
}

func (l *udpListener) stop() {
	select {
	case <-l.stopCh:
		return
	default:
		close(l.stopCh)
		_ = l.conn.Close()
		l.closeAllSessions()
		l.wg.Wait()
		cfg := l.config()
		l.runtime.logger.Printf("runtime udp listener stopped rule=%d addr=%s", cfg.rule.ID, cfg.listenAddr)
	}
}

func (s *udpSession) readLoop() {
	defer s.listener.wg.Done()
	defer s.listener.removeSession(s)
	buf := make([]byte, maxUDPPacketBytes)
	for {
		n, err := s.upstream.Read(buf)
		if n > 0 {
			packet := append([]byte(nil), buf[:n]...)
			result := s.dpiFlow.inspect(context.Background(), packet, "server_to_client")
			if result.Action != protocol.ActionAllow {
				if s.dpiFlow.markViolation(result.Action) {
					go s.listener.reportViolation(context.Background(), s.cfg, result, s.sourceIP, s.clientAddr.String())
				}
				if result.Action == protocol.ActionBlock {
					s.listener.removeSession(s)
					return
				}
			}
			s.downloadLimiter.wait(len(packet))
			written, writeErr := s.listener.conn.WriteTo(packet, s.clientAddr)
			if written > 0 {
				s.listener.runtime.traffic.add(s.cfg.rule.ID, 0, int64(written))
			}
			s.touch()
			if writeErr != nil {
				atomic.AddInt64(&s.listener.runtime.upstreamWriteErrors, 1)
				s.listener.runtime.logger.Printf("runtime udp client write failed rule=%d client=%s: %v", s.cfg.rule.ID, s.clientAddr.String(), writeErr)
				return
			}
		}
		if err != nil {
			select {
			case <-s.listener.stopCh:
			default:
				if !errors.Is(err, net.ErrClosed) {
					s.listener.runtime.logger.Printf("runtime udp upstream read failed rule=%d client=%s: %v", s.cfg.rule.ID, s.clientAddr.String(), err)
				}
			}
			return
		}
	}
}

func (s *udpSession) forwardClientPacket(packet []byte) {
	s.touch()
	s.uploadLimiter.wait(len(packet))
	written, err := s.upstream.Write(packet)
	if written > 0 {
		s.listener.runtime.traffic.add(s.cfg.rule.ID, int64(written), 0)
	}
	if err != nil {
		atomic.AddInt64(&s.listener.runtime.upstreamWriteErrors, 1)
		s.listener.runtime.logger.Printf("runtime udp upstream write failed rule=%d client=%s: %v", s.cfg.rule.ID, s.clientAddr.String(), err)
		s.listener.removeSession(s)
	}
}

func (s *udpSession) inspectPacket(packet []byte) bool {
	if s.inspectedPackets >= udpInspectionPackets(s.cfg) {
		return true
	}
	s.inspectedPackets++
	result := s.dpiFlow.inspect(context.Background(), packet, "client_to_server")
	if result.Action == protocol.ActionAllow {
		return true
	}
	if result.Action == protocol.ActionBlock {
		if s.dpiFlow.markViolation(result.Action) {
			s.listener.reportViolation(context.Background(), s.cfg, result, s.sourceIP, s.clientAddr.String())
		}
		s.listener.removeSession(s)
		return false
	}
	if s.dpiFlow.markViolation(result.Action) {
		go s.listener.reportViolation(context.Background(), s.cfg, result, s.sourceIP, s.clientAddr.String())
	}
	return true
}

func udpInspectionPackets(cfg ruleRuntimeConfig) int {
	if cfg.policy == nil {
		return 1
	}
	return defaultUDPInspectionPackets
}

func (s *udpSession) touch() {
	atomic.StoreInt64(&s.lastSeen, time.Now().UnixNano())
}

func (s *udpSession) lastSeenAt() int64 {
	return atomic.LoadInt64(&s.lastSeen)
}

func (s *udpSession) close() {
	s.closeOnce.Do(func() {
		_ = s.upstream.Close()
		if s.dpiFlow != nil {
			s.dpiFlow.close()
		}
	})
}

func (r *Runtime) detectProtocol(ctx context.Context, packet []byte, cfg ruleRuntimeConfig, network string) protocol.Result {
	result, _ := r.detectProtocolFlow(ctx, packet, cfg, dpi.ClassifyRequest{Network: network})
	return result
}

func (r *Runtime) detectProtocolFlow(ctx context.Context, packet []byte, cfg ruleRuntimeConfig, request dpi.ClassifyRequest) (protocol.Result, bool) {
	network := request.Network
	policy := policyFromClient(cfg.policy, network)
	result := protocol.Detect(packet, policy)
	if result.Action == protocol.ActionBlock && result.Protocol != protocol.NameUnknown {
		return result, true
	}
	if !shouldUseDPI(cfg.policy, result) || r.dpi == nil || !r.dpi.Enabled() {
		return result, result.Protocol != protocol.NameUnknown
	}
	timeout := r.options.DPITimeout
	if cfg.policy != nil && cfg.policy.DPITimeoutMs > 0 {
		timeout = time.Duration(cfg.policy.DPITimeoutMs) * time.Millisecond
	}
	if timeout <= 0 {
		timeout = defaultDPITimeout
	}
	dpiCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	request.Network = network
	request.Payload = packet
	request.BuiltinProtocol = result.Protocol
	request.Host = result.Host
	request.ALPN = result.ALPN
	request.RuleID = cfg.rule.ID
	verdict, err := r.dpi.Classify(dpiCtx, request)
	if err != nil {
		atomic.AddInt64(&r.dpiErrors, 1)
		return result, false
	}
	if !verdict.Final && (verdict.Protocol == "" || verdict.Protocol == protocol.NameUnknown || verdict.Confidence < 80) {
		if result.Protocol == protocol.NameUnknown {
			result.Action = protocol.ActionAllow
			result.Reason = "nDPI multi-packet inspection is pending"
			result.MatchedRule = "ndpi_pending"
		}
		return result, false
	}
	result = protocol.ApplyDPI(result, policy, protocol.DPIResult{
		Source:     verdict.Engine,
		Protocol:   verdict.Protocol,
		Category:   verdict.Category,
		Confidence: verdict.Confidence,
		RiskScore:  verdict.RiskScore,
		RiskLevel:  verdict.RiskLevel,
		Tags:       verdict.Tags,
	})
	return result, verdict.Final
}

func shouldUseDPI(policy *client.ProtocolPolicy, result protocol.Result) bool {
	if policy == nil {
		return false
	}
	switch strings.ToLower(strings.TrimSpace(policy.InspectionLevel)) {
	case "deep", "advanced", "ndpi", "full":
		return true
	}
	if strings.TrimSpace(policy.BlockedProtocolGroups) != "" {
		return true
	}
	if strings.TrimSpace(policy.NDPILowConfidenceAction) != "" {
		return true
	}
	return result.Protocol == protocol.NameUnknown && strings.TrimSpace(policy.AuthorizedProtocols) == ""
}

type trafficBuffer struct {
	reporter    Reporter
	logger      *log.Logger
	maxSamples  int
	maxBytes    int64
	maxFailures int

	mu             sync.Mutex
	samples        map[uint]client.TrafficSample
	retryBatches   []trafficBatch
	pendingBytes   int64
	flushFailures  int
	droppedSamples int64
	droppedBytes   int64
	nextReportSeq  uint64
}

type trafficBatch struct {
	reportID string
	samples  []client.TrafficSample
	bytes    int64
}

func newTrafficBuffer(reporter Reporter, logger *log.Logger, options Options) *trafficBuffer {
	return &trafficBuffer{
		reporter:    reporter,
		logger:      logger,
		maxSamples:  options.MaxTrafficSamples,
		maxBytes:    options.MaxTrafficBytes,
		maxFailures: options.MaxTrafficFailures,
		samples:     map[uint]client.TrafficSample{},
	}
}

func (b *trafficBuffer) add(ruleID uint, inBytes, outBytes int64) {
	if inBytes <= 0 && outBytes <= 0 {
		return
	}
	b.mu.Lock()
	incoming := inBytes + outBytes
	if incoming < 0 {
		incoming = 0
	}
	if _, exists := b.samples[ruleID]; !exists && b.maxSamples > 0 && len(b.samples) >= b.maxSamples {
		b.droppedSamples++
		b.droppedBytes += incoming
		b.mu.Unlock()
		return
	}
	if b.maxBytes > 0 && incoming > 0 && b.pendingBytes+incoming > b.maxBytes {
		b.droppedSamples++
		b.droppedBytes += incoming
		b.mu.Unlock()
		return
	}
	sample := b.samples[ruleID]
	sample.RuleID = ruleID
	sample.InBytes += inBytes
	sample.OutBytes += outBytes
	b.samples[ruleID] = sample
	b.pendingBytes += incoming
	flushNow := len(b.samples) >= defaultTrafficFlushSize
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
	if len(b.samples) == 0 && len(b.retryBatches) == 0 {
		b.mu.Unlock()
		return
	}
	var batch trafficBatch
	if len(b.retryBatches) > 0 {
		batch = b.retryBatches[0]
		b.retryBatches = b.retryBatches[1:]
	} else {
		batch.samples = make([]client.TrafficSample, 0, len(b.samples))
		batch.bytes = b.pendingBytes
		batch.reportID = b.newReportIDLocked()
		for _, sample := range b.samples {
			batch.samples = append(batch.samples, sample)
		}
		b.samples = map[uint]client.TrafficSample{}
		b.pendingBytes = 0
	}
	b.mu.Unlock()

	if _, err := b.reporter.ReportTraffic(ctx, client.TrafficReport{ReportID: batch.reportID, Samples: batch.samples}); err != nil {
		b.logger.Printf("runtime traffic report failed: %v", err)
		b.mu.Lock()
		b.flushFailures++
		if b.maxFailures > 0 && b.flushFailures >= b.maxFailures {
			b.droppedSamples += int64(len(batch.samples))
			b.droppedBytes += batch.bytes
			b.mu.Unlock()
			return
		}
		if len(b.retryBatches) < b.maxFailures || b.maxFailures <= 0 {
			b.retryBatches = append([]trafficBatch{batch}, b.retryBatches...)
			b.mu.Unlock()
			return
		}
		for _, sample := range batch.samples {
			bytes := sample.InBytes + sample.OutBytes
			if bytes < 0 {
				bytes = 0
			}
			if _, exists := b.samples[sample.RuleID]; !exists && b.maxSamples > 0 && len(b.samples) >= b.maxSamples {
				b.droppedSamples++
				b.droppedBytes += bytes
				continue
			}
			if b.maxBytes > 0 && bytes > 0 && b.pendingBytes+bytes > b.maxBytes {
				b.droppedSamples++
				b.droppedBytes += bytes
				continue
			}
			existing := b.samples[sample.RuleID]
			existing.RuleID = sample.RuleID
			existing.InBytes += sample.InBytes
			existing.OutBytes += sample.OutBytes
			b.samples[sample.RuleID] = existing
			b.pendingBytes += bytes
		}
		b.mu.Unlock()
		return
	}
	b.mu.Lock()
	b.flushFailures = 0
	b.mu.Unlock()
}

func (b *trafficBuffer) status() map[string]any {
	b.mu.Lock()
	defer b.mu.Unlock()
	return map[string]any{
		"pendingSamples": len(b.samples),
		"retryBatches":   len(b.retryBatches),
		"pendingBytes":   b.pendingBytes,
		"flushFailures":  b.flushFailures,
		"droppedSamples": b.droppedSamples,
		"droppedBytes":   b.droppedBytes,
		"maxSamples":     b.maxSamples,
		"maxBytes":       b.maxBytes,
		"maxFailures":    b.maxFailures,
	}
}

func (b *trafficBuffer) newReportIDLocked() string {
	b.nextReportSeq++
	return fmt.Sprintf("%d-%d", time.Now().UnixNano(), b.nextReportSeq)
}

type effectiveSpeedLimit struct {
	UploadBps   int64
	DownloadBps int64
	MaxConns    int
	MaxIPs      int
}

type limitTracker struct {
	limit   effectiveSpeedLimit
	mu      sync.Mutex
	active  int64
	ipCount map[string]int
}

func newLimitTracker(limit effectiveSpeedLimit) *limitTracker {
	return &limitTracker{limit: limit, ipCount: map[string]int{}}
}

func (t *limitTracker) sameLimit(limit effectiveSpeedLimit) bool {
	return t != nil && t.limit == limit
}

func (t *limitTracker) acquire(sourceIP string) bool {
	if t == nil {
		return true
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.limit.MaxConns > 0 && t.active >= int64(t.limit.MaxConns) {
		return false
	}
	if t.limit.MaxIPs > 0 && t.ipCount[sourceIP] == 0 && len(t.ipCount) >= t.limit.MaxIPs {
		return false
	}
	t.ipCount[sourceIP]++
	t.active++
	return true
}

func (t *limitTracker) release(sourceIP string) {
	if t == nil {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if count := t.ipCount[sourceIP]; count <= 1 {
		delete(t.ipCount, sourceIP)
	} else {
		t.ipCount[sourceIP] = count - 1
	}
	if t.active > 0 {
		t.active--
	}
}

func (t *limitTracker) activeCount() int64 {
	if t == nil {
		return 0
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.active
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

func copyWithLimit(dst net.Conn, src net.Conn, limiter *tokenBucket, inspect func([]byte) error, count func(int64)) error {
	buf := make([]byte, 32*1024)
	for {
		n, readErr := src.Read(buf)
		if n > 0 {
			if inspect != nil {
				packet := append([]byte(nil), buf[:n]...)
				if err := inspect(packet); err != nil {
					return err
				}
			}
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
	buf := make([]byte, maxBytes)
	if timeout <= 0 {
		timeout = defaultReadTimeout
	}
	deadline := time.Now().Add(timeout)
	defer conn.SetReadDeadline(time.Time{})

	var used int
	for used < maxBytes {
		if used > 0 && !needsMoreInitialBytes(buf[:used]) {
			return buf[:used], nil
		}
		readDeadline := deadline
		if used > 0 && softMoreInitialBytes(buf[:used]) {
			idleDeadline := time.Now().Add(defaultInspectionIdleTimeout)
			if idleDeadline.Before(readDeadline) {
				readDeadline = idleDeadline
			}
		}
		_ = conn.SetReadDeadline(readDeadline)
		n, err := conn.Read(buf[used:])
		if n > 0 {
			used += n
			continue
		}
		if err != nil {
			if used > 0 && isBenignFirstRead(err) {
				return buf[:used], nil
			}
			return nil, err
		}
		if time.Now().After(deadline) {
			break
		}
	}
	if used > 0 {
		return buf[:used], nil
	}
	return nil, nil
}

func needsMoreInitialBytes(packet []byte) bool {
	if len(packet) == 0 {
		return true
	}
	if packet[0] == 0x16 {
		if len(packet) < 5 {
			return true
		}
		recordLen := int(packet[3])<<8 | int(packet[4])
		return recordLen > 0 && len(packet) < 5+recordLen
	}
	if isPrefixOf(packet, "SSH-") {
		return !bytes.Contains(packet, []byte{'\n'}) && len(packet) < 255
	}
	if len(packet) > 0 && (packet[0] == 0x05 || packet[0] == 0x04) {
		if packet[0] == 0x05 {
			if len(packet) < 2 {
				return true
			}
			return len(packet) < 2+int(packet[1])
		}
		return len(packet) < 9
	}
	if possibleHTTPPrefix(packet) {
		return !bytes.Contains(packet, []byte("\r\n\r\n"))
	}
	return false
}

func softMoreInitialBytes(packet []byte) bool {
	return possibleHTTPPrefix(packet) && !bytes.Contains(packet, []byte("\r\n\r\n"))
}

func possibleHTTPPrefix(packet []byte) bool {
	methods := []string{"GET ", "POST ", "PUT ", "DELETE ", "PATCH ", "HEAD ", "OPTIONS ", "CONNECT ", "TRACE "}
	for _, method := range methods {
		if isPrefixOf(packet, method) {
			return true
		}
	}
	return false
}

func isPrefixOf(packet []byte, value string) bool {
	if len(packet) > len(value) {
		return bytes.HasPrefix(packet, []byte(value))
	}
	return bytes.HasPrefix([]byte(value), packet)
}

func isBenignFirstRead(err error) bool {
	if err == nil || errors.Is(err, io.EOF) {
		return true
	}
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
}

func shouldProbeServerFirstSSH(cfg ruleRuntimeConfig, firstPacket []byte) bool {
	if len(firstPacket) > 0 || cfg.policy == nil {
		return false
	}
	result := protocol.Detect([]byte("SSH-2.0-dusheng-probe\r\n"), policyFromClient(cfg.policy, "tcp"))
	return result.Action != protocol.ActionAllow
}

func skipRule(rule client.ForwardRule) bool {
	status := strings.ToLower(strings.TrimSpace(rule.Status))
	if status == "paused" || status == "disabled" || status == "deleted" || status == "quota_exhausted" {
		return true
	}
	return rule.ListenPort <= 0 || rule.RemoteHost == "" || rule.RemotePort <= 0
}

func listenerBind(cfg ruleRuntimeConfig) string {
	return cfg.network + "|" + cfg.listenAddr
}

func isTCPRule(rule client.ForwardRule) bool {
	switch strings.ToLower(strings.TrimSpace(rule.Protocol)) {
	case "tcp", "tcp_udp", "":
		return true
	default:
		return false
	}
}

func isUDPRule(rule client.ForwardRule) bool {
	switch strings.ToLower(strings.TrimSpace(rule.Protocol)) {
	case "udp", "tcp_udp":
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

func policyFromClient(policy *client.ProtocolPolicy, network string) protocol.Policy {
	if policy == nil {
		return protocol.Policy{Network: network}
	}
	return protocol.Policy{
		Template:                policy.Template,
		Purpose:                 policy.Purpose,
		InspectionLevel:         policy.InspectionLevel,
		Network:                 network,
		Mode:                    policy.Mode,
		BlockTLS:                policy.BlockTLS,
		BlockQUIC:               policy.BlockQUIC,
		AllowPlainTCPOnly:       policy.AllowPlainTCPOnly,
		AllowHTTPOnly:           policy.AllowHTTPOnly,
		BlockProxyLike:          policy.BlockProxyLike,
		BlockEncryptedTunnel:    policy.BlockEncryptedTunnel,
		ObservationMinutes:      policy.ObservationMinutes,
		AuthorizedProtocols:     policy.AuthorizedProtocols,
		BlockedProtocolGroups:   policy.BlockedProtocolGroups,
		HostAllowlist:           policy.HostAllowlist,
		HostBlocklist:           policy.HostBlocklist,
		SNIAllowlist:            policy.SNIAllowlist,
		SNIBlocklist:            policy.SNIBlocklist,
		ALPNAllowlist:           policy.ALPNAllowlist,
		ALPNBlocklist:           policy.ALPNBlocklist,
		TLSNoSNIAction:          policy.TLSNoSNIAction,
		QUICAction:              policy.QUICAction,
		SSHAction:               policy.SSHAction,
		UnknownTCPAction:        policy.UnknownTCPAction,
		UnknownUDPAction:        policy.UnknownUDPAction,
		NDPILowConfidenceAction: policy.NDPILowConfidenceAction,
		DPITimeoutMs:            policy.DPITimeoutMs,
	}
}

func fingerprint(rule client.ForwardRule, tunnel client.Tunnel, group client.DeviceGroup, policy *client.ProtocolPolicy, limit effectiveSpeedLimit, listenHost, network string) string {
	ruleValue := struct {
		ID               uint
		UserID           uint
		TunnelID         uint
		Name             string
		Protocol         string
		ListenPort       int
		RemoteHost       string
		RemotePort       int
		Status           string
		Strategy         string
		ProtocolPolicyID *uint
	}{
		ID:               rule.ID,
		UserID:           rule.UserID,
		TunnelID:         rule.TunnelID,
		Name:             rule.Name,
		Protocol:         rule.Protocol,
		ListenPort:       rule.ListenPort,
		RemoteHost:       rule.RemoteHost,
		RemotePort:       rule.RemotePort,
		Status:           rule.Status,
		Strategy:         rule.Strategy,
		ProtocolPolicyID: rule.ProtocolPolicyID,
	}
	tunnelValue := struct {
		ID                uint
		EntryGroupID      uint
		ExitGroupID       *uint
		Protocol          string
		FlowAccounting    string
		EntryTrafficRatio float64
		ExitTrafficRatio  float64
		ProtocolPolicyID  *uint
		AdvancedJSON      string
	}{
		ID:                tunnel.ID,
		EntryGroupID:      tunnel.EntryGroupID,
		ExitGroupID:       tunnel.ExitGroupID,
		Protocol:          tunnel.Protocol,
		FlowAccounting:    tunnel.FlowAccounting,
		EntryTrafficRatio: tunnel.EntryTrafficRatio,
		ExitTrafficRatio:  tunnel.ExitTrafficRatio,
		ProtocolPolicyID:  tunnel.ProtocolPolicyID,
		AdvancedJSON:      tunnel.AdvancedJSON,
	}
	value := struct {
		Rule       any
		Tunnel     any
		GroupID    uint
		Policy     *client.ProtocolPolicy
		Limit      effectiveSpeedLimit
		ListenHost string
		Network    string
	}{ruleValue, tunnelValue, group.ID, policy, limit, listenHost, network}
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

func minDuration(a, b time.Duration) time.Duration {
	if a <= 0 {
		return b
	}
	if b <= 0 || a < b {
		return a
	}
	return b
}

func errorString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}
