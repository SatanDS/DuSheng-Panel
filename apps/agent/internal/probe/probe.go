package probe

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"dusheng-panel/apps/agent/internal/client"
)

type Reporter interface {
	ReportProbe(context.Context, client.ProbeReport) error
}

type Manager struct {
	reporter Reporter
	logger   *log.Logger

	mu      sync.Mutex
	workers map[uint]*worker
	results map[uint]result
	stopped bool

	totalChecks    uint64
	totalFailures  uint64
	nextGeneration uint64
}

type worker struct {
	probe      client.LineProbe
	generation uint64
	cancel     context.CancelFunc
}

type result struct {
	Success   bool      `json:"success"`
	LatencyMs float64   `json:"latencyMs"`
	Error     string    `json:"error,omitempty"`
	CheckedAt time.Time `json:"checkedAt"`
}

var directHTTPClient = &http.Client{
	Transport:     &http.Transport{Proxy: nil},
	CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse },
}

func New(reporter Reporter, logger *log.Logger) *Manager {
	if logger == nil {
		logger = log.Default()
	}
	return &Manager{reporter: reporter, logger: logger, workers: map[uint]*worker{}, results: map[uint]result{}}
}

func (m *Manager) Validate(cfg client.AgentConfig) error {
	seen := map[uint]struct{}{}
	for _, probe := range cfg.LineProbes {
		if !probe.Enabled {
			continue
		}
		if probe.ID == 0 {
			return errors.New("line probe id is required")
		}
		if _, exists := seen[probe.ID]; exists {
			return fmt.Errorf("duplicate line probe %d", probe.ID)
		}
		seen[probe.ID] = struct{}{}
		if err := validate(probe); err != nil {
			return fmt.Errorf("line probe %d: %w", probe.ID, err)
		}
	}
	return nil
}

func (m *Manager) Apply(cfg client.AgentConfig) error {
	if err := m.Validate(cfg); err != nil {
		return err
	}
	desired := map[uint]client.LineProbe{}
	for _, probe := range cfg.LineProbes {
		if probe.Enabled {
			desired[probe.ID] = probe
		}
	}

	m.mu.Lock()
	if m.stopped {
		m.mu.Unlock()
		return errors.New("probe manager is stopped")
	}
	for id, current := range m.workers {
		probe, exists := desired[id]
		if exists && probe == current.probe {
			delete(desired, id)
			continue
		}
		current.cancel()
		delete(m.workers, id)
		delete(m.results, id)
	}
	for id, probe := range desired {
		ctx, cancel := context.WithCancel(context.Background())
		m.nextGeneration++
		worker := &worker{probe: probe, generation: m.nextGeneration, cancel: cancel}
		m.workers[id] = worker
		go m.run(ctx, worker)
	}
	m.mu.Unlock()
	return nil
}

func (m *Manager) run(ctx context.Context, worker *worker) {
	probe := worker.probe
	interval := time.Duration(probe.IntervalSeconds) * time.Second
	check := func() {
		checkCtx, cancel := context.WithTimeout(ctx, time.Duration(probe.TimeoutMs)*time.Millisecond)
		started := time.Now()
		err := execute(checkCtx, probe)
		latency := float64(time.Since(started).Microseconds()) / 1000
		cancel()
		probeResult := result{Success: err == nil, LatencyMs: latency, CheckedAt: time.Now().UTC()}
		if err != nil {
			probeResult.Error = err.Error()
			atomic.AddUint64(&m.totalFailures, 1)
		}
		atomic.AddUint64(&m.totalChecks, 1)
		m.mu.Lock()
		if m.stopped || m.workers[probe.ID] != worker {
			m.mu.Unlock()
			return
		}
		m.results[probe.ID] = probeResult
		m.mu.Unlock()
		if m.reporter != nil {
			reportCtx, reportCancel := context.WithTimeout(ctx, 10*time.Second)
			reportErr := m.reporter.ReportProbe(reportCtx, client.ProbeReport{
				ProbeID: probe.ID, Revision: probe.Revision, Success: probeResult.Success, LatencyMs: probeResult.LatencyMs, Error: probeResult.Error,
			})
			reportCancel()
			if reportErr != nil && !errors.Is(reportErr, context.Canceled) {
				m.logger.Printf("line probe report failed probe=%d: %v", probe.ID, reportErr)
			}
		}
	}

	check()
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			check()
		}
	}
}

func (m *Manager) Status() map[string]any {
	m.mu.Lock()
	defer m.mu.Unlock()
	results := make(map[string]any, len(m.results))
	for id, value := range m.results {
		results[fmt.Sprint(id)] = value
	}
	return map[string]any{
		"active": len(m.workers), "totalChecks": atomic.LoadUint64(&m.totalChecks),
		"totalFailures": atomic.LoadUint64(&m.totalFailures), "results": results,
	}
}

func (m *Manager) Stop() {
	m.mu.Lock()
	if m.stopped {
		m.mu.Unlock()
		return
	}
	m.stopped = true
	for _, worker := range m.workers {
		worker.cancel()
	}
	m.workers = map[uint]*worker{}
	m.mu.Unlock()
}

func validate(probe client.LineProbe) error {
	if probe.IntervalSeconds < 5 || probe.IntervalSeconds > 3600 || probe.TimeoutMs < 100 || probe.TimeoutMs > 30000 {
		return errors.New("interval or timeout is out of range")
	}
	switch probe.Type {
	case "tcp", "udp_echo":
		host, port, err := net.SplitHostPort(probe.Target)
		if err != nil || strings.TrimSpace(host) == "" || strings.TrimSpace(port) == "" {
			return errors.New("target must use host:port")
		}
	case "http":
		parsed, err := url.ParseRequestURI(probe.Target)
		if err != nil || parsed.Host == "" || (parsed.Scheme != "http" && parsed.Scheme != "https") {
			return errors.New("target must be an http or https URL")
		}
	default:
		return errors.New("unsupported probe type")
	}
	return nil
}

func execute(ctx context.Context, probe client.LineProbe) error {
	switch probe.Type {
	case "tcp":
		conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", probe.Target)
		if err != nil {
			return err
		}
		return conn.Close()
	case "udp_echo":
		conn, err := (&net.Dialer{}).DialContext(ctx, "udp", probe.Target)
		if err != nil {
			return err
		}
		defer conn.Close()
		deadline, ok := ctx.Deadline()
		if ok {
			_ = conn.SetDeadline(deadline)
		}
		payload := []byte(probe.Payload)
		if len(payload) == 0 {
			payload = []byte("dusheng-probe")
		}
		if _, err := conn.Write(payload); err != nil {
			return err
		}
		buffer := make([]byte, 2048)
		n, err := conn.Read(buffer)
		if err != nil {
			return err
		}
		if string(buffer[:n]) != string(payload) {
			return errors.New("udp echo response did not match payload")
		}
		return nil
	case "http":
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, probe.Target, nil)
		if err != nil {
			return err
		}
		response, err := directHTTPClient.Do(request)
		if err != nil {
			return err
		}
		defer response.Body.Close()
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
		if response.StatusCode < 200 || response.StatusCode >= 400 {
			return fmt.Errorf("http status %d", response.StatusCode)
		}
		return nil
	default:
		return errors.New("unsupported probe type")
	}
}
