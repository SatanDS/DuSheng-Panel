package main

import (
	"context"
	"errors"
	"log"
	"net"
	"net/http"
	"runtime"
	"time"

	"dusheng-panel/apps/agent/internal/configsync"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

type agentCollector struct {
	runtime *combinedRuntime
	syncer  *configsync.Syncer

	info         *prometheus.Desc
	runtimeUp    *prometheus.Desc
	listeners    *prometheus.Desc
	connections  *prometheus.Desc
	config       *prometheus.Desc
	leaseSeconds *prometheus.Desc
	errors       *prometheus.Desc
	traffic      *prometheus.Desc
	dpiEnabled   *prometheus.Desc
	probes       *prometheus.Desc
}

func newAgentCollector(runtimeManager *combinedRuntime, syncer *configsync.Syncer) *agentCollector {
	return &agentCollector{
		runtime: runtimeManager, syncer: syncer,
		info:         prometheus.NewDesc("dusheng_agent_info", "Agent build and runtime information.", []string{"version", "os", "arch"}, nil),
		runtimeUp:    prometheus.NewDesc("dusheng_agent_runtime_up", "Whether the forwarding runtime is active.", nil, nil),
		listeners:    prometheus.NewDesc("dusheng_agent_listeners", "Forwarding listeners by lifecycle or network kind.", []string{"kind"}, nil),
		connections:  prometheus.NewDesc("dusheng_agent_connections", "Active or draining forwarding connections and sessions.", []string{"kind"}, nil),
		config:       prometheus.NewDesc("dusheng_agent_config_revision", "Agent configuration revisions.", []string{"kind"}, nil),
		leaseSeconds: prometheus.NewDesc("dusheng_agent_config_lease_seconds", "Seconds remaining on the active configuration lease.", nil, nil),
		errors:       prometheus.NewDesc("dusheng_agent_runtime_errors_total", "Runtime errors by bounded error type.", []string{"type"}, nil),
		traffic:      prometheus.NewDesc("dusheng_agent_traffic_buffer", "Traffic reporter buffer state.", []string{"kind"}, nil),
		dpiEnabled:   prometheus.NewDesc("dusheng_agent_dpi_enabled", "Whether the DPI sidecar is configured.", nil, nil),
		probes:       prometheus.NewDesc("dusheng_agent_line_probes", "Line probe manager state.", []string{"kind"}, nil),
	}
}

func (c *agentCollector) Describe(ch chan<- *prometheus.Desc) {
	for _, descriptor := range []*prometheus.Desc{c.info, c.runtimeUp, c.listeners, c.connections, c.config, c.leaseSeconds, c.errors, c.traffic, c.dpiEnabled, c.probes} {
		ch <- descriptor
	}
}

func (c *agentCollector) Collect(ch chan<- prometheus.Metric) {
	status := c.syncer.RuntimeStatus()
	ch <- prometheus.MustNewConstMetric(c.info, prometheus.GaugeValue, 1, version, runtime.GOOS, runtime.GOARCH)
	ch <- prometheus.MustNewConstMetric(c.runtimeUp, prometheus.GaugeValue, boolFloat(c.runtime.Running()))
	for key, field := range map[string]string{
		"tcp": "tcpListeners", "udp": "udpListeners", "warming": "warmingListeners", "draining": "drainingListeners",
	} {
		ch <- prometheus.MustNewConstMetric(c.listeners, prometheus.GaugeValue, number(status[field]), key)
	}
	for key, field := range map[string]string{
		"active": "activeConnections", "udp_sessions": "activeUDPSessions", "draining": "drainingConnections",
	} {
		ch <- prometheus.MustNewConstMetric(c.connections, prometheus.GaugeValue, number(status[field]), key)
	}
	ch <- prometheus.MustNewConstMetric(c.config, prometheus.GaugeValue, float64(c.syncer.AppliedRevision()), "applied")
	ch <- prometheus.MustNewConstMetric(c.config, prometheus.GaugeValue, number(status["configRevision"]), "acknowledged")
	if validUntil, ok := status["configLeaseValidUntil"].(time.Time); ok && !validUntil.IsZero() {
		remaining := time.Until(validUntil).Seconds()
		if remaining < 0 {
			remaining = 0
		}
		ch <- prometheus.MustNewConstMetric(c.leaseSeconds, prometheus.GaugeValue, remaining)
	}
	if values, ok := status["listenerErrors"].(map[string]int64); ok {
		for kind, value := range values {
			ch <- prometheus.MustNewConstMetric(c.errors, prometheus.CounterValue, float64(value), kind)
		}
	}
	if values, ok := status["trafficBuffer"].(map[string]any); ok {
		for _, kind := range []string{"pendingSamples", "pendingBytes", "droppedSamples", "flushFailures", "retryBatches"} {
			ch <- prometheus.MustNewConstMetric(c.traffic, prometheus.GaugeValue, number(values[kind]), kind)
		}
	}
	ch <- prometheus.MustNewConstMetric(c.dpiEnabled, prometheus.GaugeValue, boolFloat(status["dpiEnabled"] == true))
	if values, ok := status["lineProbes"].(map[string]any); ok {
		for _, kind := range []string{"active", "totalChecks", "totalFailures"} {
			ch <- prometheus.MustNewConstMetric(c.probes, prometheus.GaugeValue, number(values[kind]), kind)
		}
	}
}

func startMetricsServer(ctx context.Context, listen string, collector prometheus.Collector, logger *log.Logger) {
	if listen == "" {
		return
	}
	registry := prometheus.NewRegistry()
	registry.MustRegister(collectors.NewGoCollector(), collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}), collector)
	listener, err := net.Listen("tcp", listen)
	if err != nil {
		logger.Printf("metrics listener failed addr=%s: %v", listen, err)
		return
	}
	server := &http.Server{
		Handler:           promhttp.HandlerFor(registry, promhttp.HandlerOpts{EnableOpenMetrics: true}),
		ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 15 * time.Second, IdleTimeout: 60 * time.Second,
	}
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdownCtx)
	}()
	go func() {
		logger.Printf("Prometheus metrics listening on %s", listener.Addr())
		if err := server.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Printf("metrics server failed: %v", err)
		}
	}()
}

func number(value any) float64 {
	switch typed := value.(type) {
	case int:
		return float64(typed)
	case int64:
		return float64(typed)
	case uint64:
		return float64(typed)
	case float64:
		return typed
	default:
		return 0
	}
}

func boolFloat(value bool) float64 {
	if value {
		return 1
	}
	return 0
}
