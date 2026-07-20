package app

import (
	"net/http"
	"strconv"
	"time"

	"dusheng-panel/apps/api/internal/models"
	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"gorm.io/gorm"
)

type apiMetrics struct {
	registry *prometheus.Registry
	requests *prometheus.CounterVec
	duration *prometheus.HistogramVec
}

func newAPIMetrics(db *gorm.DB) *apiMetrics {
	registry := prometheus.NewRegistry()
	metrics := &apiMetrics{
		registry: registry,
		requests: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: "dusheng", Subsystem: "api", Name: "http_requests_total",
			Help: "Total API HTTP requests by stable route, method, and status code.",
		}, []string{"route", "method", "code"}),
		duration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Namespace: "dusheng", Subsystem: "api", Name: "http_request_duration_seconds",
			Help:    "API HTTP request duration by stable route and method.",
			Buckets: prometheus.DefBuckets,
		}, []string{"route", "method"}),
	}
	registry.MustRegister(collectors.NewGoCollector(), collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}))
	registry.MustRegister(metrics.requests, metrics.duration, newPanelCollector(db))
	return metrics
}

func (m *apiMetrics) middleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		started := time.Now()
		c.Next()
		route := c.FullPath()
		if route == "" {
			route = "unmatched"
		}
		m.requests.WithLabelValues(route, c.Request.Method, strconv.Itoa(c.Writer.Status())).Inc()
		m.duration.WithLabelValues(route, c.Request.Method).Observe(time.Since(started).Seconds())
	}
}

func (m *apiMetrics) handler() http.Handler {
	return promhttp.HandlerFor(m.registry, promhttp.HandlerOpts{EnableOpenMetrics: true})
}

type panelCollector struct {
	db *gorm.DB

	nodes              *prometheus.Desc
	configAcks         *prometheus.Desc
	rules              *prometheus.Desc
	tenants            *prometheus.Desc
	circuits           *prometheus.Desc
	probes             *prometheus.Desc
	userBytes          *prometheus.Desc
	tenantBytes        *prometheus.Desc
	tenantQuotaBlocked *prometheus.Desc
	tenantTunnelGrants *prometheus.Desc
	violations         *prometheus.Desc
}

func newPanelCollector(db *gorm.DB) *panelCollector {
	return &panelCollector{
		db:                 db,
		nodes:              prometheus.NewDesc("dusheng_panel_nodes", "Registered nodes by status.", []string{"status"}, nil),
		configAcks:         prometheus.NewDesc("dusheng_panel_node_config_acks", "Nodes by latest configuration acknowledgement status.", []string{"status"}, nil),
		rules:              prometheus.NewDesc("dusheng_panel_forward_rules", "Forwarding rules by status.", []string{"status"}, nil),
		tenants:            prometheus.NewDesc("dusheng_panel_tenants", "Tenants by status.", []string{"status"}, nil),
		circuits:           prometheus.NewDesc("dusheng_panel_line_circuits", "Physical line circuits by status.", []string{"status"}, nil),
		probes:             prometheus.NewDesc("dusheng_panel_line_probes", "Line probes by current status.", []string{"status"}, nil),
		userBytes:          prometheus.NewDesc("dusheng_panel_accounted_bytes", "Total bytes accounted to users.", nil, nil),
		tenantBytes:        prometheus.NewDesc("dusheng_panel_tenant_accounted_bytes", "Total bytes accounted to tenant billing periods.", nil, nil),
		tenantQuotaBlocked: prometheus.NewDesc("dusheng_panel_tenant_quota_blocked", "Tenants currently blocked by traffic quota.", nil, nil),
		tenantTunnelGrants: prometheus.NewDesc("dusheng_panel_tenant_tunnel_grants", "Configured tenant-to-tunnel grants.", nil, nil),
		violations:         prometheus.NewDesc("dusheng_panel_protocol_violations_24h", "Protocol violations recorded during the last 24 hours.", nil, nil),
	}
}

func (c *panelCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.nodes
	ch <- c.configAcks
	ch <- c.rules
	ch <- c.tenants
	ch <- c.circuits
	ch <- c.probes
	ch <- c.userBytes
	ch <- c.tenantBytes
	ch <- c.tenantQuotaBlocked
	ch <- c.tenantTunnelGrants
	ch <- c.violations
}

func (c *panelCollector) Collect(ch chan<- prometheus.Metric) {
	collectStatusCounts[models.Node](c.db, "status", c.nodes, ch)
	collectStatusCounts[models.Node](c.db, "config_status", c.configAcks, ch)
	collectStatusCounts[models.ForwardRule](c.db, "status", c.rules, ch)
	collectStatusCounts[models.Tenant](c.db, "status", c.tenants, ch)
	collectStatusCounts[models.LineCircuit](c.db, "status", c.circuits, ch)
	collectStatusCounts[models.LineProbe](c.db, "status", c.probes, ch)

	var userBytes int64
	if err := c.db.Model(&models.User{}).Select("COALESCE(SUM(used_bytes), 0)").Scan(&userBytes).Error; err == nil {
		ch <- prometheus.MustNewConstMetric(c.userBytes, prometheus.GaugeValue, float64(userBytes))
	}
	var tenantBytes int64
	if err := c.db.Model(&models.Tenant{}).Select("COALESCE(SUM(used_bytes), 0)").Scan(&tenantBytes).Error; err == nil {
		ch <- prometheus.MustNewConstMetric(c.tenantBytes, prometheus.GaugeValue, float64(tenantBytes))
	}
	var quotaBlocked int64
	if err := c.db.Model(&models.Tenant{}).Where("quota_blocked = ?", true).Count(&quotaBlocked).Error; err == nil {
		ch <- prometheus.MustNewConstMetric(c.tenantQuotaBlocked, prometheus.GaugeValue, float64(quotaBlocked))
	}
	var grants int64
	if err := c.db.Model(&models.TenantTunnelGrant{}).Count(&grants).Error; err == nil {
		ch <- prometheus.MustNewConstMetric(c.tenantTunnelGrants, prometheus.GaugeValue, float64(grants))
	}
	var violations int64
	if err := c.db.Model(&models.ProtocolViolation{}).Where("occurred_at >= ?", time.Now().Add(-24*time.Hour)).Count(&violations).Error; err == nil {
		ch <- prometheus.MustNewConstMetric(c.violations, prometheus.GaugeValue, float64(violations))
	}
}

func collectStatusCounts[T any](db *gorm.DB, column string, descriptor *prometheus.Desc, ch chan<- prometheus.Metric) {
	var rows []struct {
		Status string
		Count  int64
	}
	if err := db.Model(new(T)).Select(column + " AS status, COUNT(*) AS count").Group(column).Scan(&rows).Error; err != nil {
		return
	}
	for _, row := range rows {
		status := row.Status
		if status == "" {
			status = "unknown"
		}
		ch <- prometheus.MustNewConstMetric(descriptor, prometheus.GaugeValue, float64(row.Count), status)
	}
}
