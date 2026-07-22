package app

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"dusheng-panel/apps/api/internal/auth"
	"dusheng-panel/apps/api/internal/config"
	"dusheng-panel/apps/api/internal/models"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

type Server struct {
	cfg            config.Config
	db             *gorm.DB
	loginLimiter   *loginLimiter
	maintenanceMu  sync.Mutex
	lastProbePrune time.Time
}

const nodeOfflineAfter = 90 * time.Second
const nodeUninstallAckTimeout = 5 * time.Minute
const agentConfigLease = 2 * time.Minute
const maxRequestBodyBytes = int64(2 << 20)
const loginAttemptWindow = 10 * time.Minute
const maxLoginLimiterEntries = 10000
const (
	defaultPageSize = 25
	maxPageSize     = 200
)

var (
	errAgentPayload   = errors.New("invalid agent payload")
	errAgentForbidden = errors.New("agent is not allowed to report this rule")
)

type pageResponse[T any] struct {
	Items    []T   `json:"items"`
	Total    int64 `json:"total"`
	Page     int   `json:"page"`
	PageSize int   `json:"pageSize"`
}

type loginLimiter struct {
	mu       sync.Mutex
	attempts map[string]loginAttempt
}

type loginAttempt struct {
	Count     int
	FirstSeen time.Time
	BlockedAt time.Time
}

func newLoginLimiter() *loginLimiter {
	return &loginLimiter{attempts: map[string]loginAttempt{}}
}

func NewServer(cfg config.Config, db *gorm.DB) *gin.Engine {
	gin.SetMode(gin.ReleaseMode)
	s := &Server{cfg: cfg, db: db, loginLimiter: newLoginLimiter()}
	metrics := newAPIMetrics(db)
	router := gin.New()
	router.Use(gin.Logger(), gin.Recovery(), limitRequestBody(maxRequestBodyBytes), metrics.middleware(), cors(cfg.CORSOrigins))

	router.GET("/healthz", func(c *gin.Context) {
		ctx, cancel := context.WithTimeout(c.Request.Context(), 2*time.Second)
		defer cancel()
		if err := db.WithContext(ctx).Exec("SELECT 1").Error; err != nil {
			c.JSON(http.StatusServiceUnavailable, gin.H{"status": "degraded", "database": "unavailable", "time": time.Now().UTC()})
			return
		}
		c.JSON(http.StatusOK, gin.H{"status": "ok", "time": time.Now().UTC()})
	})
	router.GET("/metrics", gin.WrapH(metrics.handler()))
	router.GET("/install-agent.sh", s.installAgentScript)

	api := router.Group("/api/v1")
	api.POST("/auth/login", s.login)
	api.POST("/auth/refresh", s.refresh)
	api.POST("/agent/register", s.agentRegister)

	agent := api.Group("/agent", s.agentAuth())
	agent.POST("/heartbeat", s.agentHeartbeat)
	agent.GET("/config", s.agentConfig)
	agent.POST("/config/ack", s.agentConfigAck)
	agent.POST("/probes", s.agentProbeResult)
	agent.POST("/traffic", s.agentTraffic)
	agent.POST("/violations", s.agentViolation)
	agent.POST("/commands/:id/ack", s.agentCommandAck)

	protected := api.Group("", s.userAuth())
	protected.GET("/me", s.me)
	protected.GET("/dashboard", s.dashboard)
	tenantManagerView := protected.Group("", requireRole("tenant_admin"))
	tenantManagerView.GET("/tenant", s.currentTenant)
	tenantManagerView.GET("/tenant/traffic", s.currentTenantTraffic)
	protected.GET("/forward-rules", s.listForwardRules)
	protected.GET("/tunnels", s.listTunnels)
	protected.POST("/forward-rules", s.createForwardRule)
	protected.POST("/forward-rules/batch/preview", s.previewForwardRuleBatch)
	protected.POST("/forward-rules/batch", s.createForwardRuleBatch)
	protected.PUT("/forward-rules/:id", s.updateForwardRule)
	protected.DELETE("/forward-rules/:id", s.deleteForwardRule)

	userManager := protected.Group("", requireAnyRole("admin", "tenant_admin"))
	userManager.GET("/users", s.listUsers)
	userManager.POST("/users", s.createUser)
	userManager.PUT("/users/:id", s.updateUser)
	userManager.DELETE("/users/:id", s.deleteUser)
	userManager.POST("/users/:id/traffic/reset", s.resetUserTraffic)

	admin := protected.Group("", requireRole("admin"))
	admin.GET("/tenants", s.listTenants)
	admin.POST("/tenants", s.createTenant)
	admin.PUT("/tenants/:id", s.updateTenant)
	admin.DELETE("/tenants/:id", s.deleteTenant)
	admin.GET("/tenants/:id/traffic", s.adminTenantTraffic)
	admin.POST("/tenants/:id/traffic/reset", s.resetTenantTraffic)
	admin.GET("/tenant-tunnel-grants", s.listTenantTunnelGrants)
	admin.POST("/tenant-tunnel-grants", s.createTenantTunnelGrant)
	admin.PUT("/tenant-tunnel-grants/:id", s.updateTenantTunnelGrant)
	admin.DELETE("/tenant-tunnel-grants/:id", s.deleteTenantTunnelGrant)
	admin.GET("/user-tunnel-grants", s.listUserTunnelGrants)
	admin.POST("/user-tunnel-grants", s.createUserTunnelGrant)
	admin.PUT("/user-tunnel-grants/:id", s.updateUserTunnelGrant)
	admin.DELETE("/user-tunnel-grants/:id", s.deleteUserTunnelGrant)
	admin.GET("/device-groups", s.listDeviceGroups)
	admin.POST("/device-groups", s.createDeviceGroup)
	admin.PUT("/device-groups/:id", s.updateDeviceGroup)
	admin.DELETE("/device-groups/:id", s.deleteDeviceGroup)
	admin.GET("/line-providers", s.listLineProviders)
	admin.POST("/line-providers", s.createLineProvider)
	admin.PUT("/line-providers/:id", s.updateLineProvider)
	admin.DELETE("/line-providers/:id", s.deleteLineProvider)
	admin.GET("/line-sites", s.listLineSites)
	admin.POST("/line-sites", s.createLineSite)
	admin.PUT("/line-sites/:id", s.updateLineSite)
	admin.DELETE("/line-sites/:id", s.deleteLineSite)
	admin.GET("/line-circuits", s.listLineCircuits)
	admin.POST("/line-circuits", s.createLineCircuit)
	admin.PUT("/line-circuits/:id", s.updateLineCircuit)
	admin.DELETE("/line-circuits/:id", s.deleteLineCircuit)
	admin.GET("/line-endpoints", s.listLineEndpoints)
	admin.POST("/line-endpoints", s.createLineEndpoint)
	admin.PUT("/line-endpoints/:id", s.updateLineEndpoint)
	admin.DELETE("/line-endpoints/:id", s.deleteLineEndpoint)
	admin.GET("/line-probes", s.listLineProbes)
	admin.POST("/line-probes", s.createLineProbe)
	admin.PUT("/line-probes/:id", s.updateLineProbe)
	admin.DELETE("/line-probes/:id", s.deleteLineProbe)
	admin.GET("/line-probe-samples", s.listLineProbeSamples)
	admin.POST("/tunnels", s.createTunnel)
	admin.PUT("/tunnels/:id", s.updateTunnel)
	admin.DELETE("/tunnels/:id", s.deleteTunnel)
	admin.GET("/protocol-policies", s.listProtocolPolicies)
	admin.POST("/protocol-policies", s.createProtocolPolicy)
	admin.POST("/protocol-policies/evaluate", s.evaluateProtocolPolicy)
	admin.PUT("/protocol-policies/:id", s.updateProtocolPolicy)
	admin.DELETE("/protocol-policies/:id", s.deleteProtocolPolicy)
	admin.GET("/speed-limits", s.listSpeedLimits)
	admin.POST("/speed-limits", s.createSpeedLimit)
	admin.PUT("/speed-limits/:id", s.updateSpeedLimit)
	admin.DELETE("/speed-limits/:id", s.deleteSpeedLimit)
	admin.GET("/nodes", s.listNodes)
	admin.GET("/node-events", s.listNodeEvents)
	admin.PUT("/nodes/:id", s.updateNode)
	admin.DELETE("/nodes/:id", s.requestNodeUninstall)
	admin.POST("/install-tokens", s.createInstallToken)
	admin.GET("/install-tokens", s.listInstallTokens)
	admin.DELETE("/install-tokens/:id", s.deleteInstallToken)
	admin.GET("/audit-logs", s.listAuditLogs)
	admin.GET("/protocol-violations", s.listProtocolViolations)

	return router
}

func cors(origins []string) gin.HandlerFunc {
	allowAll := len(origins) == 0 || contains(origins, "*")
	allowed := map[string]bool{}
	for _, origin := range origins {
		origin = strings.TrimSpace(origin)
		if origin != "" {
			allowed[origin] = true
		}
	}
	return func(c *gin.Context) {
		origin := c.GetHeader("Origin")
		switch {
		case allowAll:
			c.Writer.Header().Set("Access-Control-Allow-Origin", "*")
		case origin != "" && allowed[origin]:
			c.Writer.Header().Set("Access-Control-Allow-Origin", origin)
			c.Writer.Header().Add("Vary", "Origin")
		}
		c.Writer.Header().Set("Access-Control-Allow-Methods", "GET,POST,PUT,DELETE,OPTIONS")
		c.Writer.Header().Set("Access-Control-Allow-Headers", "Authorization,Content-Type")
		if c.Request.Method == http.MethodOptions {
			c.AbortWithStatus(http.StatusNoContent)
			return
		}
		c.Next()
	}
}

func limitRequestBody(maxBytes int64) gin.HandlerFunc {
	return func(c *gin.Context) {
		if c.Request.Body == nil || maxBytes <= 0 {
			c.Next()
			return
		}
		if c.Request.ContentLength > maxBytes {
			c.AbortWithStatusJSON(http.StatusRequestEntityTooLarge, gin.H{"error": "request body is too large"})
			return
		}
		c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, maxBytes)
		c.Next()
	}
}

func (s *Server) limiter() *loginLimiter {
	if s.loginLimiter == nil {
		s.loginLimiter = newLoginLimiter()
	}
	return s.loginLimiter
}

func (l *loginLimiter) allow(key string, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	attempt := l.attempts[key]
	if now.Sub(attempt.FirstSeen) > loginAttemptWindow {
		delete(l.attempts, key)
		return true
	}
	return attempt.Count < 8
}

func (l *loginLimiter) fail(key string, now time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if _, exists := l.attempts[key]; !exists && len(l.attempts) >= maxLoginLimiterEntries {
		l.pruneLocked(now)
		if len(l.attempts) >= maxLoginLimiterEntries {
			l.evictOldestLocked()
		}
	}
	attempt := l.attempts[key]
	if attempt.FirstSeen.IsZero() || now.Sub(attempt.FirstSeen) > loginAttemptWindow {
		attempt = loginAttempt{FirstSeen: now}
	}
	attempt.Count++
	if attempt.Count >= 8 {
		attempt.BlockedAt = now
	}
	l.attempts[key] = attempt
}

func (l *loginLimiter) pruneLocked(now time.Time) {
	for key, attempt := range l.attempts {
		if now.Sub(attempt.FirstSeen) > loginAttemptWindow {
			delete(l.attempts, key)
		}
	}
}

func (l *loginLimiter) evictOldestLocked() {
	var oldestKey string
	var oldest time.Time
	for key, attempt := range l.attempts {
		if oldestKey == "" || attempt.FirstSeen.Before(oldest) {
			oldestKey = key
			oldest = attempt.FirstSeen
		}
	}
	if oldestKey != "" {
		delete(l.attempts, oldestKey)
	}
}

func (l *loginLimiter) success(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.attempts, key)
}

func (s *Server) login(c *gin.Context) {
	var req struct {
		Username string `json:"username" binding:"required"`
		Password string `json:"password" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		bad(c, err)
		return
	}
	req.Username = strings.TrimSpace(req.Username)
	key := strings.ToLower(c.ClientIP() + "|" + req.Username)
	now := time.Now()
	if !s.limiter().allow(key, now) {
		s.audit(c, nil, "auth.login.rate_limited", "user", req.Username, "{}")
		c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{"error": "too many failed login attempts"})
		return
	}
	var user models.User
	if err := s.db.Where("username = ?", req.Username).First(&user).Error; err != nil {
		s.limiter().fail(key, now)
		s.audit(c, nil, "auth.login.failed", "user", req.Username, "{}")
		unauthorized(c)
		return
	}
	if !s.userCanAuthenticate(user, now) || !auth.CheckPassword(user.PasswordHash, req.Password) {
		s.limiter().fail(key, now)
		s.audit(c, &user.ID, "auth.login.failed", "user", fmt.Sprint(user.ID), "{}")
		unauthorized(c)
		return
	}
	s.limiter().success(key)
	access, err := auth.GenerateToken(user.ID, user.Role, auth.TokenTypeAccess, s.cfg.JWTSecret, 8*time.Hour)
	if err != nil {
		fail(c, err)
		return
	}
	refresh, err := auth.GenerateToken(user.ID, user.Role, auth.TokenTypeRefresh, s.cfg.JWTSecret, 14*24*time.Hour)
	if err != nil {
		fail(c, err)
		return
	}
	s.audit(c, &user.ID, "auth.login", "user", fmt.Sprint(user.ID), "{}")
	c.JSON(http.StatusOK, gin.H{"accessToken": access, "refreshToken": refresh, "user": user})
}

func (s *Server) refresh(c *gin.Context) {
	token := bearer(c)
	claims, err := auth.ParseJWT(token, s.cfg.JWTSecret)
	if err != nil {
		unauthorized(c)
		return
	}
	if err := auth.RequireTokenType(claims, auth.TokenTypeRefresh); err != nil {
		unauthorized(c)
		return
	}
	var user models.User
	if err := s.db.First(&user, claims.UserID).Error; err != nil || !s.userCanAuthenticate(user, time.Now()) {
		unauthorized(c)
		return
	}
	access, err := auth.GenerateToken(user.ID, user.Role, auth.TokenTypeAccess, s.cfg.JWTSecret, 8*time.Hour)
	if err != nil {
		fail(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"accessToken": access})
}

func (s *Server) me(c *gin.Context) {
	var user models.User
	if err := s.db.First(&user, ctxUserID(c)).Error; err != nil {
		unauthorized(c)
		return
	}
	c.JSON(http.StatusOK, user)
}

func (s *Server) dashboard(c *gin.Context) {
	s.markStaleNodesOffline(time.Now())

	var users, nodes, onlineNodes, rules, violations int64
	var todayBytes int64
	var recentViolations []models.ProtocolViolation
	var recentRules []models.ForwardRule
	now := time.Now()
	since := now.Add(-24 * time.Hour)
	dayStart := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, now.Location())

	if ctxRole(c) == "admin" {
		s.db.Model(&models.User{}).Count(&users)
		s.db.Model(&models.Node{}).Count(&nodes)
		s.db.Model(&models.Node{}).Where("status = ?", "online").Count(&onlineNodes)
		s.db.Model(&models.ForwardRule{}).Count(&rules)
		s.db.Model(&models.ProtocolViolation{}).Where("occurred_at >= ?", since).Count(&violations)
		s.db.Model(&models.TrafficSample{}).
			Where("sampled_at >= ?", dayStart).
			Select("COALESCE(SUM(bytes),0)").
			Scan(&todayBytes)
		s.db.Order("occurred_at desc").Limit(8).Find(&recentViolations)
		s.db.Order("updated_at desc").Limit(8).Find(&recentRules)
	} else if ctxRole(c) == "tenant_admin" {
		tenantID := ctxTenantID(c)
		s.db.Model(&models.User{}).Where("tenant_id = ?", tenantID).Count(&users)
		s.nodeScopeForTenant(tenantID).Count(&nodes)
		s.nodeScopeForTenant(tenantID).Where("nodes.status = ?", "online").Count(&onlineNodes)
		s.db.Model(&models.ForwardRule{}).Where("tenant_id = ?", tenantID).Count(&rules)
		s.db.Model(&models.ProtocolViolation{}).
			Joins("JOIN forward_rules ON forward_rules.id = protocol_violations.rule_id").
			Where("forward_rules.tenant_id = ? AND protocol_violations.occurred_at >= ?", tenantID, since).
			Count(&violations)
		s.db.Model(&models.TrafficSample{}).
			Where("tenant_id = ? AND sampled_at >= ?", tenantID, dayStart).
			Select("COALESCE(SUM(bytes),0)").
			Scan(&todayBytes)
		s.db.Joins("JOIN forward_rules ON forward_rules.id = protocol_violations.rule_id").
			Where("forward_rules.tenant_id = ?", tenantID).
			Order("protocol_violations.occurred_at desc").
			Limit(8).
			Find(&recentViolations)
		s.db.Where("tenant_id = ?", tenantID).Order("updated_at desc").Limit(8).Find(&recentRules)
	} else {
		userID := ctxUserID(c)
		users = 1
		s.nodeScopeForUser(userID).Count(&nodes)
		s.nodeScopeForUser(userID).Where("nodes.status = ?", "online").Count(&onlineNodes)
		s.db.Model(&models.ForwardRule{}).Where("user_id = ?", userID).Count(&rules)
		s.db.Model(&models.ProtocolViolation{}).
			Joins("JOIN forward_rules ON forward_rules.id = protocol_violations.rule_id").
			Where("forward_rules.user_id = ? AND protocol_violations.occurred_at >= ?", userID, since).
			Count(&violations)
		s.db.Model(&models.TrafficSample{}).
			Where("user_id = ? AND sampled_at >= ?", userID, dayStart).
			Select("COALESCE(SUM(bytes),0)").
			Scan(&todayBytes)
		s.db.Joins("JOIN forward_rules ON forward_rules.id = protocol_violations.rule_id").
			Where("forward_rules.user_id = ?", userID).
			Order("protocol_violations.occurred_at desc").
			Limit(8).
			Find(&recentViolations)
		s.db.Where("user_id = ?", userID).Order("updated_at desc").Limit(8).Find(&recentRules)
	}

	c.JSON(http.StatusOK, gin.H{
		"users":            users,
		"nodes":            nodes,
		"onlineNodes":      onlineNodes,
		"forwardRules":     rules,
		"todayBytes":       todayBytes,
		"violations24h":    violations,
		"recentViolations": recentViolations,
		"recentRules":      recentRules,
	})
}

func (s *Server) userAuth() gin.HandlerFunc {
	return func(c *gin.Context) {
		claims, err := auth.ParseJWT(bearer(c), s.cfg.JWTSecret)
		if err != nil {
			unauthorized(c)
			return
		}
		if err := auth.RequireTokenType(claims, auth.TokenTypeAccess); err != nil {
			unauthorized(c)
			return
		}
		var user models.User
		if err := s.db.First(&user, claims.UserID).Error; err != nil || !s.userCanAuthenticate(user, time.Now()) {
			unauthorized(c)
			return
		}
		c.Set("userID", user.ID)
		c.Set("role", user.Role)
		if user.TenantID != nil {
			c.Set("tenantID", *user.TenantID)
		}
		c.Next()
	}
}

func userActiveAt(user models.User, now time.Time) bool {
	return user.Status == "active" && (user.ExpiresAt == nil || user.ExpiresAt.After(now))
}

func (s *Server) userCanAuthenticate(user models.User, now time.Time) bool {
	if !userActiveAt(user, now) {
		return false
	}
	if user.TenantID == nil || *user.TenantID == 0 || user.Role == "admin" {
		return true
	}
	var tenant models.Tenant
	return s.db.First(&tenant, *user.TenantID).Error == nil && tenantActiveAt(tenant, now)
}

func requireRole(role string) gin.HandlerFunc {
	return requireAnyRole(role)
}

func requireAnyRole(roles ...string) gin.HandlerFunc {
	allowed := make(map[string]struct{}, len(roles))
	for _, role := range roles {
		allowed[role] = struct{}{}
	}
	return func(c *gin.Context) {
		if _, ok := allowed[ctxRole(c)]; !ok {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "forbidden"})
			return
		}
		c.Next()
	}
}

func bearer(c *gin.Context) string {
	value := c.GetHeader("Authorization")
	if strings.HasPrefix(strings.ToLower(value), "bearer ") {
		return strings.TrimSpace(value[7:])
	}
	return ""
}

func ctxUserID(c *gin.Context) uint {
	value, _ := c.Get("userID")
	if id, ok := value.(uint); ok {
		return id
	}
	return 0
}

func ctxRole(c *gin.Context) string {
	value, _ := c.Get("role")
	if role, ok := value.(string); ok {
		return role
	}
	return ""
}

func ctxTenantID(c *gin.Context) uint {
	value, _ := c.Get("tenantID")
	if id, ok := value.(uint); ok {
		return id
	}
	return 0
}

func (s *Server) agentAuth() gin.HandlerFunc {
	return func(c *gin.Context) {
		token := bearer(c)
		if token == "" {
			unauthorized(c)
			return
		}
		var node models.Node
		if err := s.db.Where("token_hash = ?", auth.TokenHash(token)).First(&node).Error; err != nil {
			unauthorized(c)
			return
		}
		if node.Status == "disabled" {
			forbidden(c)
			return
		}
		c.Set("node", node)
		c.Next()
	}
}

func ctxNode(c *gin.Context) models.Node {
	value, _ := c.Get("node")
	if node, ok := value.(models.Node); ok {
		return node
	}
	return models.Node{}
}

func pageParams(c *gin.Context) (int, int) {
	page, err := strconv.Atoi(c.DefaultQuery("page", "1"))
	if err != nil || page < 1 {
		page = 1
	}
	pageSize, err := strconv.Atoi(c.DefaultQuery("pageSize", fmt.Sprint(defaultPageSize)))
	if err != nil || pageSize < 1 {
		pageSize = defaultPageSize
	}
	if pageSize > maxPageSize {
		pageSize = maxPageSize
	}
	return page, pageSize
}

func respondPage[T any](c *gin.Context, query *gorm.DB, order string) {
	page, pageSize := pageParams(c)
	var total int64
	if err := query.Count(&total).Error; err != nil {
		fail(c, err)
		return
	}
	var rows []T
	if err := query.Order(order).Limit(pageSize).Offset((page - 1) * pageSize).Find(&rows).Error; err != nil {
		fail(c, err)
		return
	}
	c.JSON(http.StatusOK, pageResponse[T]{Items: rows, Total: total, Page: page, PageSize: pageSize})
}

func applySearch(query *gorm.DB, c *gin.Context, columns ...string) *gorm.DB {
	needle := strings.ToLower(strings.TrimSpace(c.Query("q")))
	if needle == "" || len(columns) == 0 {
		return query
	}
	parts := make([]string, 0, len(columns))
	args := make([]any, 0, len(columns))
	for _, column := range columns {
		parts = append(parts, "LOWER("+column+") LIKE ?")
		args = append(args, "%"+needle+"%")
	}
	return query.Where("("+strings.Join(parts, " OR ")+")", args...)
}

func filterString(query *gorm.DB, c *gin.Context, column, param string) *gorm.DB {
	value := strings.TrimSpace(c.Query(param))
	if value == "" {
		return query
	}
	return query.Where(column+" = ?", value)
}

func filterUint(query *gorm.DB, c *gin.Context, column, param string) *gorm.DB {
	value, err := strconv.ParseUint(strings.TrimSpace(c.Query(param)), 10, 64)
	if err != nil || value == 0 {
		return query
	}
	return query.Where(column+" = ?", uint(value))
}

func filterDateRange(query *gorm.DB, c *gin.Context, column string) *gorm.DB {
	if from := parseQueryTime(c.Query("dateFrom")); !from.IsZero() {
		query = query.Where(column+" >= ?", from)
	}
	if to := parseQueryTime(c.Query("dateTo")); !to.IsZero() {
		query = query.Where(column+" <= ?", to)
	}
	return query
}

func parseQueryTime(value string) time.Time {
	value = strings.TrimSpace(value)
	if value == "" {
		return time.Time{}
	}
	for _, layout := range []string{time.RFC3339, "2006-01-02"} {
		parsed, err := time.Parse(layout, value)
		if err == nil {
			return parsed
		}
	}
	return time.Time{}
}

func (s *Server) listUsers(c *gin.Context) {
	query := s.db.Model(&models.User{})
	if ctxRole(c) == "tenant_admin" {
		query = query.Where("tenant_id = ?", ctxTenantID(c))
	}
	query = applySearch(query, c, "username", "display_name", "role", "status")
	query = filterString(query, c, "status", "status")
	query = filterUint(query, c, "tenant_id", "tenantId")
	respondPage[models.User](c, query, "id desc")
}

type userPayload struct {
	TenantID       *uint      `json:"tenantId"`
	Username       string     `json:"username"`
	DisplayName    string     `json:"displayName"`
	Password       string     `json:"password"`
	Role           string     `json:"role"`
	Status         string     `json:"status"`
	FlowLimitBytes int64      `json:"flowLimitBytes"`
	ForwardLimit   int        `json:"forwardLimit"`
	ExpiresAt      *time.Time `json:"expiresAt"`
}

func (s *Server) createUser(c *gin.Context) {
	var req userPayload
	if err := c.ShouldBindJSON(&req); err != nil {
		bad(c, err)
		return
	}
	req.Username = strings.TrimSpace(req.Username)
	if req.Username == "" || req.Password == "" {
		bad(c, errors.New("username and password are required"))
		return
	}
	tenantID, role, err := s.managedUserTenantAndRole(c, req.TenantID, defaultString(req.Role, "user"))
	if err != nil {
		bad(c, err)
		return
	}
	if err := s.validateUserPayload(req.Status, req.FlowLimitBytes, req.ForwardLimit); err != nil {
		bad(c, err)
		return
	}
	hash, err := auth.HashPassword(req.Password)
	if err != nil {
		fail(c, err)
		return
	}
	user := models.User{
		TenantID:       tenantID,
		Username:       req.Username,
		DisplayName:    req.DisplayName,
		PasswordHash:   hash,
		Role:           role,
		Status:         defaultString(req.Status, "active"),
		FlowLimitBytes: req.FlowLimitBytes,
		ForwardLimit:   req.ForwardLimit,
		ExpiresAt:      req.ExpiresAt,
	}
	var capacityErr error
	if err := s.db.Transaction(func(tx *gorm.DB) error {
		if err := s.ensureTenantUserCapacityWithDB(tx, tenantID, 0); err != nil {
			capacityErr = err
			return err
		}
		return tx.Create(&user).Error
	}); err != nil {
		if capacityErr != nil {
			bad(c, capacityErr)
		} else {
			fail(c, err)
		}
		return
	}
	s.audit(c, actor(c), "user.create", "user", fmt.Sprint(user.ID), "{}")
	c.JSON(http.StatusCreated, user)
}

func (s *Server) updateUser(c *gin.Context) {
	var user models.User
	if err := s.db.First(&user, c.Param("id")).Error; err != nil {
		notFound(c)
		return
	}
	if !canManageUser(c, user) {
		forbidden(c)
		return
	}
	var req userPayload
	if err := c.ShouldBindJSON(&req); err != nil {
		bad(c, err)
		return
	}
	requestedTenantID := req.TenantID
	if requestedTenantID == nil {
		requestedTenantID = user.TenantID
	}
	tenantID, role, err := s.managedUserTenantAndRole(c, requestedTenantID, defaultString(req.Role, user.Role))
	if err != nil {
		bad(c, err)
		return
	}
	if err := s.validateUserPayload(req.Status, req.FlowLimitBytes, req.ForwardLimit); err != nil {
		bad(c, err)
		return
	}
	if !sameOptionalUint(user.TenantID, tenantID) {
		var references int64
		if err := s.db.Model(&models.ForwardRule{}).Where("user_id = ?", user.ID).Count(&references).Error; err != nil {
			fail(c, err)
			return
		}
		if references > 0 {
			bad(c, errors.New("user with forwarding rules cannot be moved between tenants"))
			return
		}
	}
	user.TenantID = tenantID
	user.Username = defaultString(strings.TrimSpace(req.Username), user.Username)
	user.DisplayName = req.DisplayName
	user.Role = role
	user.Status = defaultString(req.Status, user.Status)
	user.FlowLimitBytes = req.FlowLimitBytes
	user.ForwardLimit = req.ForwardLimit
	user.ExpiresAt = req.ExpiresAt
	if req.Password != "" {
		hash, err := auth.HashPassword(req.Password)
		if err != nil {
			fail(c, err)
			return
		}
		user.PasswordHash = hash
	}
	revision := time.Now().UnixNano()
	var capacityErr error
	if err := s.db.Transaction(func(tx *gorm.DB) error {
		if err := s.ensureTenantUserCapacityWithDB(tx, tenantID, user.ID); err != nil {
			capacityErr = err
			return err
		}
		if err := tx.Save(&user).Error; err != nil {
			return err
		}
		return s.reconcileUserQuotaTx(tx, &user, revision)
	}); err != nil {
		if capacityErr != nil {
			bad(c, capacityErr)
		} else {
			fail(c, err)
		}
		return
	}
	s.audit(c, actor(c), "user.update", "user", fmt.Sprint(user.ID), "{}")
	c.JSON(http.StatusOK, user)
}

func (s *Server) deleteUser(c *gin.Context) {
	var user models.User
	if err := s.db.First(&user, c.Param("id")).Error; err != nil {
		notFound(c)
		return
	}
	if !canManageUser(c, user) {
		forbidden(c)
		return
	}
	if user.ID == ctxUserID(c) {
		bad(c, errors.New("the current account cannot delete itself"))
		return
	}
	if user.Role == "admin" {
		var admins int64
		if err := s.db.Model(&models.User{}).Where("role = ?", "admin").Count(&admins).Error; err != nil {
			fail(c, err)
			return
		}
		if admins <= 1 {
			bad(c, errors.New("the last administrator cannot be deleted"))
			return
		}
	}
	var rules, limits int64
	if err := s.db.Model(&models.ForwardRule{}).Where("user_id = ?", user.ID).Count(&rules).Error; err != nil {
		fail(c, err)
		return
	}
	if err := s.db.Model(&models.SpeedLimit{}).Where("user_id = ?", user.ID).Count(&limits).Error; err != nil {
		fail(c, err)
		return
	}
	if rules+limits > 0 {
		bad(c, errors.New("user is still referenced by forwarding rules or speed limits"))
		return
	}
	if err := s.db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Where("user_id = ?", user.ID).Delete(&models.UserTunnelGrant{}).Error; err != nil {
			return err
		}
		return tx.Delete(&user).Error
	}); err != nil {
		fail(c, err)
		return
	}
	s.audit(c, actor(c), "user.delete", "user", fmt.Sprint(user.ID), "{}")
	c.Status(http.StatusNoContent)
}

func (s *Server) managedUserTenantAndRole(c *gin.Context, requestedTenantID *uint, requestedRole string) (*uint, string, error) {
	role := strings.ToLower(strings.TrimSpace(requestedRole))
	if ctxRole(c) == "tenant_admin" {
		tenantID := ctxTenantID(c)
		if tenantID == 0 {
			return nil, "", errors.New("tenant administrator is not assigned to a tenant")
		}
		if role != "user" {
			return nil, "", errors.New("tenant administrators can only manage regular users")
		}
		return &tenantID, role, nil
	}
	if !contains([]string{"admin", "tenant_admin", "user"}, role) {
		return nil, "", errors.New("role must be admin, tenant_admin, or user")
	}
	if role == "admin" {
		return nil, role, nil
	}
	if requestedTenantID != nil && *requestedTenantID == 0 {
		requestedTenantID = nil
	}
	if role == "tenant_admin" && requestedTenantID == nil {
		return nil, "", errors.New("tenant administrators must be assigned to a tenant")
	}
	if requestedTenantID != nil {
		if err := s.requireID(&models.Tenant{}, *requestedTenantID, "tenant"); err != nil {
			return nil, "", err
		}
		value := *requestedTenantID
		return &value, role, nil
	}
	return nil, role, nil
}

func (s *Server) validateUserPayload(status string, flowLimitBytes int64, forwardLimit int) error {
	status = defaultString(strings.ToLower(strings.TrimSpace(status)), "active")
	if !contains([]string{"active", "suspended", "disabled"}, status) {
		return errors.New("status must be active, suspended, or disabled")
	}
	if flowLimitBytes < 0 || forwardLimit < 0 {
		return errors.New("user limits must be non-negative")
	}
	return nil
}

func (s *Server) ensureTenantUserCapacityWithDB(db *gorm.DB, tenantID *uint, excludeUserID uint) error {
	if tenantID == nil || *tenantID == 0 {
		return nil
	}
	var tenant models.Tenant
	if err := db.Clauses(clause.Locking{Strength: "UPDATE"}).First(&tenant, *tenantID).Error; err != nil {
		return errors.New("tenant not found")
	}
	if tenant.UserLimit <= 0 {
		return nil
	}
	query := db.Model(&models.User{}).Where("tenant_id = ?", tenant.ID)
	if excludeUserID > 0 {
		query = query.Where("id <> ?", excludeUserID)
	}
	var count int64
	if err := query.Count(&count).Error; err != nil {
		return err
	}
	if count >= int64(tenant.UserLimit) {
		return errors.New("tenant user limit reached")
	}
	return nil
}

func canManageUser(c *gin.Context, user models.User) bool {
	if ctxRole(c) == "admin" {
		return true
	}
	return ctxRole(c) == "tenant_admin" && user.Role == "user" && user.TenantID != nil && *user.TenantID == ctxTenantID(c)
}

func sameOptionalUint(left, right *uint) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return *left == *right
}

func (s *Server) listNodes(c *gin.Context) {
	s.markStaleNodesOffline(time.Now())
	query := s.db.Model(&models.Node{})
	query = applySearch(query, c, "name", "uuid", "status", "version", "public_ip", "connect_host")
	query = filterString(query, c, "status", "status")
	query = filterUint(query, c, "device_group_id", "deviceGroupId")
	respondPage[models.Node](c, query, "id desc")
}

func (s *Server) markStaleNodesOffline(now time.Time) {
	cutoff := now.Add(-nodeOfflineAfter)
	s.db.Model(&models.Node{}).
		Where("status = ? AND (last_seen_at IS NULL OR last_seen_at < ?)", "online", cutoff).
		Update("status", "offline")
	uninstallCutoff := now.Add(-nodeUninstallAckTimeout)
	var staleUninstalls []models.Node
	if err := s.db.Where("status = ? AND uninstall_requested_at < ?", "uninstalling", uninstallCutoff).Find(&staleUninstalls).Error; err != nil {
		return
	}
	for _, node := range staleUninstalls {
		updates := map[string]any{
			"status":                "uninstall_timeout",
			"uninstall_ack_status":  "timeout",
			"uninstall_ack_message": "agent did not confirm cleanup before the uninstall timeout",
			"uninstall_ack_at":      now.UTC(),
		}
		if !nodeSupportsFinalUninstallAck(node) && node.LastSeenAt != nil && node.UninstallRequestedAt != nil && !node.LastSeenAt.Before(*node.UninstallRequestedAt) {
			updates["status"] = "uninstall_legacy"
			updates["uninstall_ack_status"] = "legacy"
			updates["uninstall_ack_message"] = "legacy agent received the command but cannot confirm final cleanup"
			updates["uninstall_legacy"] = true
		}
		s.db.Model(&models.Node{}).Where("id = ? AND status = ?", node.ID, "uninstalling").Updates(updates)
	}
}

func (s *Server) nodeScopeForUser(userID uint) *gorm.DB {
	return s.db.Model(&models.Node{}).
		Joins("JOIN tunnels ON nodes.device_group_id = tunnels.entry_group_id OR nodes.device_group_id = tunnels.exit_group_id").
		Joins("JOIN forward_rules ON forward_rules.tunnel_id = tunnels.id").
		Where("forward_rules.user_id = ?", userID).
		Distinct("nodes.id")
}

func (s *Server) nodeScopeForTenant(tenantID uint) *gorm.DB {
	return s.db.Model(&models.Node{}).
		Joins("JOIN tunnels ON nodes.device_group_id = tunnels.entry_group_id OR nodes.device_group_id = tunnels.exit_group_id").
		Joins("JOIN forward_rules ON forward_rules.tunnel_id = tunnels.id").
		Where("forward_rules.tenant_id = ?", tenantID).
		Distinct("nodes.id")
}

func (s *Server) updateNode(c *gin.Context) {
	var node models.Node
	if err := s.db.First(&node, c.Param("id")).Error; err != nil {
		notFound(c)
		return
	}
	var req struct {
		DeviceGroupID uint    `json:"deviceGroupId"`
		Name          string  `json:"name"`
		Status        string  `json:"status"`
		ConnectHost   *string `json:"connectHost"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		bad(c, err)
		return
	}
	if req.DeviceGroupID != 0 {
		node.DeviceGroupID = req.DeviceGroupID
	}
	if req.Name != "" {
		node.Name = req.Name
	}
	if req.Status != "" {
		node.Status = req.Status
	}
	if req.ConnectHost != nil {
		node.ConnectHost = strings.TrimSpace(*req.ConnectHost)
	}
	node.DesiredRevision = time.Now().UnixNano()
	if err := s.db.Save(&node).Error; err != nil {
		fail(c, err)
		return
	}
	s.audit(c, actor(c), "node.update", "node", fmt.Sprint(node.ID), "{}")
	c.JSON(http.StatusOK, node)
}

func (s *Server) requestNodeUninstall(c *gin.Context) {
	var node models.Node
	if err := s.db.First(&node, c.Param("id")).Error; err != nil {
		notFound(c)
		return
	}
	if strings.EqualFold(c.Query("force"), "true") {
		metadata, _ := json.Marshal(map[string]any{
			"status":                  node.Status,
			"lastSeenAt":              node.LastSeenAt,
			"uninstallCommandId":      node.UninstallCommandID,
			"uninstallRequestedAt":    node.UninstallRequestedAt,
			"uninstallConfirmedAt":    node.UninstallConfirmedAt,
			"previousDesiredRevision": node.DesiredRevision,
		})
		if err := s.db.Delete(&node).Error; err != nil {
			fail(c, err)
			return
		}
		s.audit(c, actor(c), "node.delete.force", "node", fmt.Sprint(node.ID), string(metadata))
		c.Status(http.StatusNoContent)
		return
	}
	now := time.Now().UTC()
	if node.UninstallCommandID == "" {
		node.UninstallCommandID = fmt.Sprintf("uninstall-%d-%d", node.ID, now.UnixNano())
	}
	node.Status = "uninstalling"
	node.DesiredRevision = now.UnixNano()
	node.UninstallRequestedAt = &now
	node.UninstallConfirmedAt = nil
	node.UninstallAckStatus = ""
	node.UninstallAckMessage = ""
	node.UninstallAckAt = nil
	node.UninstallLegacy = false
	if err := s.db.Save(&node).Error; err != nil {
		fail(c, err)
		return
	}
	metadata, _ := json.Marshal(map[string]any{"commandId": node.UninstallCommandID})
	s.audit(c, actor(c), "node.uninstall.request", "node", fmt.Sprint(node.ID), string(metadata))
	c.JSON(http.StatusAccepted, node)
}

type deviceGroupPayload struct {
	Name             string  `json:"name"`
	Role             string  `json:"role"`
	BindIPs          string  `json:"bindIPs"`
	PortStart        int     `json:"portStart"`
	PortEnd          int     `json:"portEnd"`
	TrafficRatio     float64 `json:"trafficRatio"`
	ProtocolPolicyID *uint   `json:"protocolPolicyId"`
	FailoverGroupID  *uint   `json:"failoverGroupId"`
	AdvancedJSON     string  `json:"advancedJson"`
}

func (s *Server) listDeviceGroups(c *gin.Context) {
	query := s.db.Model(&models.DeviceGroup{})
	query = applySearch(query, c, "name", "role", "bind_ips")
	query = filterString(query, c, "role", "role")
	respondPage[models.DeviceGroup](c, query, "id desc")
}

func (s *Server) createDeviceGroup(c *gin.Context) {
	var req deviceGroupPayload
	if err := c.ShouldBindJSON(&req); err != nil {
		bad(c, err)
		return
	}
	row := models.DeviceGroup{}
	if err := s.applyDeviceGroupPayload(&row, req); err != nil {
		bad(c, err)
		return
	}
	if err := s.db.Create(&row).Error; err != nil {
		fail(c, err)
		return
	}
	s.afterDeviceGroupChange(c, s.db, &row, "create")
	c.JSON(http.StatusCreated, row)
}

func (s *Server) updateDeviceGroup(c *gin.Context) {
	var row models.DeviceGroup
	if err := s.db.First(&row, c.Param("id")).Error; err != nil {
		notFound(c)
		return
	}
	var req deviceGroupPayload
	if err := c.ShouldBindJSON(&req); err != nil {
		bad(c, err)
		return
	}
	if err := s.applyDeviceGroupPayload(&row, req); err != nil {
		bad(c, err)
		return
	}
	if err := s.db.Save(&row).Error; err != nil {
		fail(c, err)
		return
	}
	s.afterDeviceGroupChange(c, s.db, &row, "update")
	c.JSON(http.StatusOK, row)
}

func (s *Server) deleteDeviceGroup(c *gin.Context) {
	var row models.DeviceGroup
	if err := s.db.First(&row, c.Param("id")).Error; err != nil {
		notFound(c)
		return
	}
	var nodes, tunnels, endpoints, tokens int64
	checks := []struct {
		query *gorm.DB
		count *int64
	}{
		{s.db.Model(&models.Node{}).Where("device_group_id = ?", row.ID), &nodes},
		{s.db.Model(&models.Tunnel{}).Where("entry_group_id = ? OR exit_group_id = ?", row.ID, row.ID), &tunnels},
		{s.db.Model(&models.LineEndpoint{}).Where("device_group_id = ?", row.ID), &endpoints},
		{s.db.Model(&models.InstallToken{}).Where("device_group_id = ?", row.ID), &tokens},
	}
	for _, check := range checks {
		if err := check.query.Count(check.count).Error; err != nil {
			fail(c, err)
			return
		}
	}
	if nodes+tunnels+endpoints+tokens > 0 {
		bad(c, errors.New("device group is still referenced by nodes, tunnels, line endpoints, or install tokens"))
		return
	}
	if err := s.db.Delete(&row).Error; err != nil {
		fail(c, err)
		return
	}
	s.afterDeviceGroupChange(c, s.db, &row, "delete")
	c.Status(http.StatusNoContent)
}

func (s *Server) applyDeviceGroupPayload(row *models.DeviceGroup, req deviceGroupPayload) error {
	req.Name = strings.TrimSpace(req.Name)
	req.Role = strings.TrimSpace(req.Role)
	if req.Name == "" {
		return errors.New("name is required")
	}
	if req.Role == "" {
		req.Role = "entry"
	}
	if !contains([]string{"entry", "exit", "relay"}, req.Role) {
		return errors.New("role must be entry, exit, or relay")
	}
	if req.PortStart < 0 || req.PortEnd < 0 || req.PortStart > 65535 || req.PortEnd > 65535 {
		return errors.New("port range must be between 0 and 65535")
	}
	if req.PortStart > 0 && req.PortEnd > 0 && req.PortStart > req.PortEnd {
		return errors.New("portStart must be less than or equal to portEnd")
	}
	if req.TrafficRatio == 0 {
		req.TrafficRatio = 1
	}
	if req.TrafficRatio < 0 {
		return errors.New("trafficRatio must be non-negative")
	}
	if err := s.requireOptionalID(&models.ProtocolPolicy{}, req.ProtocolPolicyID, "protocol policy"); err != nil {
		return err
	}
	if err := s.requireOptionalID(&models.DeviceGroup{}, req.FailoverGroupID, "failover device group"); err != nil {
		return err
	}
	row.Name = req.Name
	row.Role = req.Role
	row.BindIPs = strings.TrimSpace(req.BindIPs)
	row.PortStart = req.PortStart
	row.PortEnd = req.PortEnd
	row.TrafficRatio = req.TrafficRatio
	row.ProtocolPolicyID = req.ProtocolPolicyID
	row.FailoverGroupID = req.FailoverGroupID
	row.AdvancedJSON = req.AdvancedJSON
	return nil
}

type tunnelPayload struct {
	Name              string  `json:"name"`
	Mode              string  `json:"mode"`
	EntryGroupID      uint    `json:"entryGroupId"`
	ExitGroupID       *uint   `json:"exitGroupId"`
	Protocol          string  `json:"protocol"`
	FlowAccounting    string  `json:"flowAccounting"`
	EntryTrafficRatio float64 `json:"entryTrafficRatio"`
	ExitTrafficRatio  float64 `json:"exitTrafficRatio"`
	ProtocolPolicyID  *uint   `json:"protocolPolicyId"`
	LineCircuitID     *uint   `json:"lineCircuitId"`
	AdvancedJSON      string  `json:"advancedJson"`
}

func (s *Server) listTunnels(c *gin.Context) {
	query := s.db.Model(&models.Tunnel{})
	switch ctxRole(c) {
	case "admin":
	case "user":
		var directGrantCount int64
		if err := s.db.Model(&models.UserTunnelGrant{}).Where("user_id = ?", ctxUserID(c)).Count(&directGrantCount).Error; err != nil {
			fail(c, err)
			return
		}
		if directGrantCount > 0 {
			grants := s.db.Model(&models.UserTunnelGrant{}).
				Select("tunnel_id").
				Where("user_id = ?", ctxUserID(c))
			query = query.Where("id IN (?)", grants)
		} else if ctxTenantID(c) > 0 {
			grants := s.db.Model(&models.TenantTunnelGrant{}).
				Select("tunnel_id").
				Where("tenant_id = ?", ctxTenantID(c))
			query = query.Where("id IN (?)", grants)
		} else {
			query = query.Where("1 = 0")
		}
	case "tenant_admin":
		if ctxTenantID(c) == 0 {
			query = query.Where("1 = 0")
		} else {
			grants := s.db.Model(&models.TenantTunnelGrant{}).
				Select("tunnel_id").
				Where("tenant_id = ?", ctxTenantID(c))
			query = query.Where("id IN (?)", grants)
		}
	default:
		query = query.Where("1 = 0")
	}
	query = applySearch(query, c, "name", "mode", "protocol", "flow_accounting")
	query = filterString(query, c, "mode", "mode")
	query = filterUint(query, c, "entry_group_id", "entryGroupId")
	query = filterUint(query, c, "exit_group_id", "exitGroupId")
	query = filterUint(query, c, "line_circuit_id", "lineCircuitId")
	respondPage[models.Tunnel](c, query, "id desc")
}

func (s *Server) createTunnel(c *gin.Context) {
	var req tunnelPayload
	if err := c.ShouldBindJSON(&req); err != nil {
		bad(c, err)
		return
	}
	row := models.Tunnel{}
	if err := s.applyTunnelPayload(&row, req); err != nil {
		bad(c, err)
		return
	}
	if err := s.db.Create(&row).Error; err != nil {
		fail(c, err)
		return
	}
	s.afterTunnelChange(c, s.db, &row, "create")
	c.JSON(http.StatusCreated, row)
}

func (s *Server) updateTunnel(c *gin.Context) {
	var row models.Tunnel
	if err := s.db.First(&row, c.Param("id")).Error; err != nil {
		notFound(c)
		return
	}
	previous := row
	var req tunnelPayload
	if err := c.ShouldBindJSON(&req); err != nil {
		bad(c, err)
		return
	}
	if err := s.applyTunnelPayload(&row, req); err != nil {
		bad(c, err)
		return
	}
	if err := s.db.Save(&row).Error; err != nil {
		fail(c, err)
		return
	}
	s.afterTunnelUpdate(c, s.db, &previous, &row)
	c.JSON(http.StatusOK, row)
}

func (s *Server) deleteTunnel(c *gin.Context) {
	var row models.Tunnel
	if err := s.db.First(&row, c.Param("id")).Error; err != nil {
		notFound(c)
		return
	}
	var rules, limits, tenantGrants, userGrants int64
	if err := s.db.Model(&models.ForwardRule{}).Where("tunnel_id = ?", row.ID).Count(&rules).Error; err != nil {
		fail(c, err)
		return
	}
	if err := s.db.Model(&models.SpeedLimit{}).Where("tunnel_id = ?", row.ID).Count(&limits).Error; err != nil {
		fail(c, err)
		return
	}
	if err := s.db.Model(&models.TenantTunnelGrant{}).Where("tunnel_id = ?", row.ID).Count(&tenantGrants).Error; err != nil {
		fail(c, err)
		return
	}
	if err := s.db.Model(&models.UserTunnelGrant{}).Where("tunnel_id = ?", row.ID).Count(&userGrants).Error; err != nil {
		fail(c, err)
		return
	}
	if rules+limits+tenantGrants+userGrants > 0 {
		bad(c, errors.New("tunnel is still referenced by forwarding rules, speed limits, or line grants"))
		return
	}
	if err := s.db.Delete(&row).Error; err != nil {
		fail(c, err)
		return
	}
	s.afterTunnelChange(c, s.db, &row, "delete")
	c.Status(http.StatusNoContent)
}

func (s *Server) applyTunnelPayload(row *models.Tunnel, req tunnelPayload) error {
	req.Name = strings.TrimSpace(req.Name)
	if req.Name == "" {
		return errors.New("name is required")
	}
	if req.Mode == "" {
		req.Mode = "single"
	}
	if !contains([]string{"single", "relay", "failover"}, req.Mode) {
		return errors.New("mode must be single, relay, or failover")
	}
	if req.Protocol == "" {
		req.Protocol = "direct"
	}
	if !contains([]string{"direct", "tcp", "tls", "ws", "wss", "ws_over_tls", "ws-over-tls", "quic"}, req.Protocol) {
		return errors.New("unsupported tunnel protocol")
	}
	if req.FlowAccounting == "" {
		req.FlowAccounting = "single"
	}
	if !contains([]string{"single", "entry", "exit", "both"}, req.FlowAccounting) {
		return errors.New("flowAccounting must be single, entry, exit, or both")
	}
	if req.EntryGroupID == 0 {
		return errors.New("entryGroupId is required")
	}
	if err := s.requireID(&models.DeviceGroup{}, req.EntryGroupID, "entry device group"); err != nil {
		return err
	}
	if err := s.requireOptionalID(&models.DeviceGroup{}, req.ExitGroupID, "exit device group"); err != nil {
		return err
	}
	if err := s.requireOptionalID(&models.ProtocolPolicy{}, req.ProtocolPolicyID, "protocol policy"); err != nil {
		return err
	}
	if err := s.requireOptionalID(&models.LineCircuit{}, req.LineCircuitID, "line circuit"); err != nil {
		return err
	}
	if req.EntryTrafficRatio == 0 {
		req.EntryTrafficRatio = 1
	}
	if req.ExitTrafficRatio == 0 {
		req.ExitTrafficRatio = 1
	}
	if req.EntryTrafficRatio < 0 || req.ExitTrafficRatio < 0 {
		return errors.New("traffic ratios must be non-negative")
	}
	row.Name = req.Name
	row.Mode = req.Mode
	row.EntryGroupID = req.EntryGroupID
	row.ExitGroupID = req.ExitGroupID
	row.Protocol = req.Protocol
	row.FlowAccounting = req.FlowAccounting
	row.EntryTrafficRatio = req.EntryTrafficRatio
	row.ExitTrafficRatio = req.ExitTrafficRatio
	row.ProtocolPolicyID = req.ProtocolPolicyID
	row.LineCircuitID = req.LineCircuitID
	row.AdvancedJSON = req.AdvancedJSON
	return nil
}

type protocolPolicyPayload struct {
	Name                    string `json:"name"`
	Template                string `json:"template"`
	Purpose                 string `json:"purpose"`
	InspectionLevel         string `json:"inspectionLevel"`
	Mode                    string `json:"mode"`
	BlockTLS                bool   `json:"blockTls"`
	BlockQUIC               bool   `json:"blockQuic"`
	AllowPlainTCPOnly       bool   `json:"allowPlainTcpOnly"`
	AllowHTTPOnly           bool   `json:"allowHttpOnly"`
	BlockProxyLike          bool   `json:"blockProxyLike"`
	BlockEncryptedTunnel    bool   `json:"blockEncryptedTunnel"`
	ObservationMinutes      int    `json:"observationMinutes"`
	AuthorizedProtocols     string `json:"authorizedProtocols"`
	BlockedProtocolGroups   string `json:"blockedProtocolGroups"`
	HostAllowlist           string `json:"hostAllowlist"`
	HostBlocklist           string `json:"hostBlocklist"`
	SNIAllowlist            string `json:"sniAllowlist"`
	SNIBlocklist            string `json:"sniBlocklist"`
	ALPNAllowlist           string `json:"alpnAllowlist"`
	ALPNBlocklist           string `json:"alpnBlocklist"`
	TLSNoSNIAction          string `json:"tlsNoSniAction"`
	QUICAction              string `json:"quicAction"`
	SSHAction               string `json:"sshAction"`
	UnknownTCPAction        string `json:"unknownTcpAction"`
	UnknownUDPAction        string `json:"unknownUdpAction"`
	NDPILowConfidenceAction string `json:"ndpiLowConfidenceAction"`
	DPITimeoutMs            int    `json:"dpiTimeoutMs"`
	Description             string `json:"description"`
}

func (s *Server) listProtocolPolicies(c *gin.Context) {
	query := s.db.Model(&models.ProtocolPolicy{})
	query = applySearch(query, c, "name", "template", "purpose", "mode", "inspection_level", "description")
	query = filterString(query, c, "mode", "mode")
	query = filterString(query, c, "purpose", "purpose")
	query = filterString(query, c, "inspection_level", "inspectionLevel")
	respondPage[models.ProtocolPolicy](c, query, "id desc")
}

func (s *Server) createProtocolPolicy(c *gin.Context) {
	var req protocolPolicyPayload
	if err := c.ShouldBindJSON(&req); err != nil {
		bad(c, err)
		return
	}
	row := models.ProtocolPolicy{}
	if err := applyProtocolPolicyPayload(&row, req); err != nil {
		bad(c, err)
		return
	}
	if err := s.db.Create(&row).Error; err != nil {
		fail(c, err)
		return
	}
	s.afterProtocolPolicyChange(c, s.db, &row, "create")
	c.JSON(http.StatusCreated, row)
}

func (s *Server) updateProtocolPolicy(c *gin.Context) {
	var row models.ProtocolPolicy
	if err := s.db.First(&row, c.Param("id")).Error; err != nil {
		notFound(c)
		return
	}
	var req protocolPolicyPayload
	if err := c.ShouldBindJSON(&req); err != nil {
		bad(c, err)
		return
	}
	if err := applyProtocolPolicyPayload(&row, req); err != nil {
		bad(c, err)
		return
	}
	if err := s.db.Save(&row).Error; err != nil {
		fail(c, err)
		return
	}
	s.afterProtocolPolicyChange(c, s.db, &row, "update")
	c.JSON(http.StatusOK, row)
}

func (s *Server) deleteProtocolPolicy(c *gin.Context) {
	var row models.ProtocolPolicy
	if err := s.db.First(&row, c.Param("id")).Error; err != nil {
		notFound(c)
		return
	}
	var groups, tunnels, rules int64
	if err := s.db.Model(&models.DeviceGroup{}).Where("protocol_policy_id = ?", row.ID).Count(&groups).Error; err != nil {
		fail(c, err)
		return
	}
	if err := s.db.Model(&models.Tunnel{}).Where("protocol_policy_id = ?", row.ID).Count(&tunnels).Error; err != nil {
		fail(c, err)
		return
	}
	if err := s.db.Model(&models.ForwardRule{}).Where("protocol_policy_id = ?", row.ID).Count(&rules).Error; err != nil {
		fail(c, err)
		return
	}
	if groups+tunnels+rules > 0 {
		bad(c, errors.New("protocol policy is still referenced by device groups, tunnels, or forwarding rules"))
		return
	}
	if err := s.db.Delete(&row).Error; err != nil {
		fail(c, err)
		return
	}
	s.afterProtocolPolicyChange(c, s.db, &row, "delete")
	c.Status(http.StatusNoContent)
}

func applyProtocolPolicyPayload(row *models.ProtocolPolicy, req protocolPolicyPayload) error {
	req.Name = strings.TrimSpace(req.Name)
	if req.Name == "" {
		return errors.New("name is required")
	}
	if req.Template == "" {
		req.Template = "custom"
	}
	if !contains([]string{"none", "iepl_iplc_no_tls", "plain_tcp_only", "http_only", "block_proxy_like", "game_acceleration", "authorized_ss", "ssh_ops", "daily_browsing", "normal_forward", "strict_compliance", "custom"}, req.Template) {
		return errors.New("unsupported protocol policy template")
	}
	if req.Purpose == "" {
		req.Purpose = purposeFromTemplate(req.Template)
	}
	if !contains([]string{"gaming", "authorized_ss", "ssh_ops", "daily", "normal", "strict", "custom"}, req.Purpose) {
		return errors.New("unsupported protocol policy purpose")
	}
	if req.InspectionLevel == "" {
		req.InspectionLevel = "light"
	}
	if !contains([]string{"off", "light", "advanced", "deep", "ndpi"}, req.InspectionLevel) {
		return errors.New("inspectionLevel must be off, light, advanced, deep, or ndpi")
	}
	if req.Mode == "" {
		req.Mode = "block"
	}
	if !validPolicyAction(req.Mode, false) {
		return errors.New("mode must be observe, alert, limit, or block")
	}
	for name, action := range map[string]string{
		"tlsNoSniAction":          req.TLSNoSNIAction,
		"quicAction":              req.QUICAction,
		"sshAction":               req.SSHAction,
		"unknownTcpAction":        req.UnknownTCPAction,
		"unknownUdpAction":        req.UnknownUDPAction,
		"ndpiLowConfidenceAction": req.NDPILowConfidenceAction,
	} {
		if !validPolicyAction(action, true) {
			return fmt.Errorf("%s must be allow, observe, alert, limit, or block", name)
		}
	}
	if req.ObservationMinutes < 0 {
		return errors.New("observationMinutes must be non-negative")
	}
	if req.DPITimeoutMs < 0 {
		return errors.New("dpiTimeoutMs must be non-negative")
	}
	applyPolicyTemplateDefaults(&req)
	row.Name = req.Name
	row.Template = req.Template
	row.Purpose = req.Purpose
	row.InspectionLevel = req.InspectionLevel
	row.Mode = req.Mode
	row.BlockTLS = req.BlockTLS
	row.BlockQUIC = req.BlockQUIC
	row.AllowPlainTCPOnly = req.AllowPlainTCPOnly
	row.AllowHTTPOnly = req.AllowHTTPOnly
	row.BlockProxyLike = req.BlockProxyLike
	row.BlockEncryptedTunnel = req.BlockEncryptedTunnel
	row.ObservationMinutes = req.ObservationMinutes
	row.AuthorizedProtocols = normalizeTextList(req.AuthorizedProtocols)
	row.BlockedProtocolGroups = normalizeTextList(req.BlockedProtocolGroups)
	row.HostAllowlist = normalizeTextList(req.HostAllowlist)
	row.HostBlocklist = normalizeTextList(req.HostBlocklist)
	row.SNIAllowlist = normalizeTextList(req.SNIAllowlist)
	row.SNIBlocklist = normalizeTextList(req.SNIBlocklist)
	row.ALPNAllowlist = normalizeTextList(req.ALPNAllowlist)
	row.ALPNBlocklist = normalizeTextList(req.ALPNBlocklist)
	row.TLSNoSNIAction = req.TLSNoSNIAction
	row.QUICAction = req.QUICAction
	row.SSHAction = req.SSHAction
	row.UnknownTCPAction = req.UnknownTCPAction
	row.UnknownUDPAction = req.UnknownUDPAction
	row.NDPILowConfidenceAction = req.NDPILowConfidenceAction
	row.DPITimeoutMs = req.DPITimeoutMs
	row.Description = req.Description
	return nil
}

func purposeFromTemplate(template string) string {
	switch strings.TrimSpace(template) {
	case "game_acceleration":
		return "gaming"
	case "authorized_ss":
		return "authorized_ss"
	case "ssh_ops":
		return "ssh_ops"
	case "daily_browsing":
		return "daily"
	case "normal_forward", "plain_tcp_only", "http_only", "block_proxy_like":
		return "normal"
	case "strict_compliance", "iepl_iplc_no_tls":
		return "strict"
	default:
		return "custom"
	}
}

func applyPolicyTemplateDefaults(req *protocolPolicyPayload) {
	if req.Mode == "" {
		req.Mode = "block"
	}
	switch req.Purpose {
	case "gaming":
		req.BlockProxyLike = true
		req.QUICAction = defaultString(req.QUICAction, "allow")
		req.SSHAction = defaultString(req.SSHAction, "block")
		req.UnknownTCPAction = defaultString(req.UnknownTCPAction, "allow")
		req.UnknownUDPAction = defaultString(req.UnknownUDPAction, "allow")
		req.NDPILowConfidenceAction = defaultString(req.NDPILowConfidenceAction, "allow")
		req.BlockedProtocolGroups = defaultString(req.BlockedProtocolGroups, "proxy,p2p,vpn,remote_access")
	case "authorized_ss":
		req.BlockProxyLike = true
		req.AuthorizedProtocols = defaultString(req.AuthorizedProtocols, "ss,shadowsocks,ss2022,2022-blake3-aes-256-gcm")
		req.QUICAction = defaultString(req.QUICAction, "allow")
		req.SSHAction = defaultString(req.SSHAction, "block")
		req.UnknownTCPAction = defaultString(req.UnknownTCPAction, "allow")
		req.UnknownUDPAction = defaultString(req.UnknownUDPAction, "allow")
		req.NDPILowConfidenceAction = defaultString(req.NDPILowConfidenceAction, "allow")
		req.BlockedProtocolGroups = defaultString(req.BlockedProtocolGroups, "p2p,vpn,remote_access")
	case "ssh_ops":
		req.BlockProxyLike = true
		req.SSHAction = defaultString(req.SSHAction, "allow")
		req.UnknownTCPAction = defaultString(req.UnknownTCPAction, "alert")
		req.UnknownUDPAction = defaultString(req.UnknownUDPAction, "block")
		req.NDPILowConfidenceAction = defaultString(req.NDPILowConfidenceAction, "alert")
		req.BlockedProtocolGroups = defaultString(req.BlockedProtocolGroups, "proxy,p2p,vpn")
	case "daily":
		req.BlockProxyLike = true
		req.QUICAction = defaultString(req.QUICAction, "allow")
		req.SSHAction = defaultString(req.SSHAction, "block")
		req.UnknownTCPAction = defaultString(req.UnknownTCPAction, "allow")
		req.UnknownUDPAction = defaultString(req.UnknownUDPAction, "allow")
		req.NDPILowConfidenceAction = defaultString(req.NDPILowConfidenceAction, "allow")
		req.BlockedProtocolGroups = defaultString(req.BlockedProtocolGroups, "proxy,p2p,vpn,remote_access")
	case "normal":
		req.BlockProxyLike = true
		req.SSHAction = defaultString(req.SSHAction, "block")
		req.UnknownTCPAction = defaultString(req.UnknownTCPAction, "alert")
		req.UnknownUDPAction = defaultString(req.UnknownUDPAction, "allow")
		req.NDPILowConfidenceAction = defaultString(req.NDPILowConfidenceAction, "alert")
		req.BlockedProtocolGroups = defaultString(req.BlockedProtocolGroups, "proxy,p2p,vpn,remote_access")
	case "strict":
		req.BlockProxyLike = true
		req.BlockEncryptedTunnel = true
		req.TLSNoSNIAction = defaultString(req.TLSNoSNIAction, "alert")
		req.QUICAction = defaultString(req.QUICAction, "alert")
		req.SSHAction = defaultString(req.SSHAction, "block")
		req.UnknownTCPAction = defaultString(req.UnknownTCPAction, "alert")
		req.UnknownUDPAction = defaultString(req.UnknownUDPAction, "alert")
		req.NDPILowConfidenceAction = defaultString(req.NDPILowConfidenceAction, "alert")
		req.BlockedProtocolGroups = defaultString(req.BlockedProtocolGroups, "proxy,p2p,vpn,remote_access,encrypted_tunnel")
	}
}

func validPolicyAction(action string, allowEmpty bool) bool {
	action = strings.TrimSpace(action)
	if action == "" {
		return allowEmpty
	}
	return contains([]string{"allow", "observe", "alert", "limit", "block"}, action)
}

func normalizeTextList(value string) string {
	parts := splitPolicyList(value)
	if len(parts) == 0 {
		return ""
	}
	seen := map[string]bool{}
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		key := strings.ToLower(part)
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, part)
	}
	return strings.Join(out, "\n")
}

func splitPolicyList(value string) []string {
	parts := strings.FieldsFunc(value, func(r rune) bool {
		return r == ',' || r == '\n' || r == '\r' || r == ';' || r == '\t'
	})
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

func (s *Server) evaluateProtocolPolicy(c *gin.Context) {
	var req struct {
		PolicyID     uint                  `json:"policyId"`
		Policy       protocolPolicyPayload `json:"policy"`
		Protocol     string                `json:"protocol"`
		Network      string                `json:"network"`
		Host         string                `json:"host"`
		ALPN         []string              `json:"alpn"`
		NDPIProtocol string                `json:"ndpiProtocol"`
		NDPICategory string                `json:"ndpiCategory"`
		Confidence   int                   `json:"confidence"`
		RiskScore    int                   `json:"riskScore"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		bad(c, err)
		return
	}
	var policy models.ProtocolPolicy
	if req.PolicyID > 0 {
		if err := s.db.First(&policy, req.PolicyID).Error; err != nil {
			notFound(c)
			return
		}
	} else {
		if err := applyProtocolPolicyPayload(&policy, req.Policy); err != nil {
			bad(c, err)
			return
		}
	}
	action, reason, matched := evaluatePolicyPreview(policy, req.Protocol, req.Network, req.Host, req.ALPN, req.NDPIProtocol, req.NDPICategory, req.Confidence, req.RiskScore)
	c.JSON(http.StatusOK, gin.H{
		"action":      action,
		"reason":      reason,
		"matchedRule": matched,
		"policy":      policy,
	})
}

func evaluatePolicyPreview(policy models.ProtocolPolicy, protocolName, network, host string, alpn []string, ndpiProtocol, ndpiCategory string, confidence, riskScore int) (string, string, string) {
	protocolName = normalizePolicyToken(protocolName)
	network = normalizePolicyToken(network)
	if protocolName == "" {
		protocolName = "unknown"
	}
	if matched := firstPolicyHostMatch(host, policy.HostAllowlist, policy.SNIAllowlist); matched != "" {
		return "allow", "host is allowlisted", "host allowlist: " + matched
	}
	if matched := firstPolicyHostMatch(host, policy.HostBlocklist, policy.SNIBlocklist); matched != "" {
		return policyAction(policy.Mode, "block"), "host is blocklisted", "host blocklist: " + matched
	}
	if matched := firstPolicyALPNMatch(alpn, policy.ALPNAllowlist); matched != "" {
		return "allow", "alpn is allowlisted", "alpn allowlist: " + matched
	}
	if matched := firstPolicyALPNMatch(alpn, policy.ALPNBlocklist); matched != "" {
		return policyAction(policy.Mode, "block"), "alpn is blocklisted", "alpn blocklist: " + matched
	}
	switch {
	case policy.BlockTLS && protocolName == "tls":
		return policyAction(policy.Mode, "block"), "tls is blocked", "blockTls"
	case policy.BlockQUIC && protocolName == "quic":
		return policyAction(policy.Mode, "block"), "quic is blocked", "blockQuic"
	case policy.BlockProxyLike && (protocolName == "socks" || protocolName == "http_connect"):
		return policyAction(policy.Mode, "block"), "proxy-like protocol is blocked", "blockProxyLike"
	case policy.BlockEncryptedTunnel && (protocolName == "tls" || protocolName == "quic" || protocolName == "ssh"):
		return policyAction(policy.Mode, "block"), "encrypted tunnel protocol is blocked", "blockEncryptedTunnel"
	case policy.AllowHTTPOnly && protocolName != "http":
		return policyAction(policy.Mode, "block"), "only http is allowed", "allowHttpOnly"
	case policy.AllowPlainTCPOnly && protocolName != "unknown":
		return policyAction(policy.Mode, "block"), "only plain tcp is allowed", "allowPlainTcpOnly"
	}
	if protocolName == "tls" && strings.TrimSpace(host) == "" && policy.TLSNoSNIAction != "" && policy.TLSNoSNIAction != "allow" {
		return policyAction(policy.TLSNoSNIAction, "block"), "tls has no sni", "tls_no_sni"
	}
	if protocolName == "quic" && policy.QUICAction != "" && policy.QUICAction != "allow" {
		return policyAction(policy.QUICAction, "alert"), "quic matched policy action", "quic_action"
	}
	if protocolName == "ssh" && policy.SSHAction != "" && policy.SSHAction != "allow" {
		return policyAction(policy.SSHAction, "block"), "ssh matched policy action", "ssh_action"
	}
	if protocolName == "unknown" {
		if containsPolicyToken(policy.AuthorizedProtocols, "ss", "shadowsocks", "ss2022") || policy.Purpose == "authorized_ss" {
			return "allow", "unknown first packet is allowed for authorized protocol entry", "authorized encrypted entry"
		}
		action := policy.UnknownTCPAction
		if network == "udp" {
			action = policy.UnknownUDPAction
		}
		if action != "" && action != "allow" {
			return policyAction(action, "alert"), "unknown protocol matched policy action", "unknown_action"
		}
	}
	if confidence > 0 && confidence < 50 && policy.NDPILowConfidenceAction != "" && policy.NDPILowConfidenceAction != "allow" {
		return policyAction(policy.NDPILowConfidenceAction, "alert"), "ndpi confidence is low", "ndpi_low_confidence"
	}
	if matched := matchedPolicyBlockedGroup(policy.BlockedProtocolGroups, ndpiProtocol, ndpiCategory); matched != "" {
		return policyAction(policy.Mode, "block"), "ndpi matched blocked protocol group", "ndpi_group:" + matched
	}
	if riskScore >= 80 {
		return policyAction(policy.Mode, "block"), "ndpi high risk protocol", "ndpi_high_risk"
	}
	if riskScore >= 50 {
		return policyAction(policy.Mode, "alert"), "ndpi medium risk protocol", "ndpi_medium_risk"
	}
	return "allow", "policy would allow this flow", ""
}

func policyAction(action, fallback string) string {
	action = strings.TrimSpace(action)
	if contains([]string{"allow", "observe", "alert", "limit", "block"}, action) {
		return action
	}
	if contains([]string{"allow", "observe", "alert", "limit", "block"}, fallback) {
		return fallback
	}
	return "block"
}

func firstPolicyHostMatch(host string, lists ...string) string {
	host = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
	if host == "" {
		return ""
	}
	if withoutPort, _, ok := strings.Cut(host, ":"); ok {
		host = strings.TrimSuffix(withoutPort, ".")
	}
	for _, list := range lists {
		for _, pattern := range splitPolicyList(list) {
			if matchPolicyHost(host, pattern) {
				return pattern
			}
		}
	}
	return ""
}

func matchPolicyHost(host, pattern string) bool {
	pattern = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(pattern), "."))
	if strings.HasPrefix(pattern, "*.") {
		suffix := strings.TrimPrefix(pattern, "*")
		return strings.HasSuffix(host, suffix) && host != strings.TrimPrefix(suffix, ".")
	}
	return host == pattern
}

func firstPolicyALPNMatch(values []string, list string) string {
	for _, value := range values {
		value = normalizePolicyToken(value)
		for _, pattern := range splitPolicyList(list) {
			if value == normalizePolicyToken(pattern) {
				return pattern
			}
		}
	}
	return ""
}

func containsPolicyToken(list string, needles ...string) bool {
	for _, value := range splitPolicyList(list) {
		value = normalizePolicyToken(value)
		for _, needle := range needles {
			if value == normalizePolicyToken(needle) {
				return true
			}
		}
	}
	return false
}

func matchedPolicyBlockedGroup(groups, protocolName, category string) string {
	protocolName = normalizePolicyToken(protocolName)
	category = normalizePolicyToken(category)
	for _, group := range splitPolicyList(groups) {
		group = normalizePolicyToken(group)
		if group == "" {
			continue
		}
		if group == protocolName || group == category {
			return group
		}
		switch group {
		case "proxy":
			if strings.Contains(protocolName, "socks") || strings.Contains(protocolName, "shadowsocks") || strings.Contains(protocolName, "v2ray") || strings.Contains(protocolName, "trojan") {
				return group
			}
		case "vpn", "encrypted_tunnel":
			if strings.Contains(protocolName, "wireguard") || strings.Contains(protocolName, "openvpn") || strings.Contains(protocolName, "hysteria") || strings.Contains(protocolName, "tuic") || strings.Contains(category, "vpn") || strings.Contains(category, "tunnel") {
				return group
			}
		case "p2p", "bt", "bittorrent":
			if strings.Contains(protocolName, "bittorrent") || strings.Contains(category, "p2p") {
				return group
			}
		case "remote_access":
			if strings.Contains(protocolName, "ssh") || strings.Contains(protocolName, "rdp") || strings.Contains(category, "remote") {
				return group
			}
		}
	}
	return ""
}

func normalizePolicyToken(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	value = strings.ReplaceAll(value, "-", "_")
	value = strings.ReplaceAll(value, " ", "_")
	return value
}

type speedLimitPayload struct {
	Name        string `json:"name"`
	TenantID    *uint  `json:"tenantId"`
	UserID      *uint  `json:"userId"`
	TunnelID    *uint  `json:"tunnelId"`
	RuleID      *uint  `json:"ruleId"`
	UploadBps   int64  `json:"uploadBps"`
	DownloadBps int64  `json:"downloadBps"`
	MaxConns    int    `json:"maxConns"`
	MaxIPs      int    `json:"maxIps"`
}

func (s *Server) listSpeedLimits(c *gin.Context) {
	query := s.db.Model(&models.SpeedLimit{})
	query = applySearch(query, c, "name")
	query = filterUint(query, c, "tenant_id", "tenantId")
	query = filterUint(query, c, "user_id", "userId")
	query = filterUint(query, c, "tunnel_id", "tunnelId")
	query = filterUint(query, c, "rule_id", "ruleId")
	respondPage[models.SpeedLimit](c, query, "id desc")
}

func (s *Server) createSpeedLimit(c *gin.Context) {
	var req speedLimitPayload
	if err := c.ShouldBindJSON(&req); err != nil {
		bad(c, err)
		return
	}
	row := models.SpeedLimit{}
	if err := s.applySpeedLimitPayload(&row, req); err != nil {
		bad(c, err)
		return
	}
	if err := s.db.Create(&row).Error; err != nil {
		fail(c, err)
		return
	}
	s.afterSpeedLimitChange(c, s.db, &row, "create")
	c.JSON(http.StatusCreated, row)
}

func (s *Server) updateSpeedLimit(c *gin.Context) {
	var row models.SpeedLimit
	if err := s.db.First(&row, c.Param("id")).Error; err != nil {
		notFound(c)
		return
	}
	var req speedLimitPayload
	if err := c.ShouldBindJSON(&req); err != nil {
		bad(c, err)
		return
	}
	if err := s.applySpeedLimitPayload(&row, req); err != nil {
		bad(c, err)
		return
	}
	if err := s.db.Save(&row).Error; err != nil {
		fail(c, err)
		return
	}
	s.afterSpeedLimitChange(c, s.db, &row, "update")
	c.JSON(http.StatusOK, row)
}

func (s *Server) deleteSpeedLimit(c *gin.Context) {
	var row models.SpeedLimit
	if err := s.db.First(&row, c.Param("id")).Error; err != nil {
		notFound(c)
		return
	}
	if err := s.db.Delete(&row).Error; err != nil {
		fail(c, err)
		return
	}
	s.afterSpeedLimitChange(c, s.db, &row, "delete")
	c.Status(http.StatusNoContent)
}

func (s *Server) applySpeedLimitPayload(row *models.SpeedLimit, req speedLimitPayload) error {
	req.Name = strings.TrimSpace(req.Name)
	if req.Name == "" {
		return errors.New("name is required")
	}
	if req.UploadBps < 0 || req.DownloadBps < 0 || req.MaxConns < 0 || req.MaxIPs < 0 {
		return errors.New("speed limit values must be non-negative")
	}
	scopeCount := 0
	for _, id := range []*uint{req.TenantID, req.UserID, req.TunnelID, req.RuleID} {
		if id != nil && *id > 0 {
			scopeCount++
		}
	}
	if scopeCount == 0 {
		return errors.New("one of tenantId, userId, tunnelId, or ruleId is required")
	}
	if scopeCount > 1 {
		return errors.New("speed limits must target exactly one tenant, user, tunnel, or rule")
	}
	if err := s.requireOptionalID(&models.Tenant{}, req.TenantID, "tenant"); err != nil {
		return err
	}
	if err := s.requireOptionalID(&models.User{}, req.UserID, "user"); err != nil {
		return err
	}
	if err := s.requireOptionalID(&models.Tunnel{}, req.TunnelID, "tunnel"); err != nil {
		return err
	}
	if err := s.requireOptionalID(&models.ForwardRule{}, req.RuleID, "forward rule"); err != nil {
		return err
	}
	row.Name = req.Name
	row.TenantID = req.TenantID
	row.UserID = req.UserID
	row.TunnelID = req.TunnelID
	row.RuleID = req.RuleID
	row.UploadBps = req.UploadBps
	row.DownloadBps = req.DownloadBps
	row.MaxConns = req.MaxConns
	row.MaxIPs = req.MaxIPs
	return nil
}

func (s *Server) requireID(model any, id uint, name string) error {
	if id == 0 {
		return fmt.Errorf("%s is required", name)
	}
	if err := s.db.First(model, id).Error; err != nil {
		return fmt.Errorf("%s not found", name)
	}
	return nil
}

func (s *Server) requireOptionalID(model any, id *uint, name string) error {
	if id == nil || *id == 0 {
		return nil
	}
	return s.requireID(model, *id, name)
}

func (s *Server) afterTunnelChange(c *gin.Context, db *gorm.DB, tunnel *models.Tunnel, action string) {
	revision := time.Now().UnixNano()
	ids := tunnelGroupIDs(tunnel)
	_ = bumpNodesByGroupWithDB(db, ids, revision)
	s.audit(c, actor(c), "tunnel."+action, "tunnel", fmt.Sprint(tunnel.ID), "{}")
}

func (s *Server) afterTunnelUpdate(c *gin.Context, db *gorm.DB, previous, tunnel *models.Tunnel) {
	revision := time.Now().UnixNano()
	groups := map[uint]struct{}{}
	for _, id := range append(tunnelGroupIDs(previous), tunnelGroupIDs(tunnel)...) {
		groups[id] = struct{}{}
	}
	_ = bumpNodesByGroupWithDB(db, uintSetValues(groups), revision)
	s.audit(c, actor(c), "tunnel.update", "tunnel", fmt.Sprint(tunnel.ID), "{}")
}

func tunnelGroupIDs(tunnel *models.Tunnel) []uint {
	ids := []uint{tunnel.EntryGroupID}
	if tunnel.ExitGroupID != nil {
		ids = append(ids, *tunnel.ExitGroupID)
	}
	return ids
}

func (s *Server) afterDeviceGroupChange(c *gin.Context, db *gorm.DB, group *models.DeviceGroup, action string) {
	_ = bumpNodesByGroupWithDB(db, []uint{group.ID}, time.Now().UnixNano())
	s.audit(c, actor(c), "device_group."+action, "device_group", fmt.Sprint(group.ID), "{}")
}

func (s *Server) afterProtocolPolicyChange(c *gin.Context, db *gorm.DB, policy *models.ProtocolPolicy, action string) {
	revision := time.Now().UnixNano()
	db.Model(&models.Node{}).Where("id > ?", 0).
		Update("desired_revision", desiredRevisionExpr(revision))
	s.audit(c, actor(c), "protocol_policy."+action, "protocol_policy", fmt.Sprint(policy.ID), "{}")
}

func (s *Server) afterSpeedLimitChange(c *gin.Context, db *gorm.DB, limit *models.SpeedLimit, action string) {
	revision := time.Now().UnixNano()
	db.Model(&models.Node{}).Where("id > ?", 0).
		Update("desired_revision", desiredRevisionExpr(revision))
	s.audit(c, actor(c), "speed_limit."+action, "speed_limit", fmt.Sprint(limit.ID), "{}")
}

func (s *Server) listForwardRules(c *gin.Context) {
	query := s.db.Model(&models.ForwardRule{})
	if ctxRole(c) == "tenant_admin" {
		query = query.Where("tenant_id = ?", ctxTenantID(c))
	} else if ctxRole(c) != "admin" {
		query = query.Where("user_id = ?", ctxUserID(c))
	}
	query = applySearch(query, c, "name", "protocol", "remote_host", "status", "strategy")
	query = filterString(query, c, "status", "status")
	query = filterUint(query, c, "user_id", "userId")
	query = filterUint(query, c, "tunnel_id", "tunnelId")
	query = filterUint(query, c, "id", "ruleId")
	respondPage[models.ForwardRule](c, query, "id desc")
}

type forwardRulePayload struct {
	UserID           uint   `json:"userId"`
	TunnelID         uint   `json:"tunnelId"`
	Name             string `json:"name"`
	Protocol         string `json:"protocol"`
	ListenPort       int    `json:"listenPort"`
	RemoteHost       string `json:"remoteHost"`
	RemotePort       int    `json:"remotePort"`
	Status           string `json:"status"`
	Strategy         string `json:"strategy"`
	ProtocolPolicyID *uint  `json:"protocolPolicyId"`
}

func (s *Server) createForwardRule(c *gin.Context) {
	var req forwardRulePayload
	if err := c.ShouldBindJSON(&req); err != nil {
		bad(c, err)
		return
	}
	policyID, err := forwardRulePolicyForActor(c, req.ProtocolPolicyID, nil)
	if err != nil {
		bad(c, err)
		return
	}
	req.ProtocolPolicyID = policyID
	var rule models.ForwardRule
	if err := s.applyForwardRulePayload(&rule, req); err != nil {
		bad(c, err)
		return
	}
	if ctxRole(c) != "admin" {
		if ctxRole(c) == "user" {
			rule.UserID = ctxUserID(c)
		} else if !s.userBelongsToTenant(rule.UserID, ctxTenantID(c)) {
			forbidden(c)
			return
		}
	}
	if ctxRole(c) != "admin" {
		if forbidden, reason := forbiddenRemoteHost(rule.RemoteHost); forbidden {
			bad(c, fmt.Errorf("remoteHost is not allowed: %s", reason))
			return
		}
	}
	rule.Status = forwardRuleStatusAfterWrite(req.Status)
	rule.QuotaSource = ""
	rule.Revision = time.Now().UnixNano()
	if err := s.db.Transaction(func(tx *gorm.DB) error {
		group, err := s.prepareForwardRuleTx(tx, &rule, 0)
		if err != nil {
			return err
		}
		if err := tx.Create(&rule).Error; err != nil {
			return err
		}
		if err := s.replaceRulePortLeasesTx(tx, rule, group); err != nil {
			return err
		}
		return s.bumpTunnelRevisionWithDB(tx, rule.TunnelID, rule.Revision)
	}); err != nil {
		bad(c, err)
		return
	}
	s.audit(c, actor(c), "forward_rule.create", "forward_rule", fmt.Sprint(rule.ID), "{}")
	c.JSON(http.StatusCreated, rule)
}

func (s *Server) updateForwardRule(c *gin.Context) {
	var existing models.ForwardRule
	if err := s.db.First(&existing, c.Param("id")).Error; err != nil {
		notFound(c)
		return
	}
	if !canManageForwardRule(c, existing) {
		c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "forbidden"})
		return
	}
	previousTunnelID := existing.TunnelID
	var req forwardRulePayload
	if err := c.ShouldBindJSON(&req); err != nil {
		bad(c, err)
		return
	}
	policyID, err := forwardRulePolicyForActor(c, req.ProtocolPolicyID, existing.ProtocolPolicyID)
	if err != nil {
		bad(c, err)
		return
	}
	req.ProtocolPolicyID = policyID
	id, _ := strconv.ParseUint(c.Param("id"), 10, 64)
	existing.ID = uint(id)
	if err := s.applyForwardRulePayload(&existing, req); err != nil {
		bad(c, err)
		return
	}
	if ctxRole(c) != "admin" {
		if ctxRole(c) == "user" {
			existing.UserID = ctxUserID(c)
		} else if !s.userBelongsToTenant(existing.UserID, ctxTenantID(c)) {
			forbidden(c)
			return
		}
	}
	if ctxRole(c) != "admin" {
		if forbidden, reason := forbiddenRemoteHost(existing.RemoteHost); forbidden {
			bad(c, fmt.Errorf("remoteHost is not allowed: %s", reason))
			return
		}
	}
	existing.Status = forwardRuleStatusAfterWrite(req.Status)
	existing.QuotaSource = ""
	existing.Revision = time.Now().UnixNano()
	if err := s.db.Transaction(func(tx *gorm.DB) error {
		previousGroupID, err := entryGroupIDForTunnelTx(tx, previousTunnelID)
		if err != nil {
			return err
		}
		newGroupID, err := entryGroupIDForTunnelTx(tx, existing.TunnelID)
		if err != nil {
			return err
		}
		if err := lockEntryGroupsTx(tx, previousGroupID, newGroupID); err != nil {
			return err
		}
		group, err := s.prepareForwardRuleTx(tx, &existing, existing.ID)
		if err != nil {
			return err
		}
		if err := tx.Save(&existing).Error; err != nil {
			return err
		}
		if err := s.replaceRulePortLeasesTx(tx, existing, group); err != nil {
			return err
		}
		if err := s.bumpTunnelRevisionWithDB(tx, existing.TunnelID, existing.Revision); err != nil {
			return err
		}
		if previousTunnelID != existing.TunnelID {
			return s.bumpTunnelRevisionWithDB(tx, previousTunnelID, existing.Revision)
		}
		return nil
	}); err != nil {
		bad(c, err)
		return
	}
	s.audit(c, actor(c), "forward_rule.update", "forward_rule", fmt.Sprint(existing.ID), "{}")
	c.JSON(http.StatusOK, existing)
}

func (s *Server) applyForwardRulePayload(rule *models.ForwardRule, req forwardRulePayload) error {
	rule.UserID = req.UserID
	rule.TunnelID = req.TunnelID
	rule.Name = strings.TrimSpace(req.Name)
	rule.Protocol = defaultString(strings.TrimSpace(req.Protocol), "tcp")
	rule.ListenPort = req.ListenPort
	rule.RemoteHost = strings.TrimSpace(req.RemoteHost)
	rule.RemotePort = req.RemotePort
	rule.Strategy = strings.TrimSpace(req.Strategy)
	rule.ProtocolPolicyID = req.ProtocolPolicyID
	if req.Status != "" && contains([]string{"active", "paused", "disabled"}, req.Status) {
		rule.Status = req.Status
	}
	if rule.Name == "" {
		return errors.New("name is required")
	}
	if req.ProtocolPolicyID != nil && *req.ProtocolPolicyID != 0 {
		if err := s.requireID(&models.ProtocolPolicy{}, *req.ProtocolPolicyID, "protocol policy"); err != nil {
			return err
		}
	}
	return nil
}

func forwardRulePolicyForActor(c *gin.Context, requested, existing *uint) (*uint, error) {
	if ctxRole(c) == "admin" {
		return requested, nil
	}
	if requested != nil && !sameOptionalUint(requested, existing) {
		return nil, errors.New("protocolPolicyId can only be managed by administrators")
	}
	return existing, nil
}

func forwardRuleStatusAfterWrite(status string) string {
	normalized := strings.ToLower(strings.TrimSpace(status))
	switch normalized {
	case "paused", "disabled":
		return normalized
	default:
		return "unsynced"
	}
}

func (s *Server) deleteForwardRule(c *gin.Context) {
	var rule models.ForwardRule
	if err := s.db.First(&rule, c.Param("id")).Error; err != nil {
		notFound(c)
		return
	}
	if !canManageForwardRule(c, rule) {
		c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "forbidden"})
		return
	}
	var limits int64
	if err := s.db.Model(&models.SpeedLimit{}).Where("rule_id = ?", rule.ID).Count(&limits).Error; err != nil {
		fail(c, err)
		return
	}
	if limits > 0 {
		bad(c, errors.New("forwarding rule is still referenced by speed limits"))
		return
	}
	revision := time.Now().UnixNano()
	if err := s.db.Transaction(func(tx *gorm.DB) error {
		if err := releaseRulePortLeasesTx(tx, rule.ID); err != nil {
			return err
		}
		if err := tx.Delete(&rule).Error; err != nil {
			return err
		}
		return s.bumpTunnelRevisionWithDB(tx, rule.TunnelID, revision)
	}); err != nil {
		fail(c, err)
		return
	}
	s.audit(c, actor(c), "forward_rule.delete", "forward_rule", fmt.Sprint(rule.ID), "{}")
	c.Status(http.StatusNoContent)
}

func (s *Server) prepareForwardRule(rule *models.ForwardRule, excludeID uint) error {
	return s.db.Transaction(func(tx *gorm.DB) error {
		_, err := s.prepareForwardRuleTx(tx, rule, excludeID)
		return err
	})
}

func (s *Server) prepareForwardRuleTx(tx *gorm.DB, rule *models.ForwardRule, excludeID uint) (models.DeviceGroup, error) {
	var entry models.DeviceGroup
	if rule.UserID == 0 {
		return entry, errors.New("userId is required")
	}
	if !contains([]string{"tcp", "udp", "tcp_udp"}, rule.Protocol) {
		return entry, errors.New("protocol must be tcp, udp, or tcp_udp")
	}
	if rule.Strategy == "" {
		rule.Strategy = "least_conn"
	}
	if !contains([]string{"least_conn", "round_robin", "random", "source_hash"}, rule.Strategy) {
		return entry, errors.New("strategy must be least_conn, round_robin, random, or source_hash")
	}
	if rule.RemoteHost == "" || rule.RemotePort <= 0 || rule.RemotePort > 65535 {
		return entry, errors.New("valid remoteHost and remotePort are required")
	}
	var user models.User
	if err := tx.First(&user, rule.UserID).Error; err != nil {
		return entry, errors.New("user not found")
	}
	if user.Status != "active" {
		return entry, errors.New("user is not active")
	}
	if user.ExpiresAt != nil && user.ExpiresAt.Before(time.Now()) {
		return entry, errors.New("user is expired")
	}
	if user.FlowLimitBytes > 0 && user.UsedBytes >= user.FlowLimitBytes {
		return entry, errors.New("user traffic is exhausted")
	}
	rule.TenantID = user.TenantID
	var tunnel models.Tunnel
	if err := tx.First(&tunnel, rule.TunnelID).Error; err != nil {
		return entry, errors.New("tunnel not found")
	}
	if err := lockEntryGroupsTx(tx, tunnel.EntryGroupID); err != nil {
		return entry, err
	}
	if err := tx.First(&entry, tunnel.EntryGroupID).Error; err != nil {
		return entry, errors.New("entry device group not found")
	}
	portStart, portEnd := entry.PortStart, entry.PortEnd
	var tenant models.Tenant
	hasTenant := user.TenantID != nil && *user.TenantID > 0
	if hasTenant {
		if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).First(&tenant, *user.TenantID).Error; err != nil {
			return entry, errors.New("tenant not found")
		}
		now := time.Now().UTC()
		if err := s.rollTenantPeriodTx(tx, &tenant, now, now.UnixNano()); err != nil {
			return entry, err
		}
		if !tenantActiveAt(tenant, now) {
			return entry, errors.New("tenant is not active")
		}
		if tenant.QuotaBlocked || (tenant.TrafficLimitBytes > 0 && tenant.UsedBytes >= tenant.TrafficLimitBytes) {
			return entry, errors.New("tenant traffic is exhausted")
		}
		if tenant.ForwardLimit > 0 {
			count, err := countForwardRulesTx(tx, "tenant_id = ?", tenant.ID, excludeID)
			if err != nil {
				return entry, err
			}
			if count >= int64(tenant.ForwardLimit) {
				return entry, errors.New("tenant forward rule limit reached")
			}
		}
	}

	if user.Role != "admin" {
		var directGrantCount int64
		if user.Role == "user" {
			if err := tx.Model(&models.UserTunnelGrant{}).Where("user_id = ?", user.ID).Count(&directGrantCount).Error; err != nil {
				return entry, err
			}
		}
		if directGrantCount > 0 {
			var grant models.UserTunnelGrant
			if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).
				Where("user_id = ? AND tunnel_id = ?", user.ID, tunnel.ID).
				First(&grant).Error; err != nil {
				return entry, errors.New("user is not authorized to use this tunnel")
			}
			if grant.PortStart > 0 && grant.PortEnd > 0 {
				portStart, portEnd = grant.PortStart, grant.PortEnd
			}
			if grant.ForwardLimit > 0 {
				count, err := countForwardRulesTx(tx, "user_id = ? AND tunnel_id = ?", []any{user.ID, tunnel.ID}, excludeID)
				if err != nil {
					return entry, err
				}
				if count >= int64(grant.ForwardLimit) {
					return entry, errors.New("user tunnel forward rule limit reached")
				}
			}
		} else if hasTenant {
			var grant models.TenantTunnelGrant
			if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).
				Where("tenant_id = ? AND tunnel_id = ?", tenant.ID, tunnel.ID).
				First(&grant).Error; err != nil {
				return entry, errors.New("tenant is not authorized to use this tunnel")
			}
			if grant.PortStart > 0 && grant.PortEnd > 0 {
				portStart, portEnd = grant.PortStart, grant.PortEnd
			}
			if grant.ForwardLimit > 0 {
				count, err := countForwardRulesTx(tx, "tenant_id = ? AND tunnel_id = ?", []any{tenant.ID, tunnel.ID}, excludeID)
				if err != nil {
					return entry, err
				}
				if count >= int64(grant.ForwardLimit) {
					return entry, errors.New("tenant tunnel forward rule limit reached")
				}
			}
		} else {
			return entry, errors.New("user is not authorized to use this tunnel")
		}
	}
	if rule.ListenPort == 0 {
		port, err := s.allocatePortTx(tx, entry, rule.Protocol, portStart, portEnd, excludeID)
		if err != nil {
			return entry, err
		}
		rule.ListenPort = port
	}
	if rule.ListenPort <= 0 || rule.ListenPort > 65535 {
		return entry, errors.New("listenPort must be between 1 and 65535")
	}
	if portStart > 0 && portEnd > 0 && (rule.ListenPort < portStart || rule.ListenPort > portEnd) {
		return entry, fmt.Errorf("listenPort must be within authorized range %d-%d", portStart, portEnd)
	}
	duplicate, err := s.entryPortInUseTx(tx, entry.ID, rule.ListenPort, rule.Protocol, excludeID)
	if err != nil {
		return entry, err
	}
	if duplicate {
		return entry, errors.New("listenPort is already used by an overlapping rule in this entry device group")
	}
	if user.ForwardLimit > 0 {
		count, err := countForwardRulesTx(tx, "user_id = ?", user.ID, excludeID)
		if err != nil {
			return entry, err
		}
		if count >= int64(user.ForwardLimit) {
			return entry, errors.New("user forward rule limit reached")
		}
	}
	policy, err := effectivePolicyWithDB(tx, rule, &tunnel, &entry)
	if err != nil {
		return entry, err
	}
	if policy != nil {
		if policy.BlockEncryptedTunnel && encryptedTunnelProtocol(tunnel.Protocol) {
			return entry, fmt.Errorf("protocol policy %q forbids encrypted tunnel protocol %q", policy.Name, tunnel.Protocol)
		}
		if policy.AllowHTTPOnly && rule.Protocol != "tcp" {
			return entry, fmt.Errorf("protocol policy %q only allows HTTP over TCP rules", policy.Name)
		}
		if policy.AllowPlainTCPOnly && rule.Protocol != "tcp" {
			return entry, fmt.Errorf("protocol policy %q only allows plain TCP rules", policy.Name)
		}
	}
	return entry, nil
}

func (s *Server) allocatePort(entryGroupID uint, protocol string, start, end int, excludeID uint) (int, error) {
	var port int
	err := s.db.Transaction(func(tx *gorm.DB) error {
		if err := lockEntryGroupsTx(tx, entryGroupID); err != nil {
			return err
		}
		var group models.DeviceGroup
		if err := tx.First(&group, entryGroupID).Error; err != nil {
			return err
		}
		var err error
		port, err = s.allocatePortTx(tx, group, protocol, start, end, excludeID)
		return err
	})
	return port, err
}

func (s *Server) entryPortInUse(entryGroupID uint, port int, protocol string, excludeID uint) (bool, error) {
	return s.entryPortInUseTx(s.db, entryGroupID, port, protocol, excludeID)
}

func countForwardRulesTx(tx *gorm.DB, condition string, args any, excludeID uint) (int64, error) {
	query := tx.Model(&models.ForwardRule{})
	if values, ok := args.([]any); ok {
		query = query.Where(condition, values...)
	} else {
		query = query.Where(condition, args)
	}
	if excludeID > 0 {
		query = query.Where("id <> ?", excludeID)
	}
	var count int64
	err := query.Count(&count).Error
	return count, err
}

func transportsOverlap(a, b string) bool {
	left := transportSet(a)
	right := transportSet(b)
	for transport := range left {
		if right[transport] {
			return true
		}
	}
	return false
}

func transportSet(protocol string) map[string]bool {
	switch strings.ToLower(strings.TrimSpace(protocol)) {
	case "udp":
		return map[string]bool{"udp": true}
	case "tcp_udp":
		return map[string]bool{"tcp": true, "udp": true}
	default:
		return map[string]bool{"tcp": true}
	}
}

func forbiddenRemoteHost(host string) (bool, string) {
	host = strings.TrimSpace(strings.Trim(host, "[]"))
	host = strings.TrimSuffix(host, ".")
	switch strings.ToLower(host) {
	case "", "localhost", "localhost.localdomain":
		return true, "loopback host"
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return false, ""
	}
	switch {
	case addr.IsLoopback():
		return true, "loopback address"
	case addr.IsUnspecified():
		return true, "unspecified address"
	case addr.IsMulticast():
		return true, "multicast address"
	case addr.IsLinkLocalUnicast():
		return true, "link-local address"
	case addr == netip.MustParseAddr("169.254.169.254"):
		return true, "cloud metadata address"
	case addr == netip.MustParseAddr("fd00:ec2::254"):
		return true, "cloud metadata address"
	default:
		return false, ""
	}
}

func (s *Server) effectivePolicy(rule *models.ForwardRule, tunnel *models.Tunnel, entry *models.DeviceGroup) (*models.ProtocolPolicy, error) {
	return effectivePolicyWithDB(s.db, rule, tunnel, entry)
}

func effectivePolicyWithDB(db *gorm.DB, rule *models.ForwardRule, tunnel *models.Tunnel, entry *models.DeviceGroup) (*models.ProtocolPolicy, error) {
	var id *uint
	switch {
	case rule.ProtocolPolicyID != nil:
		id = rule.ProtocolPolicyID
	case tunnel.ProtocolPolicyID != nil:
		id = tunnel.ProtocolPolicyID
	case entry.ProtocolPolicyID != nil:
		id = entry.ProtocolPolicyID
	}
	if id == nil {
		return nil, nil
	}
	var policy models.ProtocolPolicy
	if err := db.First(&policy, *id).Error; err != nil {
		return nil, errors.New("protocol policy not found")
	}
	return &policy, nil
}

func (s *Server) userBelongsToTenant(userID, tenantID uint) bool {
	if userID == 0 || tenantID == 0 {
		return false
	}
	var count int64
	return s.db.Model(&models.User{}).Where("id = ? AND tenant_id = ?", userID, tenantID).Count(&count).Error == nil && count == 1
}

func canManageForwardRule(c *gin.Context, rule models.ForwardRule) bool {
	switch ctxRole(c) {
	case "admin":
		return true
	case "tenant_admin":
		return rule.TenantID != nil && *rule.TenantID == ctxTenantID(c)
	default:
		return rule.UserID == ctxUserID(c)
	}
}

func encryptedTunnelProtocol(protocol string) bool {
	return contains([]string{"tls", "wss", "ws_over_tls", "ws-over-tls", "https", "quic"}, strings.ToLower(protocol))
}

func (s *Server) bumpTunnelRevision(tunnelID uint, revision int64) {
	_ = s.bumpTunnelRevisionWithDB(s.db, tunnelID, revision)
}

func (s *Server) bumpUserRevisionWithDB(db *gorm.DB, userID uint, revision int64) error {
	var tunnelIDs []uint
	if err := db.Model(&models.ForwardRule{}).
		Where("user_id = ?", userID).
		Distinct("tunnel_id").
		Pluck("tunnel_id", &tunnelIDs).Error; err != nil {
		return err
	}
	for _, tunnelID := range tunnelIDs {
		if err := s.bumpTunnelRevisionWithDB(db, tunnelID, revision); err != nil {
			return err
		}
	}
	return nil
}

func (s *Server) bumpTunnelRevisionWithDB(db *gorm.DB, tunnelID uint, revision int64) error {
	var tunnel models.Tunnel
	if err := db.First(&tunnel, tunnelID).Error; err != nil {
		return err
	}
	ids := []uint{tunnel.EntryGroupID}
	if tunnel.ExitGroupID != nil {
		ids = append(ids, *tunnel.ExitGroupID)
	}
	return bumpNodesByGroupWithDB(db, ids, revision)
}

func bumpNodesByGroupWithDB(db *gorm.DB, groupIDs []uint, revision int64) error {
	if len(groupIDs) == 0 {
		return nil
	}
	return db.Model(&models.Node{}).
		Where("device_group_id IN ?", groupIDs).
		Update("desired_revision", desiredRevisionExpr(revision)).Error
}

func desiredRevisionExpr(revision int64) clause.Expr {
	return gorm.Expr("CASE WHEN desired_revision < ? THEN ? ELSE desired_revision END", revision, revision)
}

func (s *Server) createInstallToken(c *gin.Context) {
	var req struct {
		Label         string `json:"label"`
		DeviceGroupID uint   `json:"deviceGroupId" binding:"required"`
		TTLHours      int    `json:"ttlHours"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		bad(c, err)
		return
	}
	if req.TTLHours <= 0 {
		req.TTLHours = 24
	}
	var group models.DeviceGroup
	if err := s.db.First(&group, req.DeviceGroupID).Error; err != nil {
		bad(c, errors.New("device group not found"))
		return
	}
	token, err := auth.RandomToken()
	if err != nil {
		fail(c, err)
		return
	}
	row := models.InstallToken{
		Label:         req.Label,
		TokenHash:     auth.TokenHash(token),
		DeviceGroupID: req.DeviceGroupID,
		ExpiresAt:     time.Now().Add(time.Duration(req.TTLHours) * time.Hour),
	}
	if err := s.db.Create(&row).Error; err != nil {
		fail(c, err)
		return
	}
	command := fmt.Sprintf(
		"curl -fsSL %s/install-agent.sh | sudo DUSHENG_API_URL=%q DUSHENG_INSTALL_TOKEN=%q DUSHENG_RELEASE_BASE=%q bash",
		strings.TrimRight(s.cfg.PublicURL, "/"),
		s.cfg.PublicURL,
		token,
		s.cfg.AgentReleaseBase,
	)
	s.audit(c, actor(c), "install_token.create", "install_token", fmt.Sprint(row.ID), "{}")
	c.JSON(http.StatusCreated, gin.H{"installToken": row, "token": token, "command": command})
}

func (s *Server) listInstallTokens(c *gin.Context) {
	query := s.db.Model(&models.InstallToken{})
	query = applySearch(query, c, "label")
	query = filterUint(query, c, "device_group_id", "deviceGroupId")
	respondPage[models.InstallToken](c, query, "id desc")
}

func (s *Server) deleteInstallToken(c *gin.Context) {
	var token models.InstallToken
	if err := s.db.First(&token, c.Param("id")).Error; err != nil {
		notFound(c)
		return
	}
	metadata, _ := json.Marshal(map[string]any{
		"label":         token.Label,
		"deviceGroupId": token.DeviceGroupID,
		"expiresAt":     token.ExpiresAt,
		"usedAt":        token.UsedAt,
	})
	if err := s.db.Delete(&token).Error; err != nil {
		fail(c, err)
		return
	}
	s.audit(c, actor(c), "install_token.delete", "install_token", fmt.Sprint(token.ID), string(metadata))
	c.Status(http.StatusNoContent)
}

func (s *Server) agentRegister(c *gin.Context) {
	var req struct {
		InstallToken string   `json:"installToken" binding:"required"`
		Name         string   `json:"name"`
		UUID         string   `json:"uuid"`
		Version      string   `json:"version"`
		Capabilities []string `json:"capabilities"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		bad(c, err)
		return
	}
	if req.UUID == "" {
		req.UUID = uuid.NewString()
	}
	nodeToken, err := auth.RandomToken()
	if err != nil {
		fail(c, err)
		return
	}
	now := time.Now()
	var node models.Node
	err = s.db.Transaction(func(tx *gorm.DB) error {
		var token models.InstallToken
		if err := tx.Where("token_hash = ? AND used_at IS NULL AND expires_at > ?", auth.TokenHash(req.InstallToken), now).First(&token).Error; err != nil {
			return err
		}
		result := tx.Model(&models.InstallToken{}).
			Where("id = ? AND used_at IS NULL AND expires_at > ?", token.ID, now).
			Update("used_at", &now)
		if result.Error != nil {
			return result.Error
		}
		if result.RowsAffected != 1 {
			return gorm.ErrRecordNotFound
		}
		node = models.Node{
			DeviceGroupID: token.DeviceGroupID,
			Name:          defaultString(req.Name, "DuSheng Node"),
			UUID:          req.UUID,
			TokenHash:     auth.TokenHash(nodeToken),
			Status:        "online",
			Version:       req.Version,
			Capabilities:  normalizeCapabilities(req.Capabilities),
			PublicIP:      observedPublicIP(c),
			LastSeenAt:    &now,
		}
		return tx.Create(&node).Error
	})
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			unauthorized(c)
			return
		}
		fail(c, err)
		return
	}
	s.agentEvent(node.ID, "agent.register", "info", "online", "agent registered", map[string]any{
		"version": node.Version, "capabilities": node.Capabilities,
	})
	s.audit(c, nil, "agent.register", "node", fmt.Sprint(node.ID), "{}")
	c.JSON(http.StatusCreated, gin.H{"nodeId": node.ID, "nodeToken": nodeToken, "uuid": node.UUID})
}

func (s *Server) agentHeartbeat(c *gin.Context) {
	node := ctxNode(c)
	var req struct {
		Version         string         `json:"version"`
		AppliedRevision int64          `json:"appliedRevision"`
		System          map[string]any `json:"system"`
		Capabilities    []string       `json:"capabilities"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		bad(c, err)
		return
	}
	systemJSON, _ := json.Marshal(req.System)
	now := time.Now()
	updates := map[string]any{
		"version":      req.Version,
		"system_json":  string(systemJSON),
		"last_seen_at": &now,
	}
	if req.Capabilities != nil {
		capabilitiesJSON, err := json.Marshal(normalizeCapabilities(req.Capabilities))
		if err != nil {
			fail(c, err)
			return
		}
		updates["capabilities"] = string(capabilitiesJSON)
	}
	if publicIP := observedPublicIP(c); publicIP != "" {
		updates["public_ip"] = publicIP
	}
	if req.AppliedRevision > 0 {
		updates["applied_revision"] = gorm.Expr(
			"CASE WHEN applied_revision < ? THEN ? ELSE applied_revision END",
			req.AppliedRevision,
			req.AppliedRevision,
		)
	}
	if err := s.db.Model(&models.Node{}).Where("id = ?", node.ID).Updates(updates).Error; err != nil {
		fail(c, err)
		return
	}
	if err := s.db.Model(&models.Node{}).
		Where("id = ? AND status NOT IN ?", node.ID, []string{"disabled", "maintenance", "uninstalling", "uninstall_legacy", "uninstall_timeout", "uninstall_failed"}).
		Update("status", "online").Error; err != nil {
		fail(c, err)
		return
	}
	if err := s.db.First(&node, node.ID).Error; err != nil {
		fail(c, err)
		return
	}
	response := gin.H{"desiredRevision": node.DesiredRevision, "serverTime": now.UTC()}
	if command := uninstallCommand(node); command != nil {
		response["command"] = command
	}
	c.JSON(http.StatusOK, response)
}

func observedPublicIP(c *gin.Context) string {
	candidates := make([]string, 0, 8)
	candidates = append(candidates, splitForwardedIPs(c.GetHeader("CF-Connecting-IP"))...)
	candidates = append(candidates, splitForwardedIPs(c.GetHeader("X-Forwarded-For"))...)
	candidates = append(candidates, splitForwardedIPs(c.GetHeader("X-Real-IP"))...)

	remoteAddr := strings.TrimSpace(c.Request.RemoteAddr)
	if host, _, err := net.SplitHostPort(remoteAddr); err == nil {
		remoteAddr = host
	}
	if remoteAddr != "" {
		candidates = append(candidates, remoteAddr)
	}

	for _, candidate := range candidates {
		ip := net.ParseIP(strings.TrimSpace(candidate))
		if isPublicAgentIP(ip) {
			return ip.String()
		}
	}
	return ""
}

func splitForwardedIPs(value string) []string {
	if strings.TrimSpace(value) == "" {
		return nil
	}
	return strings.Split(value, ",")
}

func isPublicAgentIP(ip net.IP) bool {
	return ip != nil &&
		ip.IsGlobalUnicast() &&
		!ip.IsPrivate() &&
		!ip.IsLoopback() &&
		!ip.IsLinkLocalUnicast() &&
		!ip.IsLinkLocalMulticast() &&
		!ip.IsUnspecified() &&
		!ip.IsMulticast()
}

func uninstallCommand(node models.Node) gin.H {
	if node.Status != "uninstalling" || node.UninstallCommandID == "" || node.UninstallRequestedAt == nil {
		return nil
	}
	return gin.H{
		"id":          node.UninstallCommandID,
		"action":      "uninstall",
		"reason":      "node deleted from panel",
		"requestedAt": node.UninstallRequestedAt.UTC(),
	}
}

func isUninstallStatus(status string) bool {
	return contains([]string{"uninstalling", "uninstall_legacy", "uninstall_timeout", "uninstall_failed"}, status)
}

func agentSupportsFinalUninstallAck(version string) bool {
	version = strings.TrimSpace(strings.TrimPrefix(strings.ToLower(version), "v"))
	parts := strings.Split(version, ".")
	if len(parts) < 3 {
		return false
	}
	values := make([]int, 3)
	for i := range values {
		part := parts[i]
		if i == 2 {
			part = strings.SplitN(part, "-", 2)[0]
			part = strings.SplitN(part, "+", 2)[0]
		}
		value, err := strconv.Atoi(part)
		if err != nil || value < 0 {
			return false
		}
		values[i] = value
	}
	return values[0] > 0 || values[1] > 1 || (values[1] == 1 && values[2] >= 5)
}

func nodeSupportsFinalUninstallAck(node models.Node) bool {
	return nodeHasCapability(node, "final_uninstall_ack") || agentSupportsFinalUninstallAck(node.Version)
}

func (s *Server) agentConfig(c *gin.Context) {
	node := ctxNode(c)
	now := time.Now().UTC()
	var group models.DeviceGroup
	if err := s.db.First(&group, node.DeviceGroupID).Error; err != nil {
		fail(c, err)
		return
	}
	var tunnels []models.Tunnel
	if err := s.db.Where("entry_group_id = ? OR exit_group_id = ?", node.DeviceGroupID, node.DeviceGroupID).Find(&tunnels).Error; err != nil {
		fail(c, err)
		return
	}
	tunnelIDs := make([]uint, 0, len(tunnels))
	entryTunnelIDs := make([]uint, 0, len(tunnels))
	for _, tunnel := range tunnels {
		tunnelIDs = append(tunnelIDs, tunnel.ID)
		if tunnel.EntryGroupID == node.DeviceGroupID {
			entryTunnelIDs = append(entryTunnelIDs, tunnel.ID)
		}
	}
	var candidateRules []models.ForwardRule
	if len(entryTunnelIDs) > 0 {
		if err := s.db.Where("tunnel_id IN ? AND status NOT IN ?", entryTunnelIDs, []string{"paused", "disabled", "deleted", "quota_exhausted"}).Order("listen_port asc").Find(&candidateRules).Error; err != nil {
			fail(c, err)
			return
		}
	}
	rules, userStateRevision, err := s.activeAgentRules(candidateRules, now)
	if err != nil {
		fail(c, err)
		return
	}
	policyIDs := map[uint]struct{}{}
	if group.ProtocolPolicyID != nil {
		policyIDs[*group.ProtocolPolicyID] = struct{}{}
	}
	userIDs := map[uint]struct{}{}
	tenantIDs := map[uint]struct{}{}
	ruleIDs := make([]uint, 0, len(rules))
	for _, tunnel := range tunnels {
		if tunnel.ProtocolPolicyID != nil {
			policyIDs[*tunnel.ProtocolPolicyID] = struct{}{}
		}
	}
	for _, rule := range rules {
		ruleIDs = append(ruleIDs, rule.ID)
		userIDs[rule.UserID] = struct{}{}
		if rule.TenantID != nil && *rule.TenantID > 0 {
			tenantIDs[*rule.TenantID] = struct{}{}
		}
		if rule.ProtocolPolicyID != nil {
			policyIDs[*rule.ProtocolPolicyID] = struct{}{}
		}
	}
	var policies []models.ProtocolPolicy
	if ids := uintSetValues(policyIDs); len(ids) > 0 {
		if err := s.db.Where("id IN ?", ids).Order("id asc").Find(&policies).Error; err != nil {
			fail(c, err)
			return
		}
	}
	var limits []models.SpeedLimit
	var limitQuery *gorm.DB
	if len(ruleIDs) > 0 {
		limitQuery = s.db.Where("rule_id IN ?", ruleIDs)
	}
	if len(tunnelIDs) > 0 {
		if limitQuery == nil {
			limitQuery = s.db.Where("tunnel_id IN ?", tunnelIDs)
		} else {
			limitQuery = limitQuery.Or("tunnel_id IN ?", tunnelIDs)
		}
	}
	if ids := uintSetValues(userIDs); len(ids) > 0 {
		if limitQuery == nil {
			limitQuery = s.db.Where("user_id IN ?", ids)
		} else {
			limitQuery = limitQuery.Or("user_id IN ?", ids)
		}
	}
	if ids := uintSetValues(tenantIDs); len(ids) > 0 {
		if limitQuery == nil {
			limitQuery = s.db.Where("tenant_id IN ?", ids)
		} else {
			limitQuery = limitQuery.Or("tenant_id IN ?", ids)
		}
	}
	if limitQuery != nil {
		if err := limitQuery.Order("id asc").Find(&limits).Error; err != nil {
			fail(c, err)
			return
		}
	}
	var lineProbes []models.LineProbe
	if err := s.db.Where("node_id = ? AND enabled = ?", node.ID, true).Order("id asc").Find(&lineProbes).Error; err != nil {
		fail(c, err)
		return
	}

	revision := node.DesiredRevision
	revision = maxRevisionTime(revision, group.UpdatedAt)
	if userStateRevision > revision {
		revision = userStateRevision
	}
	for _, tunnel := range tunnels {
		revision = maxRevisionTime(revision, tunnel.UpdatedAt)
	}
	for _, rule := range rules {
		if rule.Revision > revision {
			revision = rule.Revision
		}
	}
	for _, policy := range policies {
		revision = maxRevisionTime(revision, policy.UpdatedAt)
	}
	for _, limit := range limits {
		revision = maxRevisionTime(revision, limit.UpdatedAt)
	}
	for _, probe := range lineProbes {
		if probe.Revision > revision {
			revision = probe.Revision
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"node":             node,
		"deviceGroup":      group,
		"tunnels":          tunnels,
		"forwardRules":     rules,
		"protocolPolicies": policies,
		"speedLimits":      limits,
		"lineProbes":       lineProbes,
		"revision":         revision,
		"nonce":            configNonce(node, revision),
		"generatedAt":      now,
		"validUntil":       now.Add(agentConfigLease),
	})
}

func maxRevisionTime(revision int64, updatedAt time.Time) int64 {
	if value := updatedAt.UnixNano(); !updatedAt.IsZero() && value > revision {
		return value
	}
	return revision
}

func (s *Server) activeAgentRules(candidates []models.ForwardRule, now time.Time) ([]models.ForwardRule, int64, error) {
	userIDs := map[uint]struct{}{}
	tenantIDs := map[uint]struct{}{}
	for _, rule := range candidates {
		userIDs[rule.UserID] = struct{}{}
		if rule.TenantID != nil && *rule.TenantID > 0 {
			tenantIDs[*rule.TenantID] = struct{}{}
		}
	}
	if len(userIDs) == 0 {
		return nil, 0, nil
	}
	var users []models.User
	if err := s.db.Where("id IN ?", uintSetValues(userIDs)).Find(&users).Error; err != nil {
		return nil, 0, err
	}
	byID := make(map[uint]models.User, len(users))
	var stateRevision int64
	for _, user := range users {
		byID[user.ID] = user
		if user.ExpiresAt != nil && !user.ExpiresAt.After(now) {
			revision := user.ExpiresAt.UnixNano() + 1
			if revision > stateRevision {
				stateRevision = revision
			}
		}
	}
	var userGrants []models.UserTunnelGrant
	if err := s.db.Where("user_id IN ?", uintSetValues(userIDs)).Find(&userGrants).Error; err != nil {
		return nil, 0, err
	}
	directTunnelsByUser := make(map[uint]map[uint]struct{})
	for _, grant := range userGrants {
		if directTunnelsByUser[grant.UserID] == nil {
			directTunnelsByUser[grant.UserID] = map[uint]struct{}{}
		}
		directTunnelsByUser[grant.UserID][grant.TunnelID] = struct{}{}
	}
	if err := s.rollDueTenantPeriods(now); err != nil {
		return nil, 0, err
	}
	var tenants []models.Tenant
	if len(tenantIDs) > 0 {
		if err := s.db.Where("id IN ?", uintSetValues(tenantIDs)).Find(&tenants).Error; err != nil {
			return nil, 0, err
		}
	}
	tenantByID := make(map[uint]models.Tenant, len(tenants))
	for _, tenant := range tenants {
		tenantByID[tenant.ID] = tenant
		if tenant.ExpiresAt != nil && !tenant.ExpiresAt.After(now) {
			revision := tenant.ExpiresAt.UnixNano() + 1
			if revision > stateRevision {
				stateRevision = revision
			}
		}
	}
	active := make([]models.ForwardRule, 0, len(candidates))
	for _, rule := range candidates {
		user, ok := byID[rule.UserID]
		if !ok || user.Status != "active" || (user.ExpiresAt != nil && !user.ExpiresAt.After(now)) {
			continue
		}
		if user.FlowLimitBytes > 0 && user.UsedBytes >= user.FlowLimitBytes {
			continue
		}
		if directTunnels := directTunnelsByUser[user.ID]; user.Role == "user" && len(directTunnels) > 0 {
			if _, authorized := directTunnels[rule.TunnelID]; !authorized {
				continue
			}
		}
		if rule.TenantID != nil && *rule.TenantID > 0 {
			tenant, ok := tenantByID[*rule.TenantID]
			if !ok || !tenantActiveAt(tenant, now) || tenant.QuotaBlocked || (tenant.TrafficLimitBytes > 0 && tenant.UsedBytes >= tenant.TrafficLimitBytes) {
				continue
			}
		}
		active = append(active, rule)
	}
	return active, stateRevision, nil
}

func (s *Server) agentConfigAck(c *gin.Context) {
	node := ctxNode(c)
	var req struct {
		Revision int64          `json:"revision"`
		Nonce    string         `json:"nonce"`
		Status   string         `json:"status"`
		Message  string         `json:"message"`
		Runtime  map[string]any `json:"runtime"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		bad(c, err)
		return
	}
	req.Nonce = strings.TrimSpace(req.Nonce)
	req.Status = strings.ToLower(strings.TrimSpace(req.Status))
	if req.Revision < 0 || req.Nonce == "" {
		bad(c, errors.New("revision and nonce are required"))
		return
	}
	if !contains([]string{"applied", "rejected", "rolled_back", "lease_expired"}, req.Status) {
		bad(c, errors.New("status must be applied, rejected, rolled_back, or lease_expired"))
		return
	}
	if req.Nonce != configNonce(node, req.Revision) {
		bad(c, errors.New("config nonce does not match revision"))
		return
	}
	now := time.Now().UTC()
	detail, _ := json.Marshal(map[string]any{
		"revision": req.Revision,
		"nonce":    req.Nonce,
		"runtime":  req.Runtime,
	})
	severity := "info"
	if req.Status != "applied" {
		severity = "warning"
	}
	err := s.db.Transaction(func(tx *gorm.DB) error {
		updates := map[string]any{
			"config_ack_revision": req.Revision,
			"config_nonce":        req.Nonce,
			"config_status":       req.Status,
			"config_message":      req.Message,
			"config_ack_at":       &now,
		}
		if req.Status == "applied" {
			updates["applied_revision"] = req.Revision
			updates["last_good_revision"] = req.Revision
		}
		result := tx.Model(&models.Node{}).
			Where("id = ? AND config_ack_revision <= ?", node.ID, req.Revision).
			Updates(updates)
		if result.Error != nil {
			return result.Error
		}
		return tx.Create(&models.AgentEvent{
			NodeID: node.ID, Type: "config." + req.Status, Severity: severity, Status: req.Status,
			Message: req.Message, DetailJSON: string(detail), OccurredAt: now,
		}).Error
	})
	if err != nil {
		fail(c, err)
		return
	}
	c.Status(http.StatusNoContent)
}

func (s *Server) agentTraffic(c *gin.Context) {
	node := ctxNode(c)
	var req struct {
		ReportID string                    `json:"reportId"`
		Samples  []agentTrafficSampleInput `json:"samples"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		bad(c, err)
		return
	}
	if len(req.Samples) > 1000 {
		bad(c, errors.New("samples must contain at most 1000 entries"))
		return
	}
	req.ReportID = strings.TrimSpace(req.ReportID)
	if len(req.ReportID) > 120 {
		bad(c, errors.New("reportId must not exceed 120 characters"))
		return
	}
	for _, sample := range req.Samples {
		if sample.RuleID == 0 {
			bad(c, errors.New("ruleId is required"))
			return
		}
		if sample.InBytes < 0 || sample.OutBytes < 0 {
			bad(c, errors.New("traffic bytes must be non-negative"))
			return
		}
		if sample.InBytes+sample.OutBytes < 0 {
			bad(c, errors.New("traffic byte total overflow"))
			return
		}
	}
	duplicateAccepted := -1
	accepted := len(req.Samples)
	err := s.db.Transaction(func(tx *gorm.DB) error {
		if req.ReportID != "" {
			marker := models.AgentTrafficReport{NodeID: node.ID, ReportID: req.ReportID, Accepted: accepted}
			storedAccepted, duplicate, err := insertTrafficReportMarkerTx(tx, &marker)
			if err != nil {
				return err
			}
			if duplicate {
				duplicateAccepted = storedAccepted
				return nil
			}
		}
		return s.accountAgentTrafficTx(tx, node, req.Samples, time.Now().UTC())
	})
	if err != nil {
		if errors.Is(err, errAgentPayload) {
			bad(c, err)
			return
		}
		if errors.Is(err, errAgentForbidden) {
			forbidden(c)
			return
		}
		fail(c, err)
		return
	}
	if duplicateAccepted >= 0 {
		c.JSON(http.StatusOK, gin.H{"accepted": duplicateAccepted, "duplicate": true})
		return
	}
	c.JSON(http.StatusOK, gin.H{"accepted": accepted})
}

func (s *Server) exhaustUserQuota(tx *gorm.DB, userID uint, revision int64) error {
	var tunnelIDs []uint
	if err := tx.Model(&models.ForwardRule{}).
		Where("user_id = ? AND status NOT IN ?", userID, []string{"paused", "disabled", "deleted", "quota_exhausted"}).
		Distinct("tunnel_id").
		Pluck("tunnel_id", &tunnelIDs).Error; err != nil {
		return err
	}
	if len(tunnelIDs) == 0 {
		return nil
	}
	if err := tx.Model(&models.ForwardRule{}).
		Where("user_id = ? AND status NOT IN ?", userID, []string{"paused", "disabled", "deleted", "quota_exhausted"}).
		Updates(map[string]any{"status": "quota_exhausted", "quota_source": "user", "revision": revision}).Error; err != nil {
		return err
	}
	for _, tunnelID := range tunnelIDs {
		if err := s.bumpTunnelRevisionWithDB(tx, tunnelID, revision); err != nil {
			return err
		}
	}
	return nil
}

func (s *Server) reconcileUserQuotaTx(tx *gorm.DB, user *models.User, revision int64) error {
	if user.FlowLimitBytes > 0 && user.UsedBytes >= user.FlowLimitBytes {
		return s.exhaustUserQuota(tx, user.ID, revision)
	}
	var rules []models.ForwardRule
	if err := tx.Where("user_id = ? AND status = ? AND quota_source = ?", user.ID, "quota_exhausted", "user").Find(&rules).Error; err != nil {
		return err
	}
	tenantBlocked := false
	if user.TenantID != nil && *user.TenantID > 0 {
		var tenant models.Tenant
		if err := tx.First(&tenant, *user.TenantID).Error; err != nil {
			return err
		}
		tenantBlocked = tenant.QuotaBlocked || (tenant.TrafficLimitBytes > 0 && tenant.UsedBytes >= tenant.TrafficLimitBytes)
	}
	for _, rule := range rules {
		updates := map[string]any{"status": "unsynced", "quota_source": "", "revision": revision}
		if tenantBlocked {
			updates["status"] = "quota_exhausted"
			updates["quota_source"] = "tenant"
		}
		if err := tx.Model(&models.ForwardRule{}).Where("id = ?", rule.ID).Updates(updates).Error; err != nil {
			return err
		}
	}
	return s.bumpUserRevisionWithDB(tx, user.ID, revision)
}

func (s *Server) resetUserTraffic(c *gin.Context) {
	var user models.User
	if err := s.db.First(&user, c.Param("id")).Error; err != nil {
		notFound(c)
		return
	}
	if !canManageUser(c, user) {
		forbidden(c)
		return
	}
	revision := time.Now().UnixNano()
	if err := s.db.Transaction(func(tx *gorm.DB) error {
		user.UsedBytes = 0
		if err := tx.Model(&user).Update("used_bytes", 0).Error; err != nil {
			return err
		}
		return s.reconcileUserQuotaTx(tx, &user, revision)
	}); err != nil {
		fail(c, err)
		return
	}
	s.audit(c, actor(c), "user.traffic_reset", "user", fmt.Sprint(user.ID), "{}")
	c.JSON(http.StatusOK, user)
}

func (s *Server) agentViolation(c *gin.Context) {
	node := ctxNode(c)
	var req struct {
		RuleID   uint   `json:"ruleId"`
		PolicyID uint   `json:"policyId"`
		Protocol string `json:"protocol"`
		SourceIP string `json:"sourceIp"`
		Action   string `json:"action"`
		Detail   string `json:"detail"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		bad(c, err)
		return
	}
	if req.Action == "" {
		req.Action = "block"
	}
	if req.RuleID == 0 || req.PolicyID == 0 || strings.TrimSpace(req.Protocol) == "" {
		bad(c, errors.New("ruleId, policyId, and protocol are required"))
		return
	}
	if !contains([]string{"observe", "alert", "limit", "block"}, req.Action) {
		bad(c, errors.New("action must be observe, alert, limit, or block"))
		return
	}
	if _, err := s.findNodeRule(s.db, node, req.RuleID); err != nil {
		if errors.Is(err, errAgentForbidden) {
			forbidden(c)
			return
		}
		fail(c, err)
		return
	}
	row := models.ProtocolViolation{
		RuleID:     req.RuleID,
		NodeID:     node.ID,
		PolicyID:   req.PolicyID,
		Protocol:   req.Protocol,
		SourceIP:   req.SourceIP,
		Action:     req.Action,
		Detail:     req.Detail,
		OccurredAt: time.Now(),
	}
	if err := s.db.Create(&row).Error; err != nil {
		fail(c, err)
		return
	}
	updates := map[string]any{
		"violation_count": gorm.Expr("violation_count + 1"),
	}
	if req.Action == "block" {
		updates["status"] = "protocol_violation"
	}
	s.db.Model(&models.ForwardRule{}).Where("id = ?", req.RuleID).Updates(updates)
	c.JSON(http.StatusCreated, row)
}

func (s *Server) agentCommandAck(c *gin.Context) {
	node := ctxNode(c)
	commandID := strings.TrimSpace(c.Param("id"))
	if commandID == "" || commandID != node.UninstallCommandID {
		bad(c, errors.New("unknown command"))
		return
	}
	var req struct {
		Status  string `json:"status"`
		Message string `json:"message"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		bad(c, err)
		return
	}
	req.Status = strings.TrimSpace(req.Status)
	if req.Status == "" {
		req.Status = "accepted"
	}
	if !contains([]string{"accepted", "done", "failed"}, req.Status) {
		bad(c, errors.New("status must be accepted, done, or failed"))
		return
	}
	now := time.Now().UTC()
	node.UninstallAckStatus = req.Status
	node.UninstallAckMessage = req.Message
	node.UninstallAckAt = &now
	if req.Status == "failed" {
		node.Status = "uninstall_failed"
		node.UninstallConfirmedAt = &now
		if req.Message != "" {
			systemJSON, _ := json.Marshal(map[string]any{"uninstallError": req.Message})
			node.SystemJSON = string(systemJSON)
		}
		if err := s.db.Save(&node).Error; err != nil {
			fail(c, err)
			return
		}
		metadata, _ := json.Marshal(map[string]any{"commandId": commandID, "status": req.Status, "message": req.Message})
		s.audit(c, nil, "node.uninstall.failed", "node", fmt.Sprint(node.ID), string(metadata))
		c.Status(http.StatusNoContent)
		return
	}
	metadata, _ := json.Marshal(map[string]any{"commandId": commandID, "status": req.Status, "message": req.Message})
	if req.Status == "accepted" {
		node.UninstallLegacy = !nodeSupportsFinalUninstallAck(node)
		if node.UninstallLegacy {
			node.Status = "uninstall_legacy"
		} else {
			node.Status = "uninstalling"
		}
		if err := s.db.Save(&node).Error; err != nil {
			fail(c, err)
			return
		}
		s.audit(c, nil, "node.uninstall.accepted", "node", fmt.Sprint(node.ID), string(metadata))
		c.Status(http.StatusNoContent)
		return
	}
	node.UninstallConfirmedAt = &now
	s.audit(c, nil, "node.uninstall.done", "node", fmt.Sprint(node.ID), string(metadata))
	if err := s.db.Delete(&models.Node{}, node.ID).Error; err != nil {
		fail(c, err)
		return
	}
	c.Status(http.StatusNoContent)
}

func (s *Server) findNodeRule(db *gorm.DB, node models.Node, ruleID uint) (models.ForwardRule, error) {
	if ruleID == 0 {
		return models.ForwardRule{}, errAgentPayload
	}
	var rule models.ForwardRule
	err := db.Model(&models.ForwardRule{}).
		Joins("JOIN tunnels ON tunnels.id = forward_rules.tunnel_id").
		Where(
			"forward_rules.id = ? AND (tunnels.entry_group_id = ? OR tunnels.exit_group_id = ?)",
			ruleID,
			node.DeviceGroupID,
			node.DeviceGroupID,
		).
		First(&rule).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return models.ForwardRule{}, errAgentForbidden
	}
	return rule, err
}

func (s *Server) listAuditLogs(c *gin.Context) {
	query := s.db.Model(&models.AuditLog{})
	query = applySearch(query, c, "action", "resource_type", "resource_id", "metadata_json")
	query = filterString(query, c, "action", "action")
	query = filterString(query, c, "resource_type", "resourceType")
	query = filterString(query, c, "resource_id", "resourceId")
	query = filterDateRange(query, c, "created_at")
	respondPage[models.AuditLog](c, query, "id desc")
}

func (s *Server) listNodeEvents(c *gin.Context) {
	query := s.db.Model(&models.AgentEvent{})
	query = applySearch(query, c, "type", "severity", "status", "message", "detail_json")
	query = filterUint(query, c, "node_id", "nodeId")
	query = filterString(query, c, "type", "type")
	query = filterString(query, c, "severity", "severity")
	query = filterString(query, c, "status", "status")
	query = filterDateRange(query, c, "occurred_at")
	respondPage[models.AgentEvent](c, query, "occurred_at desc")
}

func (s *Server) listProtocolViolations(c *gin.Context) {
	query := s.db.Model(&models.ProtocolViolation{})
	query = applySearch(query, c, "protocol", "source_ip", "action", "detail")
	query = filterString(query, c, "action", "action")
	query = filterString(query, c, "protocol", "protocol")
	query = filterUint(query, c, "node_id", "nodeId")
	query = filterUint(query, c, "rule_id", "ruleId")
	query = filterDateRange(query, c, "occurred_at")
	respondPage[models.ProtocolViolation](c, query, "occurred_at desc")
}

func (s *Server) deleteByID(model any) gin.HandlerFunc {
	return func(c *gin.Context) {
		if err := s.db.First(model, c.Param("id")).Error; err != nil {
			notFound(c)
			return
		}
		if err := s.db.Delete(model).Error; err != nil {
			fail(c, err)
			return
		}
		c.Status(http.StatusNoContent)
	}
}

func (s *Server) audit(c *gin.Context, actorID *uint, action, resourceType, resourceID, metadata string) {
	_ = s.db.Create(&models.AuditLog{
		ActorID:      actorID,
		Action:       action,
		ResourceType: resourceType,
		ResourceID:   resourceID,
		MetadataJSON: metadata,
	}).Error
}

func (s *Server) agentEvent(nodeID uint, eventType, severity, status, message string, detail any) {
	detailJSON := "{}"
	if detail != nil {
		if content, err := json.Marshal(detail); err == nil {
			detailJSON = string(content)
		}
	}
	_ = s.db.Create(&models.AgentEvent{
		NodeID: nodeID, Type: eventType, Severity: severity, Status: status,
		Message: message, DetailJSON: detailJSON, OccurredAt: time.Now().UTC(),
	}).Error
}

func actor(c *gin.Context) *uint {
	id := ctxUserID(c)
	if id == 0 {
		return nil
	}
	return &id
}

func (s *Server) installAgentScript(c *gin.Context) {
	c.Header("Content-Type", "text/x-shellscript; charset=utf-8")
	c.String(http.StatusOK, `#!/usr/bin/env bash
set -euo pipefail

: "${DUSHENG_API_URL:?DUSHENG_API_URL is required}"
: "${DUSHENG_INSTALL_TOKEN:?DUSHENG_INSTALL_TOKEN is required}"

INSTALLER_URL="${DUSHENG_INSTALLER_URL:-${DUSHENG_API_URL%/}/agent-installer.sh}"

echo "Downloading DuSheng agent installer from ${INSTALLER_URL}..."

if ! command -v curl >/dev/null 2>&1; then
  apt-get update && apt-get install -y curl ca-certificates
fi

tmp="$(mktemp)"
trap 'rm -f "$tmp"' EXIT
if ! curl --fail --show-error --location --retry 3 --retry-delay 2 --connect-timeout 10 --max-time 90 "$INSTALLER_URL" -o "$tmp"; then
  echo "Unable to download the DuSheng agent installer from ${INSTALLER_URL}." >&2
  echo "Set DUSHENG_INSTALLER_URL to a reachable mirror and retry." >&2
  exit 1
fi
if [ ! -s "$tmp" ]; then
  echo "Downloaded installer is empty." >&2
  exit 1
fi
exec bash "$tmp" "$@"
`)
}

func bad(c *gin.Context, err error) {
	c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": err.Error()})
}

func fail(c *gin.Context, err error) {
	c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
}

func notFound(c *gin.Context) {
	c.AbortWithStatusJSON(http.StatusNotFound, gin.H{"error": "not found"})
}

func unauthorized(c *gin.Context) {
	c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
}

func forbidden(c *gin.Context) {
	c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "forbidden"})
}

func defaultString(value, fallback string) string {
	if value == "" {
		return fallback
	}
	return value
}

func contains(values []string, needle string) bool {
	for _, value := range values {
		if value == needle {
			return true
		}
	}
	return false
}

func normalizeCapabilities(values []string) []string {
	result := make([]string, 0, len(values))
	seen := map[string]struct{}{}
	for _, value := range values {
		value = strings.ToLower(strings.TrimSpace(value))
		if value == "" || len(value) > 80 {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
		if len(result) == 64 {
			break
		}
	}
	return result
}

func nodeHasCapability(node models.Node, capability string) bool {
	for _, value := range node.Capabilities {
		if value == capability {
			return true
		}
	}
	return false
}

func uintSetValues(values map[uint]struct{}) []uint {
	result := make([]uint, 0, len(values))
	for value := range values {
		result = append(result, value)
	}
	return result
}

func configNonce(node models.Node, revision int64) string {
	sum := sha256.Sum256([]byte(fmt.Sprintf("%s:%d", node.TokenHash, revision)))
	return fmt.Sprintf("%x", sum[:16])
}

func limit(c *gin.Context, fallback int) int {
	value, err := strconv.Atoi(c.DefaultQuery("limit", fmt.Sprint(fallback)))
	if err != nil || value <= 0 || value > 1000 {
		return fallback
	}
	return value
}
