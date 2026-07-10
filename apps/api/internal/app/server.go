package app

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
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
)

type Server struct {
	cfg          config.Config
	db           *gorm.DB
	loginLimiter *loginLimiter
}

const nodeOfflineAfter = 90 * time.Second
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
	router := gin.New()
	router.Use(gin.Logger(), gin.Recovery(), cors(cfg.CORSOrigins))

	router.GET("/healthz", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ok", "time": time.Now().UTC()})
	})
	router.GET("/install-agent.sh", s.installAgentScript)

	api := router.Group("/api/v1")
	api.POST("/auth/login", s.login)
	api.POST("/auth/refresh", s.refresh)
	api.POST("/agent/register", s.agentRegister)

	agent := api.Group("/agent", s.agentAuth())
	agent.POST("/heartbeat", s.agentHeartbeat)
	agent.GET("/config", s.agentConfig)
	agent.POST("/traffic", s.agentTraffic)
	agent.POST("/violations", s.agentViolation)
	agent.POST("/commands/:id/ack", s.agentCommandAck)

	protected := api.Group("", s.userAuth())
	protected.GET("/me", s.me)
	protected.GET("/dashboard", s.dashboard)
	protected.GET("/forward-rules", s.listForwardRules)
	protected.POST("/forward-rules", s.createForwardRule)
	protected.PUT("/forward-rules/:id", s.updateForwardRule)
	protected.DELETE("/forward-rules/:id", s.deleteForwardRule)

	admin := protected.Group("", requireRole("admin"))
	admin.GET("/users", s.listUsers)
	admin.POST("/users", s.createUser)
	admin.PUT("/users/:id", s.updateUser)
	admin.DELETE("/users/:id", s.deleteByID(&models.User{}))
	admin.GET("/device-groups", s.listDeviceGroups)
	admin.POST("/device-groups", s.createDeviceGroup)
	admin.PUT("/device-groups/:id", s.updateDeviceGroup)
	admin.DELETE("/device-groups/:id", s.deleteDeviceGroup)
	admin.GET("/tunnels", s.listTunnels)
	admin.POST("/tunnels", s.createTunnel)
	admin.PUT("/tunnels/:id", s.updateTunnel)
	admin.DELETE("/tunnels/:id", s.deleteTunnel)
	admin.GET("/protocol-policies", s.listProtocolPolicies)
	admin.POST("/protocol-policies", s.createProtocolPolicy)
	admin.PUT("/protocol-policies/:id", s.updateProtocolPolicy)
	admin.DELETE("/protocol-policies/:id", s.deleteProtocolPolicy)
	admin.GET("/speed-limits", s.listSpeedLimits)
	admin.POST("/speed-limits", s.createSpeedLimit)
	admin.PUT("/speed-limits/:id", s.updateSpeedLimit)
	admin.DELETE("/speed-limits/:id", s.deleteSpeedLimit)
	admin.GET("/nodes", s.listNodes)
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
	if now.Sub(attempt.FirstSeen) > 10*time.Minute {
		delete(l.attempts, key)
		return true
	}
	return attempt.Count < 8
}

func (l *loginLimiter) fail(key string, now time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()
	attempt := l.attempts[key]
	if attempt.FirstSeen.IsZero() || now.Sub(attempt.FirstSeen) > 10*time.Minute {
		attempt = loginAttempt{FirstSeen: now}
	}
	attempt.Count++
	if attempt.Count >= 8 {
		attempt.BlockedAt = now
	}
	l.attempts[key] = attempt
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
	if user.Status != "active" || !auth.CheckPassword(user.PasswordHash, req.Password) {
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
	if err := s.db.First(&user, claims.UserID).Error; err != nil || user.Status != "active" {
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
	since := time.Now().Add(-24 * time.Hour)
	dayStart := time.Now().Truncate(24 * time.Hour)

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
		if err := s.db.First(&user, claims.UserID).Error; err != nil || user.Status != "active" {
			unauthorized(c)
			return
		}
		c.Set("userID", user.ID)
		c.Set("role", user.Role)
		c.Next()
	}
}

func requireRole(role string) gin.HandlerFunc {
	return func(c *gin.Context) {
		if ctxRole(c) != role {
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
	query = applySearch(query, c, "username", "display_name", "role", "status")
	query = filterString(query, c, "status", "status")
	respondPage[models.User](c, query, "id desc")
}

type userPayload struct {
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
	if req.Username == "" || req.Password == "" {
		bad(c, errors.New("username and password are required"))
		return
	}
	hash, err := auth.HashPassword(req.Password)
	if err != nil {
		fail(c, err)
		return
	}
	user := models.User{
		Username:       req.Username,
		DisplayName:    req.DisplayName,
		PasswordHash:   hash,
		Role:           defaultString(req.Role, "user"),
		Status:         defaultString(req.Status, "active"),
		FlowLimitBytes: req.FlowLimitBytes,
		ForwardLimit:   req.ForwardLimit,
		ExpiresAt:      req.ExpiresAt,
	}
	if err := s.db.Create(&user).Error; err != nil {
		fail(c, err)
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
	var req userPayload
	if err := c.ShouldBindJSON(&req); err != nil {
		bad(c, err)
		return
	}
	user.Username = defaultString(req.Username, user.Username)
	user.DisplayName = req.DisplayName
	user.Role = defaultString(req.Role, user.Role)
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
	if err := s.db.Save(&user).Error; err != nil {
		fail(c, err)
		return
	}
	s.audit(c, actor(c), "user.update", "user", fmt.Sprint(user.ID), "{}")
	c.JSON(http.StatusOK, user)
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
}

func (s *Server) nodeScopeForUser(userID uint) *gorm.DB {
	return s.db.Model(&models.Node{}).
		Joins("JOIN tunnels ON nodes.device_group_id = tunnels.entry_group_id OR nodes.device_group_id = tunnels.exit_group_id").
		Joins("JOIN forward_rules ON forward_rules.tunnel_id = tunnels.id").
		Where("forward_rules.user_id = ?", userID).
		Distinct("nodes.id")
}

func (s *Server) updateNode(c *gin.Context) {
	var node models.Node
	if err := s.db.First(&node, c.Param("id")).Error; err != nil {
		notFound(c)
		return
	}
	var req struct {
		DeviceGroupID uint   `json:"deviceGroupId"`
		Name          string `json:"name"`
		Status        string `json:"status"`
		ConnectHost   string `json:"connectHost"`
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
	node.ConnectHost = req.ConnectHost
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
	AdvancedJSON      string  `json:"advancedJson"`
}

func (s *Server) listTunnels(c *gin.Context) {
	query := s.db.Model(&models.Tunnel{})
	query = applySearch(query, c, "name", "mode", "protocol", "flow_accounting")
	query = filterString(query, c, "mode", "mode")
	query = filterUint(query, c, "entry_group_id", "entryGroupId")
	query = filterUint(query, c, "exit_group_id", "exitGroupId")
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
	s.afterTunnelChange(c, s.db, &row, "update")
	c.JSON(http.StatusOK, row)
}

func (s *Server) deleteTunnel(c *gin.Context) {
	var row models.Tunnel
	if err := s.db.First(&row, c.Param("id")).Error; err != nil {
		notFound(c)
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
	row.AdvancedJSON = req.AdvancedJSON
	return nil
}

type protocolPolicyPayload struct {
	Name                 string `json:"name"`
	Template             string `json:"template"`
	Mode                 string `json:"mode"`
	BlockTLS             bool   `json:"blockTls"`
	BlockQUIC            bool   `json:"blockQuic"`
	AllowPlainTCPOnly    bool   `json:"allowPlainTcpOnly"`
	AllowHTTPOnly        bool   `json:"allowHttpOnly"`
	BlockProxyLike       bool   `json:"blockProxyLike"`
	BlockEncryptedTunnel bool   `json:"blockEncryptedTunnel"`
	Description          string `json:"description"`
}

func (s *Server) listProtocolPolicies(c *gin.Context) {
	query := s.db.Model(&models.ProtocolPolicy{})
	query = applySearch(query, c, "name", "template", "mode", "description")
	query = filterString(query, c, "mode", "mode")
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
	if !contains([]string{"none", "iepl_iplc_no_tls", "plain_tcp_only", "http_only", "block_proxy_like", "custom"}, req.Template) {
		return errors.New("unsupported protocol policy template")
	}
	if req.Mode == "" {
		req.Mode = "block"
	}
	if !contains([]string{"observe", "alert", "block"}, req.Mode) {
		return errors.New("mode must be observe, alert, or block")
	}
	row.Name = req.Name
	row.Template = req.Template
	row.Mode = req.Mode
	row.BlockTLS = req.BlockTLS
	row.BlockQUIC = req.BlockQUIC
	row.AllowPlainTCPOnly = req.AllowPlainTCPOnly
	row.AllowHTTPOnly = req.AllowHTTPOnly
	row.BlockProxyLike = req.BlockProxyLike
	row.BlockEncryptedTunnel = req.BlockEncryptedTunnel
	row.Description = req.Description
	return nil
}

type speedLimitPayload struct {
	Name        string `json:"name"`
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
	if req.UserID == nil && req.TunnelID == nil && req.RuleID == nil {
		return errors.New("one of userId, tunnelId, or ruleId is required")
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
	ids := []uint{tunnel.EntryGroupID}
	if tunnel.ExitGroupID != nil {
		ids = append(ids, *tunnel.ExitGroupID)
	}
	db.Model(&models.Node{}).Where("device_group_id IN ?", ids).Update("desired_revision", revision)
	s.audit(c, actor(c), "tunnel."+action, "tunnel", fmt.Sprint(tunnel.ID), "{}")
}

func (s *Server) afterDeviceGroupChange(c *gin.Context, db *gorm.DB, group *models.DeviceGroup, action string) {
	db.Model(&models.Node{}).Where("device_group_id = ?", group.ID).Update("desired_revision", time.Now().UnixNano())
	s.audit(c, actor(c), "device_group."+action, "device_group", fmt.Sprint(group.ID), "{}")
}

func (s *Server) afterProtocolPolicyChange(c *gin.Context, db *gorm.DB, policy *models.ProtocolPolicy, action string) {
	db.Model(&models.Node{}).Where("id > ?", 0).Update("desired_revision", time.Now().UnixNano())
	s.audit(c, actor(c), "protocol_policy."+action, "protocol_policy", fmt.Sprint(policy.ID), "{}")
}

func (s *Server) afterSpeedLimitChange(c *gin.Context, db *gorm.DB, limit *models.SpeedLimit, action string) {
	db.Model(&models.Node{}).Where("id > ?", 0).Update("desired_revision", time.Now().UnixNano())
	s.audit(c, actor(c), "speed_limit."+action, "speed_limit", fmt.Sprint(limit.ID), "{}")
}

func (s *Server) listForwardRules(c *gin.Context) {
	query := s.db.Model(&models.ForwardRule{})
	if ctxRole(c) != "admin" {
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
	var rule models.ForwardRule
	if err := s.applyForwardRulePayload(&rule, req); err != nil {
		bad(c, err)
		return
	}
	if ctxRole(c) != "admin" {
		rule.UserID = ctxUserID(c)
	}
	if err := s.prepareForwardRule(&rule, 0); err != nil {
		bad(c, err)
		return
	}
	rule.Status = forwardRuleStatusAfterWrite(req.Status)
	rule.Revision = time.Now().UnixNano()
	if err := s.db.Create(&rule).Error; err != nil {
		fail(c, err)
		return
	}
	s.bumpTunnelRevision(rule.TunnelID, rule.Revision)
	s.audit(c, actor(c), "forward_rule.create", "forward_rule", fmt.Sprint(rule.ID), "{}")
	c.JSON(http.StatusCreated, rule)
}

func (s *Server) updateForwardRule(c *gin.Context) {
	var existing models.ForwardRule
	if err := s.db.First(&existing, c.Param("id")).Error; err != nil {
		notFound(c)
		return
	}
	if ctxRole(c) != "admin" && existing.UserID != ctxUserID(c) {
		c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "forbidden"})
		return
	}
	var req forwardRulePayload
	if err := c.ShouldBindJSON(&req); err != nil {
		bad(c, err)
		return
	}
	id, _ := strconv.ParseUint(c.Param("id"), 10, 64)
	existing.ID = uint(id)
	if err := s.applyForwardRulePayload(&existing, req); err != nil {
		bad(c, err)
		return
	}
	if ctxRole(c) != "admin" {
		existing.UserID = ctxUserID(c)
	}
	if err := s.prepareForwardRule(&existing, existing.ID); err != nil {
		bad(c, err)
		return
	}
	existing.Status = forwardRuleStatusAfterWrite(req.Status)
	existing.Revision = time.Now().UnixNano()
	if err := s.db.Save(&existing).Error; err != nil {
		fail(c, err)
		return
	}
	s.bumpTunnelRevision(existing.TunnelID, existing.Revision)
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
	if ctxRole(c) != "admin" && rule.UserID != ctxUserID(c) {
		c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "forbidden"})
		return
	}
	if err := s.db.Delete(&rule).Error; err != nil {
		fail(c, err)
		return
	}
	s.bumpTunnelRevision(rule.TunnelID, time.Now().UnixNano())
	s.audit(c, actor(c), "forward_rule.delete", "forward_rule", fmt.Sprint(rule.ID), "{}")
	c.Status(http.StatusNoContent)
}

func (s *Server) prepareForwardRule(rule *models.ForwardRule, excludeID uint) error {
	if rule.UserID == 0 {
		return errors.New("userId is required")
	}
	if !contains([]string{"tcp", "udp", "tcp_udp"}, rule.Protocol) {
		return errors.New("protocol must be tcp, udp, or tcp_udp")
	}
	if rule.Strategy == "" {
		rule.Strategy = "least_conn"
	}
	if !contains([]string{"least_conn", "round_robin", "random", "source_hash"}, rule.Strategy) {
		return errors.New("strategy must be least_conn, round_robin, random, or source_hash")
	}
	if rule.RemoteHost == "" || rule.RemotePort <= 0 || rule.RemotePort > 65535 {
		return errors.New("valid remoteHost and remotePort are required")
	}
	var user models.User
	if err := s.db.First(&user, rule.UserID).Error; err != nil {
		return errors.New("user not found")
	}
	if user.Status != "active" {
		return errors.New("user is not active")
	}
	if user.ExpiresAt != nil && user.ExpiresAt.Before(time.Now()) {
		return errors.New("user is expired")
	}
	if user.FlowLimitBytes > 0 && user.UsedBytes >= user.FlowLimitBytes {
		return errors.New("user traffic is exhausted")
	}
	var tunnel models.Tunnel
	if err := s.db.First(&tunnel, rule.TunnelID).Error; err != nil {
		return errors.New("tunnel not found")
	}
	var entry models.DeviceGroup
	if err := s.db.First(&entry, tunnel.EntryGroupID).Error; err != nil {
		return errors.New("entry device group not found")
	}
	if rule.ListenPort == 0 {
		port, err := s.allocatePort(tunnel.ID, entry.PortStart, entry.PortEnd)
		if err != nil {
			return err
		}
		rule.ListenPort = port
	}
	if rule.ListenPort <= 0 || rule.ListenPort > 65535 {
		return errors.New("listenPort must be between 1 and 65535")
	}
	if entry.PortStart > 0 && entry.PortEnd > 0 && (rule.ListenPort < entry.PortStart || rule.ListenPort > entry.PortEnd) {
		return fmt.Errorf("listenPort must be within entry group range %d-%d", entry.PortStart, entry.PortEnd)
	}
	var duplicate int64
	query := s.db.Model(&models.ForwardRule{}).Where("tunnel_id = ? AND listen_port = ?", rule.TunnelID, rule.ListenPort)
	if excludeID != 0 {
		query = query.Where("id <> ?", excludeID)
	}
	if err := query.Count(&duplicate).Error; err != nil {
		return err
	}
	if duplicate > 0 {
		return errors.New("listenPort is already used in this tunnel")
	}
	if user.ForwardLimit > 0 {
		var count int64
		query := s.db.Model(&models.ForwardRule{}).Where("user_id = ?", user.ID)
		if excludeID != 0 {
			query = query.Where("id <> ?", excludeID)
		}
		if err := query.Count(&count).Error; err != nil {
			return err
		}
		if int(count) >= user.ForwardLimit {
			return errors.New("user forward rule limit reached")
		}
	}
	policy, err := s.effectivePolicy(rule, &tunnel, &entry)
	if err != nil {
		return err
	}
	if policy != nil {
		if policy.BlockEncryptedTunnel && encryptedTunnelProtocol(tunnel.Protocol) {
			return fmt.Errorf("protocol policy %q forbids encrypted tunnel protocol %q", policy.Name, tunnel.Protocol)
		}
		if policy.AllowHTTPOnly && rule.Protocol != "tcp" {
			return fmt.Errorf("protocol policy %q only allows HTTP over TCP rules", policy.Name)
		}
		if policy.AllowPlainTCPOnly && rule.Protocol != "tcp" {
			return fmt.Errorf("protocol policy %q only allows plain TCP rules", policy.Name)
		}
	}
	return nil
}

func (s *Server) allocatePort(tunnelID uint, start, end int) (int, error) {
	if start <= 0 || end <= 0 || start > end {
		start, end = 10000, 60000
	}
	var used []int
	if err := s.db.Model(&models.ForwardRule{}).Where("tunnel_id = ?", tunnelID).Pluck("listen_port", &used).Error; err != nil {
		return 0, err
	}
	seen := map[int]bool{}
	for _, port := range used {
		seen[port] = true
	}
	for port := start; port <= end; port++ {
		if !seen[port] {
			return port, nil
		}
	}
	return 0, errors.New("no free port in device group range")
}

func (s *Server) effectivePolicy(rule *models.ForwardRule, tunnel *models.Tunnel, entry *models.DeviceGroup) (*models.ProtocolPolicy, error) {
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
	if err := s.db.First(&policy, *id).Error; err != nil {
		return nil, errors.New("protocol policy not found")
	}
	return &policy, nil
}

func encryptedTunnelProtocol(protocol string) bool {
	return contains([]string{"tls", "wss", "ws_over_tls", "ws-over-tls", "https", "quic"}, strings.ToLower(protocol))
}

func (s *Server) bumpTunnelRevision(tunnelID uint, revision int64) {
	s.bumpTunnelRevisionWithDB(s.db, tunnelID, revision)
}

func (s *Server) bumpTunnelRevisionWithDB(db *gorm.DB, tunnelID uint, revision int64) {
	var tunnel models.Tunnel
	if err := db.First(&tunnel, tunnelID).Error; err != nil {
		return
	}
	ids := []uint{tunnel.EntryGroupID}
	if tunnel.ExitGroupID != nil {
		ids = append(ids, *tunnel.ExitGroupID)
	}
	db.Model(&models.Node{}).Where("device_group_id IN ?", ids).Update("desired_revision", revision)
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
		InstallToken string `json:"installToken" binding:"required"`
		Name         string `json:"name"`
		UUID         string `json:"uuid"`
		Version      string `json:"version"`
		PublicIP     string `json:"publicIp"`
		ConnectHost  string `json:"connectHost"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		bad(c, err)
		return
	}
	var token models.InstallToken
	err := s.db.Where("token_hash = ? AND used_at IS NULL AND expires_at > ?", auth.TokenHash(req.InstallToken), time.Now()).First(&token).Error
	if err != nil {
		unauthorized(c)
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
	node := models.Node{
		DeviceGroupID: token.DeviceGroupID,
		Name:          defaultString(req.Name, "DuSheng Node"),
		UUID:          req.UUID,
		TokenHash:     auth.TokenHash(nodeToken),
		Status:        "online",
		Version:       req.Version,
		PublicIP:      req.PublicIP,
		ConnectHost:   req.ConnectHost,
		LastSeenAt:    &now,
	}
	if err := s.db.Create(&node).Error; err != nil {
		fail(c, err)
		return
	}
	token.UsedAt = &now
	s.db.Save(&token)
	s.audit(c, nil, "agent.register", "node", fmt.Sprint(node.ID), "{}")
	c.JSON(http.StatusCreated, gin.H{"nodeId": node.ID, "nodeToken": nodeToken, "uuid": node.UUID})
}

func (s *Server) agentHeartbeat(c *gin.Context) {
	node := ctxNode(c)
	var req struct {
		Version         string         `json:"version"`
		PublicIP        string         `json:"publicIp"`
		ConnectHost     string         `json:"connectHost"`
		AppliedRevision int64          `json:"appliedRevision"`
		System          map[string]any `json:"system"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		bad(c, err)
		return
	}
	systemJSON, _ := json.Marshal(req.System)
	now := time.Now()
	if node.Status != "uninstalling" {
		node.Status = "online"
	}
	node.Version = req.Version
	node.PublicIP = req.PublicIP
	node.ConnectHost = req.ConnectHost
	node.AppliedRevision = req.AppliedRevision
	node.SystemJSON = string(systemJSON)
	node.LastSeenAt = &now
	if err := s.db.Save(&node).Error; err != nil {
		fail(c, err)
		return
	}
	response := gin.H{"desiredRevision": node.DesiredRevision, "serverTime": now.UTC()}
	if command := uninstallCommand(node); command != nil {
		response["command"] = command
	}
	c.JSON(http.StatusOK, response)
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

func (s *Server) agentConfig(c *gin.Context) {
	node := ctxNode(c)
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
	for _, tunnel := range tunnels {
		tunnelIDs = append(tunnelIDs, tunnel.ID)
	}
	var rules []models.ForwardRule
	if len(tunnelIDs) > 0 {
		s.db.Where("tunnel_id IN ? AND status NOT IN ?", tunnelIDs, []string{"paused", "disabled", "deleted", "quota_exhausted"}).Order("listen_port asc").Find(&rules)
	}
	var policies []models.ProtocolPolicy
	s.db.Order("id asc").Find(&policies)
	var limits []models.SpeedLimit
	s.db.Order("id asc").Find(&limits)

	revision := node.DesiredRevision
	for _, rule := range rules {
		if rule.Revision > revision {
			revision = rule.Revision
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"node":             node,
		"deviceGroup":      group,
		"tunnels":          tunnels,
		"forwardRules":     rules,
		"protocolPolicies": policies,
		"speedLimits":      limits,
		"revision":         revision,
		"generatedAt":      time.Now().UTC(),
	})
}

func (s *Server) agentTraffic(c *gin.Context) {
	node := ctxNode(c)
	var req struct {
		Samples []struct {
			RuleID   uint  `json:"ruleId"`
			InBytes  int64 `json:"inBytes"`
			OutBytes int64 `json:"outBytes"`
		} `json:"samples"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		bad(c, err)
		return
	}
	if len(req.Samples) > 1000 {
		bad(c, errors.New("samples must contain at most 1000 entries"))
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
	err := s.db.Transaction(func(tx *gorm.DB) error {
		exhaustedUsers := map[uint]struct{}{}
		now := time.Now()
		for _, sample := range req.Samples {
			rule, err := s.findNodeRule(tx, node, sample.RuleID)
			if err != nil {
				return err
			}
			if sample.InBytes > 0 {
				if err := tx.Create(&models.TrafficSample{UserID: rule.UserID, RuleID: rule.ID, NodeID: node.ID, Direction: "in", Bytes: sample.InBytes, SampledAt: now}).Error; err != nil {
					return err
				}
			}
			if sample.OutBytes > 0 {
				if err := tx.Create(&models.TrafficSample{UserID: rule.UserID, RuleID: rule.ID, NodeID: node.ID, Direction: "out", Bytes: sample.OutBytes, SampledAt: now}).Error; err != nil {
					return err
				}
			}
			total := sample.InBytes + sample.OutBytes
			if err := tx.Model(&models.ForwardRule{}).Where("id = ?", rule.ID).Updates(map[string]any{
				"in_bytes":  gorm.Expr("in_bytes + ?", sample.InBytes),
				"out_bytes": gorm.Expr("out_bytes + ?", sample.OutBytes),
			}).Error; err != nil {
				return err
			}
			if err := tx.Model(&models.User{}).Where("id = ?", rule.UserID).Update("used_bytes", gorm.Expr("used_bytes + ?", total)).Error; err != nil {
				return err
			}
			if total > 0 {
				var user models.User
				if err := tx.Select("id", "flow_limit_bytes", "used_bytes").First(&user, rule.UserID).Error; err != nil {
					return err
				}
				if user.FlowLimitBytes > 0 && user.UsedBytes >= user.FlowLimitBytes {
					exhaustedUsers[user.ID] = struct{}{}
				}
			}
		}
		for userID := range exhaustedUsers {
			if err := s.exhaustUserQuota(tx, userID, now.UnixNano()); err != nil {
				return err
			}
		}
		return nil
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
	c.JSON(http.StatusOK, gin.H{"accepted": len(req.Samples)})
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
		Updates(map[string]any{"status": "quota_exhausted", "revision": revision}).Error; err != nil {
		return err
	}
	for _, tunnelID := range tunnelIDs {
		s.bumpTunnelRevisionWithDB(tx, tunnelID, revision)
	}
	return nil
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
	if !contains([]string{"observe", "alert", "block"}, req.Action) {
		bad(c, errors.New("action must be observe, alert, or block"))
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
	s.audit(c, nil, "node.uninstall.ack", "node", fmt.Sprint(node.ID), string(metadata))
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

INSTALLER_URL="${DUSHENG_INSTALLER_URL:-https://raw.githubusercontent.com/SatanDS/DuSheng-Panel/main/deploy/scripts/install-agent.sh}"

if ! command -v curl >/dev/null 2>&1; then
  apt-get update && apt-get install -y curl ca-certificates
fi

tmp="$(mktemp)"
trap 'rm -f "$tmp"' EXIT
curl -fsSL "$INSTALLER_URL" -o "$tmp"
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

func limit(c *gin.Context, fallback int) int {
	value, err := strconv.Atoi(c.DefaultQuery("limit", fmt.Sprint(fallback)))
	if err != nil || value <= 0 || value > 1000 {
		return fallback
	}
	return value
}
