package app

import (
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"dusheng-panel/apps/api/internal/models"
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

var (
	tenantCodePattern        = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{1,59}$`)
	errTenantGrantValidation = errors.New("invalid tenant tunnel grant")
)

type tenantPayload struct {
	Name              string     `json:"name"`
	Code              string     `json:"code"`
	Status            string     `json:"status"`
	TrafficLimitBytes int64      `json:"trafficLimitBytes"`
	ForwardLimit      int        `json:"forwardLimit"`
	UserLimit         int        `json:"userLimit"`
	ResetIntervalDays int        `json:"resetIntervalDays"`
	ExpiresAt         *time.Time `json:"expiresAt"`
	Notes             string     `json:"notes"`
}

type tenantTunnelGrantPayload struct {
	TenantID     uint `json:"tenantId"`
	TunnelID     uint `json:"tunnelId"`
	ForwardLimit int  `json:"forwardLimit"`
	PortStart    int  `json:"portStart"`
	PortEnd      int  `json:"portEnd"`
}

func (s *Server) listTenants(c *gin.Context) {
	now := time.Now().UTC()
	if err := s.rollDueTenantPeriods(now); err != nil {
		fail(c, err)
		return
	}
	query := s.db.Model(&models.Tenant{})
	query = applySearch(query, c, "name", "code", "status")
	query = filterString(query, c, "status", "status")
	respondPage[models.Tenant](c, query, "id desc")
}

func (s *Server) createTenant(c *gin.Context) {
	var req tenantPayload
	if err := c.ShouldBindJSON(&req); err != nil {
		bad(c, err)
		return
	}
	row := models.Tenant{}
	if err := applyTenantPayload(&row, req, true, time.Now().UTC()); err != nil {
		bad(c, err)
		return
	}
	if err := s.db.Create(&row).Error; err != nil {
		fail(c, err)
		return
	}
	s.audit(c, actor(c), "tenant.create", "tenant", fmt.Sprint(row.ID), "{}")
	c.JSON(http.StatusCreated, row)
}

func (s *Server) updateTenant(c *gin.Context) {
	var row models.Tenant
	if err := s.db.First(&row, c.Param("id")).Error; err != nil {
		notFound(c)
		return
	}
	var req tenantPayload
	if err := c.ShouldBindJSON(&req); err != nil {
		bad(c, err)
		return
	}
	now := time.Now().UTC()
	if err := applyTenantPayload(&row, req, false, now); err != nil {
		bad(c, err)
		return
	}
	revision := now.UnixNano()
	if err := s.db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Save(&row).Error; err != nil {
			return err
		}
		if err := s.reconcileTenantQuotaTx(tx, &row, now, revision); err != nil {
			return err
		}
		return s.bumpTenantRevisionWithDB(tx, row.ID, revision)
	}); err != nil {
		fail(c, err)
		return
	}
	s.audit(c, actor(c), "tenant.update", "tenant", fmt.Sprint(row.ID), "{}")
	c.JSON(http.StatusOK, row)
}

func (s *Server) deleteTenant(c *gin.Context) {
	var row models.Tenant
	if err := s.db.First(&row, c.Param("id")).Error; err != nil {
		notFound(c)
		return
	}
	var references int64
	for _, target := range []struct {
		model any
		where string
	}{
		{&models.User{}, "tenant_id = ?"},
		{&models.ForwardRule{}, "tenant_id = ?"},
		{&models.SpeedLimit{}, "tenant_id = ?"},
		{&models.TenantTunnelGrant{}, "tenant_id = ?"},
	} {
		var count int64
		if err := s.db.Model(target.model).Where(target.where, row.ID).Count(&count).Error; err != nil {
			fail(c, err)
			return
		}
		references += count
	}
	if references > 0 {
		bad(c, errors.New("tenant is still referenced by users, rules, limits, or tunnel grants"))
		return
	}
	if err := s.db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Where("tenant_id = ?", row.ID).Delete(&models.TenantTrafficHourlyBucket{}).Error; err != nil {
			return err
		}
		return tx.Delete(&row).Error
	}); err != nil {
		fail(c, err)
		return
	}
	s.audit(c, actor(c), "tenant.delete", "tenant", fmt.Sprint(row.ID), "{}")
	c.Status(http.StatusNoContent)
}

func applyTenantPayload(row *models.Tenant, req tenantPayload, creating bool, now time.Time) error {
	name := strings.TrimSpace(req.Name)
	code := strings.ToLower(strings.TrimSpace(req.Code))
	status := strings.ToLower(strings.TrimSpace(req.Status))
	if name == "" {
		return errors.New("name is required")
	}
	if !tenantCodePattern.MatchString(code) {
		return errors.New("code must contain 2-60 lowercase letters, digits, underscores, or hyphens")
	}
	if status == "" {
		status = "active"
	}
	if !contains([]string{"active", "suspended", "disabled"}, status) {
		return errors.New("status must be active, suspended, or disabled")
	}
	if req.TrafficLimitBytes < 0 || req.ForwardLimit < 0 || req.UserLimit < 0 || req.ResetIntervalDays < 0 {
		return errors.New("tenant limits must be non-negative")
	}
	if req.ResetIntervalDays > 3660 {
		return errors.New("resetIntervalDays must not exceed 3660")
	}
	row.Name = name
	row.Code = code
	row.Status = status
	row.TrafficLimitBytes = req.TrafficLimitBytes
	row.ForwardLimit = req.ForwardLimit
	row.UserLimit = req.UserLimit
	row.ExpiresAt = req.ExpiresAt
	row.Notes = strings.TrimSpace(req.Notes)
	if creating || row.PeriodStartedAt == nil {
		started := now
		row.PeriodStartedAt = &started
	}
	if req.ResetIntervalDays != row.ResetIntervalDays || creating {
		row.ResetIntervalDays = req.ResetIntervalDays
		if req.ResetIntervalDays > 0 {
			next := now.AddDate(0, 0, req.ResetIntervalDays)
			row.NextResetAt = &next
		} else {
			row.NextResetAt = nil
		}
	}
	return nil
}

func (s *Server) listTenantTunnelGrants(c *gin.Context) {
	query := s.db.Model(&models.TenantTunnelGrant{})
	query = filterUint(query, c, "tenant_id", "tenantId")
	query = filterUint(query, c, "tunnel_id", "tunnelId")
	respondPage[models.TenantTunnelGrant](c, query, "id desc")
}

func (s *Server) createTenantTunnelGrant(c *gin.Context) {
	var req tenantTunnelGrantPayload
	if err := c.ShouldBindJSON(&req); err != nil {
		bad(c, err)
		return
	}
	var row models.TenantTunnelGrant
	revision := time.Now().UnixNano()
	if err := s.db.Transaction(func(tx *gorm.DB) error {
		if err := s.applyTenantTunnelGrantPayloadWithDB(tx, &row, req); err != nil {
			return fmt.Errorf("%w: %v", errTenantGrantValidation, err)
		}
		if err := tx.Create(&row).Error; err != nil {
			return err
		}
		return s.bumpTunnelRevisionWithDB(tx, row.TunnelID, revision)
	}); err != nil {
		if errors.Is(err, errTenantGrantValidation) {
			bad(c, err)
		} else {
			fail(c, err)
		}
		return
	}
	s.audit(c, actor(c), "tenant_tunnel_grant.create", "tenant_tunnel_grant", fmt.Sprint(row.ID), "{}")
	c.JSON(http.StatusCreated, row)
}

func (s *Server) updateTenantTunnelGrant(c *gin.Context) {
	var req tenantTunnelGrantPayload
	if err := c.ShouldBindJSON(&req); err != nil {
		bad(c, err)
		return
	}
	var row models.TenantTunnelGrant
	revision := time.Now().UnixNano()
	if err := s.db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).First(&row, c.Param("id")).Error; err != nil {
			return err
		}
		previous := row
		if err := s.applyTenantTunnelGrantPayloadWithDB(tx, &row, req); err != nil {
			return fmt.Errorf("%w: %v", errTenantGrantValidation, err)
		}
		if err := s.validateTenantTunnelGrantChangeWithDB(tx, previous, row); err != nil {
			return fmt.Errorf("%w: %v", errTenantGrantValidation, err)
		}
		if err := tx.Save(&row).Error; err != nil {
			return err
		}
		return s.bumpGrantTunnelRevisionsWithDB(tx, previous.TunnelID, row.TunnelID, revision)
	}); err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			notFound(c)
		} else if errors.Is(err, errTenantGrantValidation) {
			bad(c, err)
		} else {
			fail(c, err)
		}
		return
	}
	s.audit(c, actor(c), "tenant_tunnel_grant.update", "tenant_tunnel_grant", fmt.Sprint(row.ID), "{}")
	c.JSON(http.StatusOK, row)
}

func (s *Server) deleteTenantTunnelGrant(c *gin.Context) {
	var row models.TenantTunnelGrant
	revision := time.Now().UnixNano()
	if err := s.db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).First(&row, c.Param("id")).Error; err != nil {
			return err
		}
		var rules int64
		if err := tx.Model(&models.ForwardRule{}).Where("tenant_id = ? AND tunnel_id = ?", row.TenantID, row.TunnelID).Count(&rules).Error; err != nil {
			return err
		}
		if rules > 0 {
			return fmt.Errorf("%w: tenant tunnel grant is still used by forwarding rules", errTenantGrantValidation)
		}
		if err := tx.Delete(&row).Error; err != nil {
			return err
		}
		return s.bumpTunnelRevisionWithDB(tx, row.TunnelID, revision)
	}); err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			notFound(c)
		} else if errors.Is(err, errTenantGrantValidation) {
			bad(c, err)
		} else {
			fail(c, err)
		}
		return
	}
	s.audit(c, actor(c), "tenant_tunnel_grant.delete", "tenant_tunnel_grant", fmt.Sprint(row.ID), "{}")
	c.Status(http.StatusNoContent)
}

func (s *Server) applyTenantTunnelGrantPayloadWithDB(db *gorm.DB, row *models.TenantTunnelGrant, req tenantTunnelGrantPayload) error {
	if req.TenantID == 0 || req.TunnelID == 0 {
		return errors.New("tenantId and tunnelId are required")
	}
	if req.ForwardLimit < 0 || req.PortStart < 0 || req.PortEnd < 0 || req.PortStart > 65535 || req.PortEnd > 65535 {
		return errors.New("grant limits and ports must be valid non-negative values")
	}
	if (req.PortStart == 0) != (req.PortEnd == 0) || (req.PortStart > 0 && req.PortStart > req.PortEnd) {
		return errors.New("portStart and portEnd must both be zero or form a valid range")
	}
	var tenant models.Tenant
	if err := db.First(&tenant, req.TenantID).Error; err != nil {
		return errors.New("tenant not found")
	}
	var tunnel models.Tunnel
	if err := db.First(&tunnel, req.TunnelID).Error; err != nil {
		return errors.New("tunnel not found")
	}
	if req.PortStart > 0 {
		var group models.DeviceGroup
		if err := db.First(&group, tunnel.EntryGroupID).Error; err != nil {
			return errors.New("entry device group not found")
		}
		if group.PortStart > 0 && group.PortEnd > 0 && (req.PortStart < group.PortStart || req.PortEnd > group.PortEnd) {
			return fmt.Errorf("tenant port range must be within entry group range %d-%d", group.PortStart, group.PortEnd)
		}
	}
	row.TenantID = req.TenantID
	row.TunnelID = req.TunnelID
	row.ForwardLimit = req.ForwardLimit
	row.PortStart = req.PortStart
	row.PortEnd = req.PortEnd
	return nil
}

func (s *Server) validateTenantTunnelGrantChangeWithDB(db *gorm.DB, previous, next models.TenantTunnelGrant) error {
	if previous.TenantID != next.TenantID || previous.TunnelID != next.TunnelID {
		var oldRuleCount int64
		if err := db.Model(&models.ForwardRule{}).
			Where("tenant_id = ? AND tunnel_id = ?", previous.TenantID, previous.TunnelID).
			Count(&oldRuleCount).Error; err != nil {
			return err
		}
		if oldRuleCount > 0 {
			return errors.New("tenantId and tunnelId cannot change while the grant is used by forwarding rules")
		}
	}

	var rules []models.ForwardRule
	if err := db.Where("tenant_id = ? AND tunnel_id = ?", next.TenantID, next.TunnelID).Find(&rules).Error; err != nil {
		return err
	}
	if next.ForwardLimit > 0 && len(rules) > next.ForwardLimit {
		return fmt.Errorf("forwardLimit cannot be lower than the %d existing forwarding rules", len(rules))
	}
	if next.PortStart > 0 && next.PortEnd > 0 {
		for _, rule := range rules {
			if rule.ListenPort < next.PortStart || rule.ListenPort > next.PortEnd {
				return fmt.Errorf("authorized port range must include existing rule %d on port %d", rule.ID, rule.ListenPort)
			}
		}
	}
	return nil
}

func (s *Server) bumpGrantTunnelRevisionsWithDB(db *gorm.DB, previousTunnelID, nextTunnelID uint, revision int64) error {
	tunnelIDs := map[uint]struct{}{previousTunnelID: {}}
	tunnelIDs[nextTunnelID] = struct{}{}
	for tunnelID := range tunnelIDs {
		if err := s.bumpTunnelRevisionWithDB(db, tunnelID, revision); err != nil {
			return err
		}
	}
	return nil
}

func (s *Server) currentTenant(c *gin.Context) {
	tenantID := ctxTenantID(c)
	if tenantID == 0 {
		notFound(c)
		return
	}
	row, err := s.loadTenantForRead(tenantID, time.Now().UTC())
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			notFound(c)
			return
		}
		fail(c, err)
		return
	}
	c.JSON(http.StatusOK, row)
}

func (s *Server) currentTenantTraffic(c *gin.Context) {
	s.tenantTraffic(c, ctxTenantID(c))
}

func (s *Server) adminTenantTraffic(c *gin.Context) {
	id, _ := strconv.ParseUint(c.Param("id"), 10, 64)
	s.tenantTraffic(c, uint(id))
}

func (s *Server) tenantTraffic(c *gin.Context, tenantID uint) {
	if tenantID == 0 {
		notFound(c)
		return
	}
	tenant, err := s.loadTenantForRead(tenantID, time.Now().UTC())
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			notFound(c)
			return
		}
		fail(c, err)
		return
	}
	query := s.db.Model(&models.TenantTrafficHourlyBucket{}).Where("tenant_id = ?", tenantID)
	query = filterDateRange(query, c, "bucket_started_at")
	page, pageSize := pageParams(c)
	var total int64
	if err := query.Count(&total).Error; err != nil {
		fail(c, err)
		return
	}
	var buckets []models.TenantTrafficHourlyBucket
	if err := query.Order("bucket_started_at desc").Limit(pageSize).Offset((page - 1) * pageSize).Find(&buckets).Error; err != nil {
		fail(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"tenant":  tenant,
		"buckets": pageResponse[models.TenantTrafficHourlyBucket]{Items: buckets, Total: total, Page: page, PageSize: pageSize},
	})
}

func (s *Server) resetTenantTraffic(c *gin.Context) {
	id, _ := strconv.ParseUint(c.Param("id"), 10, 64)
	if id == 0 {
		notFound(c)
		return
	}
	now := time.Now().UTC()
	var tenant models.Tenant
	if err := s.db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).First(&tenant, uint(id)).Error; err != nil {
			return err
		}
		return s.resetTenantTrafficTx(tx, &tenant, now, now.UnixNano())
	}); err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			notFound(c)
			return
		}
		fail(c, err)
		return
	}
	s.audit(c, actor(c), "tenant.traffic_reset", "tenant", fmt.Sprint(tenant.ID), "{}")
	c.JSON(http.StatusOK, tenant)
}

func (s *Server) loadTenantForRead(tenantID uint, now time.Time) (models.Tenant, error) {
	var row models.Tenant
	err := s.db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).First(&row, tenantID).Error; err != nil {
			return err
		}
		return s.rollTenantPeriodTx(tx, &row, now, now.UnixNano())
	})
	return row, err
}

func (s *Server) rollDueTenantPeriods(now time.Time) error {
	var ids []uint
	if err := s.db.Model(&models.Tenant{}).Where("next_reset_at IS NOT NULL AND next_reset_at <= ?", now).Pluck("id", &ids).Error; err != nil {
		return err
	}
	for _, id := range ids {
		if _, err := s.loadTenantForRead(id, now); err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
			return err
		}
	}
	return nil
}

func (s *Server) rollTenantPeriodTx(tx *gorm.DB, tenant *models.Tenant, now time.Time, revision int64) error {
	if tenant.NextResetAt == nil || tenant.NextResetAt.After(now) || tenant.ResetIntervalDays <= 0 {
		return nil
	}
	return s.resetTenantTrafficTx(tx, tenant, now, revision)
}

func (s *Server) resetTenantTrafficTx(tx *gorm.DB, tenant *models.Tenant, now time.Time, revision int64) error {
	started := now
	tenant.UsedBytes = 0
	tenant.QuotaBlocked = false
	tenant.QuotaBlockedAt = nil
	tenant.PeriodStartedAt = &started
	if tenant.ResetIntervalDays > 0 {
		next := now.AddDate(0, 0, tenant.ResetIntervalDays)
		tenant.NextResetAt = &next
	} else {
		tenant.NextResetAt = nil
	}
	if err := tx.Model(tenant).Select("used_bytes", "quota_blocked", "quota_blocked_at", "period_started_at", "next_reset_at").Updates(tenant).Error; err != nil {
		return err
	}
	return s.restoreTenantQuotaRulesTx(tx, tenant.ID, revision)
}

func (s *Server) reconcileTenantQuotaTx(tx *gorm.DB, tenant *models.Tenant, now time.Time, revision int64) error {
	shouldBlock := tenant.TrafficLimitBytes > 0 && tenant.UsedBytes >= tenant.TrafficLimitBytes
	if shouldBlock {
		if !tenant.QuotaBlocked {
			tenant.QuotaBlocked = true
			tenant.QuotaBlockedAt = &now
			if err := tx.Model(tenant).Updates(map[string]any{"quota_blocked": true, "quota_blocked_at": now}).Error; err != nil {
				return err
			}
		}
		return s.exhaustTenantQuotaTx(tx, tenant.ID, revision)
	}
	if tenant.QuotaBlocked {
		tenant.QuotaBlocked = false
		tenant.QuotaBlockedAt = nil
		if err := tx.Model(tenant).Updates(map[string]any{"quota_blocked": false, "quota_blocked_at": nil}).Error; err != nil {
			return err
		}
		return s.restoreTenantQuotaRulesTx(tx, tenant.ID, revision)
	}
	return nil
}

func (s *Server) exhaustTenantQuotaTx(tx *gorm.DB, tenantID uint, revision int64) error {
	return s.updateTenantRuleStatusTx(tx, tenantID,
		"status NOT IN ?", []any{[]string{"paused", "disabled", "deleted", "quota_exhausted"}},
		map[string]any{"status": "quota_exhausted", "quota_source": "tenant", "revision": revision}, revision)
}

func (s *Server) restoreTenantQuotaRulesTx(tx *gorm.DB, tenantID uint, revision int64) error {
	var rules []models.ForwardRule
	if err := tx.Where("tenant_id = ? AND status = ? AND quota_source = ?", tenantID, "quota_exhausted", "tenant").Find(&rules).Error; err != nil {
		return err
	}
	if len(rules) == 0 {
		return nil
	}
	userIDs := make(map[uint]struct{})
	tunnelIDs := make(map[uint]struct{})
	for _, rule := range rules {
		userIDs[rule.UserID] = struct{}{}
		tunnelIDs[rule.TunnelID] = struct{}{}
	}
	var users []models.User
	if err := tx.Where("id IN ?", uintSetValues(userIDs)).Find(&users).Error; err != nil {
		return err
	}
	userByID := make(map[uint]models.User, len(users))
	for _, user := range users {
		userByID[user.ID] = user
	}
	for _, rule := range rules {
		updates := map[string]any{"status": "unsynced", "quota_source": "", "revision": revision}
		user := userByID[rule.UserID]
		if user.FlowLimitBytes > 0 && user.UsedBytes >= user.FlowLimitBytes {
			updates["status"] = "quota_exhausted"
			updates["quota_source"] = "user"
		}
		if err := tx.Model(&models.ForwardRule{}).Where("id = ?", rule.ID).Updates(updates).Error; err != nil {
			return err
		}
	}
	for tunnelID := range tunnelIDs {
		if err := s.bumpTunnelRevisionWithDB(tx, tunnelID, revision); err != nil {
			return err
		}
	}
	return nil
}

func (s *Server) updateTenantRuleStatusTx(tx *gorm.DB, tenantID uint, condition string, args []any, updates map[string]any, revision int64) error {
	var tunnelIDs []uint
	query := tx.Model(&models.ForwardRule{}).Where("tenant_id = ?", tenantID).Where(condition, args...)
	if err := query.Distinct("tunnel_id").Pluck("tunnel_id", &tunnelIDs).Error; err != nil {
		return err
	}
	if len(tunnelIDs) == 0 {
		return nil
	}
	if err := tx.Model(&models.ForwardRule{}).Where("tenant_id = ?", tenantID).Where(condition, args...).Updates(updates).Error; err != nil {
		return err
	}
	for _, tunnelID := range tunnelIDs {
		if err := s.bumpTunnelRevisionWithDB(tx, tunnelID, revision); err != nil {
			return err
		}
	}
	return nil
}

func (s *Server) bumpTenantRevisionWithDB(db *gorm.DB, tenantID uint, revision int64) error {
	var tunnelIDs []uint
	if err := db.Model(&models.ForwardRule{}).
		Where("tenant_id = ?", tenantID).
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

func tenantActiveAt(tenant models.Tenant, now time.Time) bool {
	return tenant.Status == "active" && (tenant.ExpiresAt == nil || tenant.ExpiresAt.After(now))
}
