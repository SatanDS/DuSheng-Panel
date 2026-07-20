package app

import (
	"fmt"
	"math"
	"sort"
	"time"

	"dusheng-panel/apps/api/internal/models"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

type agentTrafficSampleInput struct {
	RuleID   uint  `json:"ruleId"`
	InBytes  int64 `json:"inBytes"`
	OutBytes int64 `json:"outBytes"`
}

type trafficDelta struct {
	inBytes  int64
	outBytes int64
}

func (d trafficDelta) total() int64 {
	return d.inBytes + d.outBytes
}

func (s *Server) accountAgentTrafficTx(tx *gorm.DB, node models.Node, samples []agentTrafficSampleInput, now time.Time) error {
	deltas := make(map[uint]trafficDelta, len(samples))
	for _, sample := range samples {
		current := deltas[sample.RuleID]
		if sample.InBytes > math.MaxInt64-current.inBytes || sample.OutBytes > math.MaxInt64-current.outBytes {
			return fmt.Errorf("%w: traffic byte aggregate overflow", errAgentPayload)
		}
		current.inBytes += sample.InBytes
		current.outBytes += sample.OutBytes
		if current.inBytes > math.MaxInt64-current.outBytes {
			return fmt.Errorf("%w: traffic byte total overflow", errAgentPayload)
		}
		deltas[sample.RuleID] = current
	}
	if len(deltas) == 0 {
		return nil
	}

	ruleIDs := make([]uint, 0, len(deltas))
	for ruleID := range deltas {
		ruleIDs = append(ruleIDs, ruleID)
	}
	sort.Slice(ruleIDs, func(i, j int) bool { return ruleIDs[i] < ruleIDs[j] })
	var rules []models.ForwardRule
	if err := tx.Model(&models.ForwardRule{}).
		Joins("JOIN tunnels ON tunnels.id = forward_rules.tunnel_id").
		Where("forward_rules.id IN ? AND tunnels.entry_group_id = ?", ruleIDs, node.DeviceGroupID).
		Find(&rules).Error; err != nil {
		return err
	}
	if len(rules) != len(ruleIDs) {
		return fmt.Errorf("%w: one or more rules do not belong to this node", errAgentForbidden)
	}
	userDeltas := make(map[uint]int64)
	tenantDeltas := make(map[uint]trafficDelta)
	trafficRows := make([]models.TrafficSample, 0, len(rules)*2)
	for _, rule := range rules {
		delta, ok := deltas[rule.ID]
		if !ok {
			return fmt.Errorf("%w: rule ownership lookup was incomplete", errAgentForbidden)
		}
		if userDeltas[rule.UserID] > math.MaxInt64-delta.total() {
			return fmt.Errorf("%w: user traffic aggregate overflow", errAgentPayload)
		}
		userDeltas[rule.UserID] += delta.total()
		if rule.TenantID != nil && *rule.TenantID > 0 {
			tenantDelta := tenantDeltas[*rule.TenantID]
			if tenantDelta.inBytes > math.MaxInt64-delta.inBytes || tenantDelta.outBytes > math.MaxInt64-delta.outBytes {
				return fmt.Errorf("%w: tenant traffic aggregate overflow", errAgentPayload)
			}
			tenantDelta.inBytes += delta.inBytes
			tenantDelta.outBytes += delta.outBytes
			tenantDeltas[*rule.TenantID] = tenantDelta
		}
		if delta.inBytes > 0 {
			trafficRows = append(trafficRows, models.TrafficSample{
				TenantID: rule.TenantID, UserID: rule.UserID, RuleID: rule.ID, NodeID: node.ID,
				Direction: "in", Bytes: delta.inBytes, SampledAt: now,
			})
		}
		if delta.outBytes > 0 {
			trafficRows = append(trafficRows, models.TrafficSample{
				TenantID: rule.TenantID, UserID: rule.UserID, RuleID: rule.ID, NodeID: node.ID,
				Direction: "out", Bytes: delta.outBytes, SampledAt: now,
			})
		}
	}
	if len(trafficRows) > 0 {
		if err := tx.CreateInBatches(trafficRows, 500).Error; err != nil {
			return err
		}
	}
	for _, ruleID := range ruleIDs {
		delta := deltas[ruleID]
		if err := tx.Model(&models.ForwardRule{}).Where("id = ?", ruleID).Updates(map[string]any{
			"in_bytes":  gorm.Expr("in_bytes + ?", delta.inBytes),
			"out_bytes": gorm.Expr("out_bytes + ?", delta.outBytes),
		}).Error; err != nil {
			return err
		}
	}

	userIDs := sortedUintKeys(userDeltas)
	exhaustedUsers := make([]uint, 0)
	for _, userID := range userIDs {
		var user models.User
		if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).First(&user, userID).Error; err != nil {
			return err
		}
		delta := userDeltas[userID]
		if user.UsedBytes > math.MaxInt64-delta {
			return fmt.Errorf("%w: user usage overflow", errAgentPayload)
		}
		user.UsedBytes += delta
		if err := tx.Model(&user).Update("used_bytes", user.UsedBytes).Error; err != nil {
			return err
		}
		if user.FlowLimitBytes > 0 && user.UsedBytes >= user.FlowLimitBytes {
			exhaustedUsers = append(exhaustedUsers, user.ID)
		}
	}

	tenantIDs := sortedTenantDeltaKeys(tenantDeltas)
	bucketStartedAt := now.UTC().Truncate(time.Hour)
	for _, tenantID := range tenantIDs {
		var tenant models.Tenant
		if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).First(&tenant, tenantID).Error; err != nil {
			return err
		}
		if err := s.rollTenantPeriodTx(tx, &tenant, now.UTC(), now.UnixNano()); err != nil {
			return err
		}
		delta := tenantDeltas[tenantID]
		if delta.inBytes > math.MaxInt64-delta.outBytes {
			return fmt.Errorf("%w: tenant traffic total overflow", errAgentPayload)
		}
		billed := delta.total()
		if tenant.UsedBytes > math.MaxInt64-billed {
			return fmt.Errorf("%w: tenant usage overflow", errAgentPayload)
		}
		tenant.UsedBytes += billed
		if err := tx.Model(&tenant).Update("used_bytes", tenant.UsedBytes).Error; err != nil {
			return err
		}
		bucket := models.TenantTrafficHourlyBucket{
			TenantID: tenant.ID, BucketStartedAt: bucketStartedAt,
			InBytes: delta.inBytes, OutBytes: delta.outBytes, BilledBytes: billed,
		}
		if err := tx.Clauses(clause.OnConflict{
			Columns: []clause.Column{{Name: "tenant_id"}, {Name: "bucket_started_at"}},
			DoUpdates: clause.Assignments(map[string]any{
				// Qualify the target row. PostgreSQL exposes both the target and
				// EXCLUDED rows in DO UPDATE, so bare column names are ambiguous.
				"in_bytes":     gorm.Expr("tenant_traffic_hourly_buckets.in_bytes + ?", delta.inBytes),
				"out_bytes":    gorm.Expr("tenant_traffic_hourly_buckets.out_bytes + ?", delta.outBytes),
				"billed_bytes": gorm.Expr("tenant_traffic_hourly_buckets.billed_bytes + ?", billed),
				"updated_at":   now,
			}),
		}).Create(&bucket).Error; err != nil {
			return err
		}
		if err := s.reconcileTenantQuotaTx(tx, &tenant, now.UTC(), now.UnixNano()); err != nil {
			return err
		}
	}
	for _, userID := range exhaustedUsers {
		if err := s.exhaustUserQuota(tx, userID, now.UnixNano()); err != nil {
			return err
		}
	}
	return nil
}

func sortedUintKeys(values map[uint]int64) []uint {
	keys := make([]uint, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i] < keys[j] })
	return keys
}

func sortedTenantDeltaKeys(values map[uint]trafficDelta) []uint {
	keys := make([]uint, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i] < keys[j] })
	return keys
}

func insertTrafficReportMarkerTx(tx *gorm.DB, marker *models.AgentTrafficReport) (int, bool, error) {
	result := tx.Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "node_id"}, {Name: "report_id"}},
		DoNothing: true,
	}).Create(marker)
	if result.Error != nil {
		return 0, false, result.Error
	}
	if result.RowsAffected > 0 {
		return marker.Accepted, false, nil
	}
	var existing models.AgentTrafficReport
	if err := tx.Where("node_id = ? AND report_id = ?", marker.NodeID, marker.ReportID).First(&existing).Error; err != nil {
		return 0, false, err
	}
	return existing.Accepted, true, nil
}
