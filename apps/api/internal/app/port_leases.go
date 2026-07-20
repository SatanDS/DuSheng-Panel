package app

import (
	"errors"
	"fmt"
	"sort"
	"strings"

	"dusheng-panel/apps/api/internal/models"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

func lockEntryGroupsTx(tx *gorm.DB, groupIDs ...uint) error {
	unique := make(map[uint]struct{}, len(groupIDs))
	ids := make([]uint, 0, len(groupIDs))
	for _, id := range groupIDs {
		if id == 0 {
			continue
		}
		if _, ok := unique[id]; ok {
			continue
		}
		unique[id] = struct{}{}
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	for _, id := range ids {
		var group models.DeviceGroup
		if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).Select("id").First(&group, id).Error; err != nil {
			return fmt.Errorf("lock entry device group %d: %w", id, err)
		}
	}
	return nil
}

func entryGroupIDForTunnelTx(tx *gorm.DB, tunnelID uint) (uint, error) {
	var tunnel models.Tunnel
	if err := tx.Select("id", "entry_group_id").First(&tunnel, tunnelID).Error; err != nil {
		return 0, err
	}
	return tunnel.EntryGroupID, nil
}

func normalizedBindIP(group models.DeviceGroup) string {
	for _, value := range strings.Split(group.BindIPs, ",") {
		if value = strings.TrimSpace(value); value != "" {
			return value
		}
	}
	return "*"
}

func leaseTransports(protocol string) []string {
	switch strings.ToLower(strings.TrimSpace(protocol)) {
	case "udp":
		return []string{"udp"}
	case "tcp_udp":
		return []string{"tcp", "udp"}
	default:
		return []string{"tcp"}
	}
}

func ruleNeedsPortLease(status string) bool {
	switch strings.ToLower(strings.TrimSpace(status)) {
	case "disabled", "deleted":
		return false
	default:
		return true
	}
}

func (s *Server) replaceRulePortLeasesTx(tx *gorm.DB, rule models.ForwardRule, group models.DeviceGroup) error {
	if err := tx.Where("rule_id = ?", rule.ID).Delete(&models.PortLease{}).Error; err != nil {
		return err
	}
	if !ruleNeedsPortLease(rule.Status) {
		return nil
	}
	bindIP := normalizedBindIP(group)
	for _, transport := range leaseTransports(rule.Protocol) {
		lease := models.PortLease{
			EntryGroupID: group.ID,
			BindIP:       bindIP,
			Transport:    transport,
			ListenPort:   rule.ListenPort,
			RuleID:       rule.ID,
		}
		if err := tx.Create(&lease).Error; err != nil {
			return fmt.Errorf("listen port %d/%s is already leased in entry group %d: %w", rule.ListenPort, transport, group.ID, err)
		}
	}
	return nil
}

func releaseRulePortLeasesTx(tx *gorm.DB, ruleID uint) error {
	return tx.Where("rule_id = ?", ruleID).Delete(&models.PortLease{}).Error
}

func (s *Server) allocatePortTx(tx *gorm.DB, group models.DeviceGroup, protocol string, start, end int, excludeRuleID uint) (int, error) {
	if start <= 0 || end <= 0 || start > end {
		start, end = 10000, 60000
	}
	transports := leaseTransports(protocol)
	var leased []int
	query := tx.Model(&models.PortLease{}).
		Where("entry_group_id = ? AND bind_ip = ? AND transport IN ? AND listen_port BETWEEN ? AND ?", group.ID, normalizedBindIP(group), transports, start, end)
	if excludeRuleID > 0 {
		query = query.Where("rule_id <> ?", excludeRuleID)
	}
	if err := query.Distinct("listen_port").Pluck("listen_port", &leased).Error; err != nil {
		return 0, err
	}
	used := make(map[int]struct{}, len(leased))
	for _, port := range leased {
		used[port] = struct{}{}
	}
	for port := start; port <= end; port++ {
		if _, exists := used[port]; exists {
			continue
		}
		inUse, err := s.entryPortInUseTx(tx, group.ID, port, protocol, excludeRuleID)
		if err != nil {
			return 0, err
		}
		if !inUse {
			return port, nil
		}
	}
	return 0, errors.New("no free port in device group range")
}

func (s *Server) entryPortInUseTx(tx *gorm.DB, entryGroupID uint, port int, protocol string, excludeRuleID uint) (bool, error) {
	transports := leaseTransports(protocol)
	var leases int64
	query := tx.Model(&models.PortLease{}).
		Where("entry_group_id = ? AND listen_port = ? AND transport IN ?", entryGroupID, port, transports)
	if excludeRuleID > 0 {
		query = query.Where("rule_id <> ?", excludeRuleID)
	}
	if err := query.Count(&leases).Error; err != nil {
		return false, err
	}
	if leases > 0 {
		return true, nil
	}

	// Upgrade compatibility: old rows can exist briefly before their leases are
	// backfilled, and tests may seed legacy rules directly.
	type existingRule struct {
		ID       uint
		Protocol string
	}
	var rows []existingRule
	legacy := tx.Table("forward_rules").
		Select("forward_rules.id, forward_rules.protocol").
		Joins("JOIN tunnels ON tunnels.id = forward_rules.tunnel_id").
		Where("tunnels.entry_group_id = ? AND forward_rules.listen_port = ? AND forward_rules.status NOT IN ?", entryGroupID, port, []string{"deleted", "disabled"})
	if excludeRuleID > 0 {
		legacy = legacy.Where("forward_rules.id <> ?", excludeRuleID)
	}
	if err := legacy.Scan(&rows).Error; err != nil {
		return false, err
	}
	for _, row := range rows {
		if transportsOverlap(protocol, row.Protocol) {
			return true, nil
		}
	}
	return false, nil
}
