package app

import (
	"errors"
	"fmt"
	"net/http"
	"time"

	"dusheng-panel/apps/api/internal/models"
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

var errUserGrantValidation = errors.New("invalid user tunnel grant")

type userTunnelGrantPayload struct {
	UserID       uint `json:"userId"`
	TunnelID     uint `json:"tunnelId"`
	ForwardLimit int  `json:"forwardLimit"`
	PortStart    int  `json:"portStart"`
	PortEnd      int  `json:"portEnd"`
}

func (s *Server) listUserTunnelGrants(c *gin.Context) {
	query := s.db.Model(&models.UserTunnelGrant{})
	query = filterUint(query, c, "user_id", "userId")
	query = filterUint(query, c, "tunnel_id", "tunnelId")
	respondPage[models.UserTunnelGrant](c, query, "id desc")
}

func (s *Server) createUserTunnelGrant(c *gin.Context) {
	var req userTunnelGrantPayload
	if err := c.ShouldBindJSON(&req); err != nil {
		bad(c, err)
		return
	}
	var row models.UserTunnelGrant
	revision := time.Now().UnixNano()
	if err := s.db.Transaction(func(tx *gorm.DB) error {
		if err := s.applyUserTunnelGrantPayloadWithDB(tx, &row, req); err != nil {
			return fmt.Errorf("%w: %v", errUserGrantValidation, err)
		}
		if err := tx.Create(&row).Error; err != nil {
			return err
		}
		return s.bumpUserTunnelGrantRevisionsWithDB(tx, []uint{row.UserID}, []uint{row.TunnelID}, revision)
	}); err != nil {
		if errors.Is(err, errUserGrantValidation) {
			bad(c, err)
		} else {
			fail(c, err)
		}
		return
	}
	s.audit(c, actor(c), "user_tunnel_grant.create", "user_tunnel_grant", fmt.Sprint(row.ID), "{}")
	c.JSON(http.StatusCreated, row)
}

func (s *Server) updateUserTunnelGrant(c *gin.Context) {
	var req userTunnelGrantPayload
	if err := c.ShouldBindJSON(&req); err != nil {
		bad(c, err)
		return
	}
	var row models.UserTunnelGrant
	revision := time.Now().UnixNano()
	if err := s.db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).First(&row, c.Param("id")).Error; err != nil {
			return err
		}
		previous := row
		if err := s.applyUserTunnelGrantPayloadWithDB(tx, &row, req); err != nil {
			return fmt.Errorf("%w: %v", errUserGrantValidation, err)
		}
		if err := s.validateUserTunnelGrantChangeWithDB(tx, previous, row); err != nil {
			return fmt.Errorf("%w: %v", errUserGrantValidation, err)
		}
		if err := tx.Save(&row).Error; err != nil {
			return err
		}
		return s.bumpUserTunnelGrantRevisionsWithDB(
			tx,
			[]uint{previous.UserID, row.UserID},
			[]uint{previous.TunnelID, row.TunnelID},
			revision,
		)
	}); err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			notFound(c)
		} else if errors.Is(err, errUserGrantValidation) {
			bad(c, err)
		} else {
			fail(c, err)
		}
		return
	}
	s.audit(c, actor(c), "user_tunnel_grant.update", "user_tunnel_grant", fmt.Sprint(row.ID), "{}")
	c.JSON(http.StatusOK, row)
}

func (s *Server) deleteUserTunnelGrant(c *gin.Context) {
	var row models.UserTunnelGrant
	revision := time.Now().UnixNano()
	if err := s.db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).First(&row, c.Param("id")).Error; err != nil {
			return err
		}
		var rules int64
		if err := tx.Model(&models.ForwardRule{}).
			Where("user_id = ? AND tunnel_id = ?", row.UserID, row.TunnelID).
			Count(&rules).Error; err != nil {
			return err
		}
		if rules > 0 {
			return fmt.Errorf("%w: user tunnel grant is still used by forwarding rules", errUserGrantValidation)
		}
		if err := tx.Delete(&row).Error; err != nil {
			return err
		}
		return s.bumpUserTunnelGrantRevisionsWithDB(tx, []uint{row.UserID}, []uint{row.TunnelID}, revision)
	}); err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			notFound(c)
		} else if errors.Is(err, errUserGrantValidation) {
			bad(c, err)
		} else {
			fail(c, err)
		}
		return
	}
	s.audit(c, actor(c), "user_tunnel_grant.delete", "user_tunnel_grant", fmt.Sprint(row.ID), "{}")
	c.Status(http.StatusNoContent)
}

func (s *Server) applyUserTunnelGrantPayloadWithDB(db *gorm.DB, row *models.UserTunnelGrant, req userTunnelGrantPayload) error {
	if req.UserID == 0 || req.TunnelID == 0 {
		return errors.New("userId and tunnelId are required")
	}
	if req.ForwardLimit < 0 || req.PortStart < 0 || req.PortEnd < 0 || req.PortStart > 65535 || req.PortEnd > 65535 {
		return errors.New("grant limits and ports must be valid non-negative values")
	}
	if (req.PortStart == 0) != (req.PortEnd == 0) || (req.PortStart > 0 && req.PortStart > req.PortEnd) {
		return errors.New("portStart and portEnd must both be zero or form a valid range")
	}
	var user models.User
	if err := db.First(&user, req.UserID).Error; err != nil {
		return errors.New("user not found")
	}
	if user.Role != "user" {
		return errors.New("only regular users can receive tunnel grants")
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
			return fmt.Errorf("user port range must be within entry group range %d-%d", group.PortStart, group.PortEnd)
		}
	}
	var duplicate int64
	query := db.Model(&models.UserTunnelGrant{}).
		Where("user_id = ? AND tunnel_id = ?", req.UserID, req.TunnelID)
	if row.ID > 0 {
		query = query.Where("id <> ?", row.ID)
	}
	if err := query.Count(&duplicate).Error; err != nil {
		return err
	}
	if duplicate > 0 {
		return errors.New("this user already has a grant for the tunnel")
	}
	row.UserID = req.UserID
	row.TunnelID = req.TunnelID
	row.ForwardLimit = req.ForwardLimit
	row.PortStart = req.PortStart
	row.PortEnd = req.PortEnd
	return nil
}

func (s *Server) validateUserTunnelGrantChangeWithDB(db *gorm.DB, previous, next models.UserTunnelGrant) error {
	if previous.UserID != next.UserID || previous.TunnelID != next.TunnelID {
		var oldRuleCount int64
		if err := db.Model(&models.ForwardRule{}).
			Where("user_id = ? AND tunnel_id = ?", previous.UserID, previous.TunnelID).
			Count(&oldRuleCount).Error; err != nil {
			return err
		}
		if oldRuleCount > 0 {
			return errors.New("userId and tunnelId cannot change while the grant is used by forwarding rules")
		}
	}
	var rules []models.ForwardRule
	if err := db.Where("user_id = ? AND tunnel_id = ?", next.UserID, next.TunnelID).Find(&rules).Error; err != nil {
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

func (s *Server) bumpUserTunnelGrantRevisionsWithDB(db *gorm.DB, userIDs, explicitTunnelIDs []uint, revision int64) error {
	tunnelIDs := map[uint]struct{}{}
	for _, tunnelID := range explicitTunnelIDs {
		if tunnelID > 0 {
			tunnelIDs[tunnelID] = struct{}{}
		}
	}
	users := map[uint]struct{}{}
	for _, userID := range userIDs {
		if userID > 0 {
			users[userID] = struct{}{}
		}
	}
	if len(users) > 0 {
		var ruleTunnelIDs []uint
		if err := db.Model(&models.ForwardRule{}).
			Where("user_id IN ?", uintSetValues(users)).
			Distinct("tunnel_id").
			Pluck("tunnel_id", &ruleTunnelIDs).Error; err != nil {
			return err
		}
		for _, tunnelID := range ruleTunnelIDs {
			tunnelIDs[tunnelID] = struct{}{}
		}
	}
	for tunnelID := range tunnelIDs {
		if err := s.bumpTunnelRevisionWithDB(db, tunnelID, revision); err != nil {
			return err
		}
	}
	return nil
}
