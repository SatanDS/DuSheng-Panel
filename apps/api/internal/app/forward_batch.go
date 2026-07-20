package app

import (
	"errors"
	"fmt"
	"net/http"
	"time"

	"dusheng-panel/apps/api/internal/models"
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

const maxForwardRuleBatchSize = 100

var errForwardRulePreviewRollback = errors.New("forward rule preview rollback")

type forwardRuleBatchPayload struct {
	Rules []forwardRulePayload `json:"rules"`
}

func (s *Server) previewForwardRuleBatch(c *gin.Context) {
	var req forwardRuleBatchPayload
	if err := c.ShouldBindJSON(&req); err != nil {
		bad(c, err)
		return
	}
	rules, err := s.applyForwardRuleBatch(c, req.Rules, true)
	if err != nil {
		bad(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"items": rules, "count": len(rules), "preview": true})
}

func (s *Server) createForwardRuleBatch(c *gin.Context) {
	var req forwardRuleBatchPayload
	if err := c.ShouldBindJSON(&req); err != nil {
		bad(c, err)
		return
	}
	rules, err := s.applyForwardRuleBatch(c, req.Rules, false)
	if err != nil {
		bad(c, err)
		return
	}
	s.audit(c, actor(c), "forward_rule.batch_create", "forward_rule", "batch", fmt.Sprintf(`{"count":%d}`, len(rules)))
	c.JSON(http.StatusCreated, gin.H{"items": rules, "count": len(rules)})
}

func (s *Server) applyForwardRuleBatch(c *gin.Context, payloads []forwardRulePayload, preview bool) ([]models.ForwardRule, error) {
	if len(payloads) == 0 {
		return nil, errors.New("rules must not be empty")
	}
	if len(payloads) > maxForwardRuleBatchSize {
		return nil, fmt.Errorf("rules must contain at most %d entries", maxForwardRuleBatchSize)
	}
	rules := make([]models.ForwardRule, 0, len(payloads))
	err := s.db.Transaction(func(tx *gorm.DB) error {
		for index, req := range payloads {
			policyID, err := forwardRulePolicyForActor(c, req.ProtocolPolicyID, nil)
			if err != nil {
				return fmt.Errorf("rule %d: %w", index+1, err)
			}
			req.ProtocolPolicyID = policyID
			var rule models.ForwardRule
			if err := s.applyForwardRulePayload(&rule, req); err != nil {
				return fmt.Errorf("rule %d: %w", index+1, err)
			}
			if err := s.scopeForwardRuleForActor(c, &rule); err != nil {
				return fmt.Errorf("rule %d: %w", index+1, err)
			}
			if ctxRole(c) != "admin" {
				if forbidden, reason := forbiddenRemoteHost(rule.RemoteHost); forbidden {
					return fmt.Errorf("rule %d: remoteHost is not allowed: %s", index+1, reason)
				}
			}
			rule.Status = forwardRuleStatusAfterWrite(req.Status)
			rule.QuotaSource = ""
			rule.Revision = time.Now().UnixNano() + int64(index)
			group, err := s.prepareForwardRuleTx(tx, &rule, 0)
			if err != nil {
				return fmt.Errorf("rule %d: %w", index+1, err)
			}
			if err := tx.Create(&rule).Error; err != nil {
				return fmt.Errorf("rule %d: %w", index+1, err)
			}
			if err := s.replaceRulePortLeasesTx(tx, rule, group); err != nil {
				return fmt.Errorf("rule %d: %w", index+1, err)
			}
			if err := s.bumpTunnelRevisionWithDB(tx, rule.TunnelID, rule.Revision); err != nil {
				return err
			}
			rules = append(rules, rule)
		}
		if preview {
			return errForwardRulePreviewRollback
		}
		return nil
	})
	if preview && errors.Is(err, errForwardRulePreviewRollback) {
		for index := range rules {
			rules[index].ID = 0
			rules[index].CreatedAt = time.Time{}
			rules[index].UpdatedAt = time.Time{}
		}
		return rules, nil
	}
	return rules, err
}

func (s *Server) scopeForwardRuleForActor(c *gin.Context, rule *models.ForwardRule) error {
	switch ctxRole(c) {
	case "admin":
		return nil
	case "tenant_admin":
		if !s.userBelongsToTenant(rule.UserID, ctxTenantID(c)) {
			return errors.New("user does not belong to the current tenant")
		}
		return nil
	default:
		rule.UserID = ctxUserID(c)
		return nil
	}
}
