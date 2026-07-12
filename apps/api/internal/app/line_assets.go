package app

import (
	"errors"
	"fmt"
	"math"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"

	"dusheng-panel/apps/api/internal/models"
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

var errStaleLineProbeResult = errors.New("probe result belongs to a stale configuration revision")

type lineProviderPayload struct {
	Name           string `json:"name"`
	Code           string `json:"code"`
	Status         string `json:"status"`
	SupportContact string `json:"supportContact"`
	SupportPhone   string `json:"supportPhone"`
	SupportEmail   string `json:"supportEmail"`
	PortalURL      string `json:"portalUrl"`
	Notes          string `json:"notes"`
}

func (s *Server) listLineProviders(c *gin.Context) {
	query := applySearch(s.db.Model(&models.LineProvider{}), c, "name", "code", "status", "support_contact", "support_email")
	query = filterString(query, c, "status", "status")
	respondPage[models.LineProvider](c, query, "id desc")
}

func (s *Server) createLineProvider(c *gin.Context) {
	var req lineProviderPayload
	if err := c.ShouldBindJSON(&req); err != nil {
		bad(c, err)
		return
	}
	row := models.LineProvider{}
	if err := applyLineProviderPayload(&row, req); err != nil {
		bad(c, err)
		return
	}
	if err := s.db.Create(&row).Error; err != nil {
		fail(c, err)
		return
	}
	s.audit(c, actor(c), "line_provider.create", "line_provider", fmt.Sprint(row.ID), "{}")
	c.JSON(http.StatusCreated, row)
}

func (s *Server) updateLineProvider(c *gin.Context) {
	var row models.LineProvider
	if err := s.db.First(&row, c.Param("id")).Error; err != nil {
		notFound(c)
		return
	}
	var req lineProviderPayload
	if err := c.ShouldBindJSON(&req); err != nil {
		bad(c, err)
		return
	}
	if err := applyLineProviderPayload(&row, req); err != nil {
		bad(c, err)
		return
	}
	if err := s.db.Save(&row).Error; err != nil {
		fail(c, err)
		return
	}
	s.audit(c, actor(c), "line_provider.update", "line_provider", fmt.Sprint(row.ID), "{}")
	c.JSON(http.StatusOK, row)
}

func (s *Server) deleteLineProvider(c *gin.Context) {
	var row models.LineProvider
	if err := s.db.First(&row, c.Param("id")).Error; err != nil {
		notFound(c)
		return
	}
	var references int64
	if err := s.db.Model(&models.LineCircuit{}).Where("provider_id = ?", row.ID).Count(&references).Error; err != nil {
		fail(c, err)
		return
	}
	if references > 0 {
		bad(c, errors.New("provider is still used by line circuits"))
		return
	}
	if err := s.db.Delete(&row).Error; err != nil {
		fail(c, err)
		return
	}
	s.audit(c, actor(c), "line_provider.delete", "line_provider", fmt.Sprint(row.ID), "{}")
	c.Status(http.StatusNoContent)
}

func applyLineProviderPayload(row *models.LineProvider, req lineProviderPayload) error {
	req.Name = strings.TrimSpace(req.Name)
	req.Status = defaultString(strings.ToLower(strings.TrimSpace(req.Status)), "active")
	if req.Name == "" {
		return errors.New("name is required")
	}
	if !contains([]string{"active", "inactive", "suspended"}, req.Status) {
		return errors.New("status must be active, inactive, or suspended")
	}
	req.PortalURL = strings.TrimSpace(req.PortalURL)
	if req.PortalURL != "" {
		parsed, err := url.ParseRequestURI(req.PortalURL)
		if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") {
			return errors.New("portalUrl must be an http or https URL")
		}
	}
	row.Name = req.Name
	row.Code = strings.TrimSpace(req.Code)
	row.Status = req.Status
	row.SupportContact = strings.TrimSpace(req.SupportContact)
	row.SupportPhone = strings.TrimSpace(req.SupportPhone)
	row.SupportEmail = strings.TrimSpace(req.SupportEmail)
	row.PortalURL = req.PortalURL
	row.Notes = req.Notes
	return nil
}

type lineSitePayload struct {
	Name    string `json:"name"`
	Code    string `json:"code"`
	Status  string `json:"status"`
	Country string `json:"country"`
	Region  string `json:"region"`
	City    string `json:"city"`
	Address string `json:"address"`
	Notes   string `json:"notes"`
}

func (s *Server) listLineSites(c *gin.Context) {
	query := applySearch(s.db.Model(&models.LineSite{}), c, "name", "code", "status", "country", "region", "city", "address")
	query = filterString(query, c, "status", "status")
	respondPage[models.LineSite](c, query, "id desc")
}

func (s *Server) createLineSite(c *gin.Context) {
	var req lineSitePayload
	if err := c.ShouldBindJSON(&req); err != nil {
		bad(c, err)
		return
	}
	row := models.LineSite{}
	if err := applyLineSitePayload(&row, req); err != nil {
		bad(c, err)
		return
	}
	if err := s.db.Create(&row).Error; err != nil {
		fail(c, err)
		return
	}
	s.audit(c, actor(c), "line_site.create", "line_site", fmt.Sprint(row.ID), "{}")
	c.JSON(http.StatusCreated, row)
}

func (s *Server) updateLineSite(c *gin.Context) {
	var row models.LineSite
	if err := s.db.First(&row, c.Param("id")).Error; err != nil {
		notFound(c)
		return
	}
	var req lineSitePayload
	if err := c.ShouldBindJSON(&req); err != nil {
		bad(c, err)
		return
	}
	if err := applyLineSitePayload(&row, req); err != nil {
		bad(c, err)
		return
	}
	if err := s.db.Save(&row).Error; err != nil {
		fail(c, err)
		return
	}
	s.audit(c, actor(c), "line_site.update", "line_site", fmt.Sprint(row.ID), "{}")
	c.JSON(http.StatusOK, row)
}

func (s *Server) deleteLineSite(c *gin.Context) {
	var row models.LineSite
	if err := s.db.First(&row, c.Param("id")).Error; err != nil {
		notFound(c)
		return
	}
	var references int64
	if err := s.db.Model(&models.LineEndpoint{}).Where("site_id = ?", row.ID).Count(&references).Error; err != nil {
		fail(c, err)
		return
	}
	if references > 0 {
		bad(c, errors.New("site is still used by line endpoints"))
		return
	}
	if err := s.db.Delete(&row).Error; err != nil {
		fail(c, err)
		return
	}
	s.audit(c, actor(c), "line_site.delete", "line_site", fmt.Sprint(row.ID), "{}")
	c.Status(http.StatusNoContent)
}

func applyLineSitePayload(row *models.LineSite, req lineSitePayload) error {
	req.Name = strings.TrimSpace(req.Name)
	req.Status = defaultString(strings.ToLower(strings.TrimSpace(req.Status)), "active")
	if req.Name == "" {
		return errors.New("name is required")
	}
	if !contains([]string{"planned", "active", "maintenance", "retired"}, req.Status) {
		return errors.New("status must be planned, active, maintenance, or retired")
	}
	row.Name = req.Name
	row.Code = strings.TrimSpace(req.Code)
	row.Status = req.Status
	row.Country = strings.TrimSpace(req.Country)
	row.Region = strings.TrimSpace(req.Region)
	row.City = strings.TrimSpace(req.City)
	row.Address = strings.TrimSpace(req.Address)
	row.Notes = req.Notes
	return nil
}

type lineCircuitPayload struct {
	ProviderID       uint       `json:"providerId"`
	Name             string     `json:"name"`
	CircuitCode      string     `json:"circuitCode"`
	ServiceType      string     `json:"serviceType"`
	Status           string     `json:"status"`
	BandwidthMbps    int        `json:"bandwidthMbps"`
	CommittedMbps    int        `json:"committedMbps"`
	LatencySLAms     float64    `json:"latencySlaMs"`
	PacketLossSLAPct float64    `json:"packetLossSlaPct"`
	MonthlyCost      float64    `json:"monthlyCost"`
	Currency         string     `json:"currency"`
	StartsAt         *time.Time `json:"startsAt"`
	ExpiresAt        *time.Time `json:"expiresAt"`
	MaintenanceStart *time.Time `json:"maintenanceStart"`
	MaintenanceEnd   *time.Time `json:"maintenanceEnd"`
	Tags             string     `json:"tags"`
	Notes            string     `json:"notes"`
}

func (s *Server) listLineCircuits(c *gin.Context) {
	query := applySearch(s.db.Model(&models.LineCircuit{}), c, "name", "circuit_code", "service_type", "status", "tags")
	query = filterString(query, c, "status", "status")
	query = filterString(query, c, "service_type", "serviceType")
	query = filterUint(query, c, "provider_id", "providerId")
	respondPage[models.LineCircuit](c, query, "id desc")
}

func (s *Server) createLineCircuit(c *gin.Context) {
	var req lineCircuitPayload
	if err := c.ShouldBindJSON(&req); err != nil {
		bad(c, err)
		return
	}
	row := models.LineCircuit{}
	if err := s.applyLineCircuitPayload(&row, req); err != nil {
		bad(c, err)
		return
	}
	if err := s.db.Create(&row).Error; err != nil {
		fail(c, err)
		return
	}
	s.audit(c, actor(c), "line_circuit.create", "line_circuit", fmt.Sprint(row.ID), "{}")
	c.JSON(http.StatusCreated, row)
}

func (s *Server) updateLineCircuit(c *gin.Context) {
	var row models.LineCircuit
	if err := s.db.First(&row, c.Param("id")).Error; err != nil {
		notFound(c)
		return
	}
	var req lineCircuitPayload
	if err := c.ShouldBindJSON(&req); err != nil {
		bad(c, err)
		return
	}
	if err := s.applyLineCircuitPayload(&row, req); err != nil {
		bad(c, err)
		return
	}
	if err := s.db.Save(&row).Error; err != nil {
		fail(c, err)
		return
	}
	s.audit(c, actor(c), "line_circuit.update", "line_circuit", fmt.Sprint(row.ID), "{}")
	c.JSON(http.StatusOK, row)
}

func (s *Server) deleteLineCircuit(c *gin.Context) {
	var row models.LineCircuit
	if err := s.db.First(&row, c.Param("id")).Error; err != nil {
		notFound(c)
		return
	}
	var endpoints, tunnels, probes int64
	if err := s.db.Model(&models.LineEndpoint{}).Where("circuit_id = ?", row.ID).Count(&endpoints).Error; err != nil {
		fail(c, err)
		return
	}
	if err := s.db.Model(&models.Tunnel{}).Where("line_circuit_id = ?", row.ID).Count(&tunnels).Error; err != nil {
		fail(c, err)
		return
	}
	if err := s.db.Model(&models.LineProbe{}).Where("circuit_id = ?", row.ID).Count(&probes).Error; err != nil {
		fail(c, err)
		return
	}
	if endpoints > 0 || tunnels > 0 || probes > 0 {
		bad(c, errors.New("line circuit is still used by endpoints, probes, or tunnels"))
		return
	}
	if err := s.db.Delete(&row).Error; err != nil {
		fail(c, err)
		return
	}
	s.audit(c, actor(c), "line_circuit.delete", "line_circuit", fmt.Sprint(row.ID), "{}")
	c.Status(http.StatusNoContent)
}

func (s *Server) applyLineCircuitPayload(row *models.LineCircuit, req lineCircuitPayload) error {
	req.Name = strings.TrimSpace(req.Name)
	req.ServiceType = defaultString(strings.ToLower(strings.TrimSpace(req.ServiceType)), "iepl")
	req.Status = defaultString(strings.ToLower(strings.TrimSpace(req.Status)), "planned")
	if req.Name == "" || req.ProviderID == 0 {
		return errors.New("name and providerId are required")
	}
	if err := s.requireID(&models.LineProvider{}, req.ProviderID, "line provider"); err != nil {
		return err
	}
	if !contains([]string{"iepl", "iplc", "mpls", "internet", "custom"}, req.ServiceType) {
		return errors.New("unsupported serviceType")
	}
	if !contains([]string{"planned", "provisioning", "active", "maintenance", "suspended", "terminated"}, req.Status) {
		return errors.New("unsupported line circuit status")
	}
	if req.BandwidthMbps < 0 || req.CommittedMbps < 0 || (req.BandwidthMbps > 0 && req.CommittedMbps > req.BandwidthMbps) {
		return errors.New("committedMbps cannot exceed bandwidthMbps")
	}
	if req.LatencySLAms < 0 || req.PacketLossSLAPct < 0 || req.PacketLossSLAPct > 100 || req.MonthlyCost < 0 {
		return errors.New("SLA and cost values are out of range")
	}
	if req.StartsAt != nil && req.ExpiresAt != nil && req.ExpiresAt.Before(*req.StartsAt) {
		return errors.New("expiresAt must be after startsAt")
	}
	if req.MaintenanceStart != nil && req.MaintenanceEnd != nil && req.MaintenanceEnd.Before(*req.MaintenanceStart) {
		return errors.New("maintenanceEnd must be after maintenanceStart")
	}
	row.ProviderID = req.ProviderID
	row.Name = req.Name
	row.CircuitCode = strings.TrimSpace(req.CircuitCode)
	row.ServiceType = req.ServiceType
	row.Status = req.Status
	row.BandwidthMbps = req.BandwidthMbps
	row.CommittedMbps = req.CommittedMbps
	row.LatencySLAms = req.LatencySLAms
	row.PacketLossSLAPct = req.PacketLossSLAPct
	row.MonthlyCost = req.MonthlyCost
	row.Currency = strings.ToUpper(defaultString(strings.TrimSpace(req.Currency), "CNY"))
	row.StartsAt = req.StartsAt
	row.ExpiresAt = req.ExpiresAt
	row.MaintenanceStart = req.MaintenanceStart
	row.MaintenanceEnd = req.MaintenanceEnd
	row.Tags = strings.TrimSpace(req.Tags)
	row.Notes = req.Notes
	return nil
}

type lineEndpointPayload struct {
	CircuitID     uint   `json:"circuitId"`
	Side          string `json:"side"`
	SiteID        *uint  `json:"siteId"`
	DeviceGroupID *uint  `json:"deviceGroupId"`
	Address       string `json:"address"`
	Interface     string `json:"interface"`
	VLAN          int    `json:"vlan"`
	IPCIDRs       string `json:"ipCidrs"`
	Notes         string `json:"notes"`
}

func (s *Server) listLineEndpoints(c *gin.Context) {
	query := applySearch(s.db.Model(&models.LineEndpoint{}), c, "side", "address", "interface", "ip_cidrs")
	query = filterString(query, c, "side", "side")
	query = filterUint(query, c, "circuit_id", "circuitId")
	query = filterUint(query, c, "site_id", "siteId")
	query = filterUint(query, c, "device_group_id", "deviceGroupId")
	respondPage[models.LineEndpoint](c, query, "circuit_id desc, side asc")
}

func (s *Server) createLineEndpoint(c *gin.Context) {
	var req lineEndpointPayload
	if err := c.ShouldBindJSON(&req); err != nil {
		bad(c, err)
		return
	}
	row := models.LineEndpoint{}
	if err := s.applyLineEndpointPayload(&row, req); err != nil {
		bad(c, err)
		return
	}
	if s.lineEndpointSideExists(row.CircuitID, row.Side, 0) {
		bad(c, errors.New("circuit already has an endpoint on this side"))
		return
	}
	if err := s.db.Create(&row).Error; err != nil {
		fail(c, err)
		return
	}
	s.audit(c, actor(c), "line_endpoint.create", "line_endpoint", fmt.Sprint(row.ID), "{}")
	c.JSON(http.StatusCreated, row)
}

func (s *Server) updateLineEndpoint(c *gin.Context) {
	var row models.LineEndpoint
	if err := s.db.First(&row, c.Param("id")).Error; err != nil {
		notFound(c)
		return
	}
	var req lineEndpointPayload
	if err := c.ShouldBindJSON(&req); err != nil {
		bad(c, err)
		return
	}
	if err := s.applyLineEndpointPayload(&row, req); err != nil {
		bad(c, err)
		return
	}
	if s.lineEndpointSideExists(row.CircuitID, row.Side, row.ID) {
		bad(c, errors.New("circuit already has an endpoint on this side"))
		return
	}
	if err := s.db.Save(&row).Error; err != nil {
		fail(c, err)
		return
	}
	s.audit(c, actor(c), "line_endpoint.update", "line_endpoint", fmt.Sprint(row.ID), "{}")
	c.JSON(http.StatusOK, row)
}

func (s *Server) deleteLineEndpoint(c *gin.Context) {
	var row models.LineEndpoint
	if err := s.db.First(&row, c.Param("id")).Error; err != nil {
		notFound(c)
		return
	}
	if err := s.db.Delete(&row).Error; err != nil {
		fail(c, err)
		return
	}
	s.audit(c, actor(c), "line_endpoint.delete", "line_endpoint", fmt.Sprint(row.ID), "{}")
	c.Status(http.StatusNoContent)
}

func (s *Server) applyLineEndpointPayload(row *models.LineEndpoint, req lineEndpointPayload) error {
	req.Side = strings.ToLower(strings.TrimSpace(req.Side))
	if req.CircuitID == 0 || !contains([]string{"a", "z"}, req.Side) {
		return errors.New("circuitId and side (a or z) are required")
	}
	if err := s.requireID(&models.LineCircuit{}, req.CircuitID, "line circuit"); err != nil {
		return err
	}
	if err := s.requireOptionalID(&models.LineSite{}, req.SiteID, "line site"); err != nil {
		return err
	}
	if err := s.requireOptionalID(&models.DeviceGroup{}, req.DeviceGroupID, "device group"); err != nil {
		return err
	}
	if req.SiteID == nil && req.DeviceGroupID == nil && strings.TrimSpace(req.Address) == "" {
		return errors.New("endpoint requires a site, device group, or address")
	}
	if req.VLAN < 0 || req.VLAN > 4094 {
		return errors.New("vlan must be between 0 and 4094")
	}
	normalizedCIDRs, err := normalizeIPCIDRs(req.IPCIDRs)
	if err != nil {
		return err
	}
	row.CircuitID = req.CircuitID
	row.Side = req.Side
	row.SiteID = req.SiteID
	row.DeviceGroupID = req.DeviceGroupID
	row.Address = strings.TrimSpace(req.Address)
	row.Interface = strings.TrimSpace(req.Interface)
	row.VLAN = req.VLAN
	row.IPCIDRs = normalizedCIDRs
	row.Notes = req.Notes
	return nil
}

func (s *Server) lineEndpointSideExists(circuitID uint, side string, excludeID uint) bool {
	query := s.db.Model(&models.LineEndpoint{}).Where("circuit_id = ? AND side = ?", circuitID, side)
	if excludeID != 0 {
		query = query.Where("id <> ?", excludeID)
	}
	var count int64
	return query.Count(&count).Error == nil && count > 0
}

func normalizeIPCIDRs(value string) (string, error) {
	parts := strings.FieldsFunc(value, func(r rune) bool { return r == ',' || r == '\n' || r == '\r' || r == ';' })
	result := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if prefix, err := netip.ParsePrefix(part); err == nil {
			result = append(result, prefix.Masked().String())
			continue
		}
		if address, err := netip.ParseAddr(part); err == nil {
			result = append(result, address.String())
			continue
		}
		return "", fmt.Errorf("invalid IP or CIDR %q", part)
	}
	return strings.Join(result, "\n"), nil
}

type lineProbePayload struct {
	CircuitID       uint   `json:"circuitId"`
	NodeID          uint   `json:"nodeId"`
	Name            string `json:"name"`
	Type            string `json:"type"`
	Target          string `json:"target"`
	Payload         string `json:"payload"`
	IntervalSeconds int    `json:"intervalSeconds"`
	TimeoutMs       int    `json:"timeoutMs"`
	Enabled         *bool  `json:"enabled"`
}

func (s *Server) listLineProbes(c *gin.Context) {
	query := applySearch(s.db.Model(&models.LineProbe{}), c, "name", "type", "target", "status", "last_error")
	query = filterString(query, c, "status", "status")
	query = filterString(query, c, "type", "type")
	query = filterUint(query, c, "circuit_id", "circuitId")
	query = filterUint(query, c, "node_id", "nodeId")
	respondPage[models.LineProbe](c, query, "id desc")
}

func (s *Server) createLineProbe(c *gin.Context) {
	var req lineProbePayload
	if err := c.ShouldBindJSON(&req); err != nil {
		bad(c, err)
		return
	}
	row := models.LineProbe{}
	if err := s.applyLineProbePayload(&row, req); err != nil {
		bad(c, err)
		return
	}
	if err := s.db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Create(&row).Error; err != nil {
			return err
		}
		return bumpNodeRevisionWithDB(tx, row.NodeID, row.Revision)
	}); err != nil {
		fail(c, err)
		return
	}
	s.audit(c, actor(c), "line_probe.create", "line_probe", fmt.Sprint(row.ID), "{}")
	c.JSON(http.StatusCreated, row)
}

func (s *Server) updateLineProbe(c *gin.Context) {
	var row models.LineProbe
	if err := s.db.First(&row, c.Param("id")).Error; err != nil {
		notFound(c)
		return
	}
	previousNodeID := row.NodeID
	var req lineProbePayload
	if err := c.ShouldBindJSON(&req); err != nil {
		bad(c, err)
		return
	}
	if err := s.applyLineProbePayload(&row, req); err != nil {
		bad(c, err)
		return
	}
	if err := s.db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Save(&row).Error; err != nil {
			return err
		}
		if err := bumpNodeRevisionWithDB(tx, previousNodeID, row.Revision); err != nil {
			return err
		}
		if row.NodeID != previousNodeID {
			return bumpNodeRevisionWithDB(tx, row.NodeID, row.Revision)
		}
		return nil
	}); err != nil {
		fail(c, err)
		return
	}
	s.audit(c, actor(c), "line_probe.update", "line_probe", fmt.Sprint(row.ID), "{}")
	c.JSON(http.StatusOK, row)
}

func (s *Server) deleteLineProbe(c *gin.Context) {
	var row models.LineProbe
	if err := s.db.First(&row, c.Param("id")).Error; err != nil {
		notFound(c)
		return
	}
	revision := time.Now().UnixNano()
	if err := s.db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Where("probe_id = ?", row.ID).Delete(&models.LineProbeSample{}).Error; err != nil {
			return err
		}
		if err := tx.Delete(&row).Error; err != nil {
			return err
		}
		return bumpNodeRevisionWithDB(tx, row.NodeID, revision)
	}); err != nil {
		fail(c, err)
		return
	}
	s.audit(c, actor(c), "line_probe.delete", "line_probe", fmt.Sprint(row.ID), "{}")
	c.Status(http.StatusNoContent)
}

func (s *Server) applyLineProbePayload(row *models.LineProbe, req lineProbePayload) error {
	req.Name = strings.TrimSpace(req.Name)
	req.Type = strings.ToLower(strings.TrimSpace(req.Type))
	req.Target = strings.TrimSpace(req.Target)
	if req.CircuitID == 0 || req.NodeID == 0 || req.Name == "" || req.Target == "" {
		return errors.New("circuitId, nodeId, name, and target are required")
	}
	if err := s.requireID(&models.LineCircuit{}, req.CircuitID, "line circuit"); err != nil {
		return err
	}
	var node models.Node
	if err := s.db.First(&node, req.NodeID).Error; err != nil {
		return errors.New("node not found")
	}
	if !nodeHasCapability(node, "line_probe_v1") {
		return errors.New("node agent does not advertise line_probe_v1 capability")
	}
	if !contains([]string{"tcp", "http", "udp_echo"}, req.Type) {
		return errors.New("probe type must be tcp, http, or udp_echo")
	}
	if err := validateProbeTarget(req.Type, req.Target); err != nil {
		return err
	}
	if req.IntervalSeconds == 0 {
		req.IntervalSeconds = 30
	}
	if req.TimeoutMs == 0 {
		req.TimeoutMs = 3000
	}
	if req.IntervalSeconds < 5 || req.IntervalSeconds > 3600 {
		return errors.New("intervalSeconds must be between 5 and 3600")
	}
	if req.TimeoutMs < 100 || req.TimeoutMs > 30000 {
		return errors.New("timeoutMs must be between 100 and 30000")
	}
	enabled := true
	if req.Enabled != nil {
		enabled = *req.Enabled
	}
	row.CircuitID = req.CircuitID
	row.NodeID = req.NodeID
	row.Name = req.Name
	row.Type = req.Type
	row.Target = req.Target
	row.Payload = req.Payload
	row.IntervalSeconds = req.IntervalSeconds
	row.TimeoutMs = req.TimeoutMs
	row.Enabled = enabled
	row.Revision = time.Now().UnixNano()
	if row.Status == "" {
		row.Status = "pending"
	}
	return nil
}

func validateProbeTarget(probeType, target string) error {
	if probeType == "http" {
		parsed, err := url.ParseRequestURI(target)
		if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" {
			return errors.New("http probe target must be an http or https URL")
		}
		return nil
	}
	host, port, err := net.SplitHostPort(target)
	if err != nil || strings.TrimSpace(host) == "" || strings.TrimSpace(port) == "" {
		return errors.New("tcp and udp_echo targets must use host:port")
	}
	return nil
}

func (s *Server) listLineProbeSamples(c *gin.Context) {
	query := s.db.Model(&models.LineProbeSample{})
	query = filterUint(query, c, "probe_id", "probeId")
	query = filterUint(query, c, "circuit_id", "circuitId")
	query = filterUint(query, c, "node_id", "nodeId")
	query = filterDateRange(query, c, "checked_at")
	respondPage[models.LineProbeSample](c, query, "checked_at desc")
}

func (s *Server) agentProbeResult(c *gin.Context) {
	node := ctxNode(c)
	var req struct {
		ProbeID   uint    `json:"probeId"`
		Revision  int64   `json:"revision"`
		Success   bool    `json:"success"`
		LatencyMs float64 `json:"latencyMs"`
		Error     string  `json:"error"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		bad(c, err)
		return
	}
	if req.ProbeID == 0 || req.Revision <= 0 || req.LatencyMs < 0 || math.IsNaN(req.LatencyMs) || math.IsInf(req.LatencyMs, 0) {
		bad(c, errors.New("probeId, revision, and a valid non-negative latencyMs are required"))
		return
	}
	var probe models.LineProbe
	if err := s.db.Where("id = ? AND node_id = ?", req.ProbeID, node.ID).First(&probe).Error; err != nil {
		forbidden(c)
		return
	}
	if req.Revision != probe.Revision {
		bad(c, errStaleLineProbeResult)
		return
	}
	now := time.Now().UTC()
	status := "up"
	if !req.Success {
		status = "down"
	}
	errorMessage := strings.TrimSpace(req.Error)
	if len(errorMessage) > 1000 {
		errorMessage = errorMessage[:1000]
	}
	previousStatus := probe.Status
	updates := map[string]any{
		"status": status, "last_latency_ms": req.LatencyMs, "last_error": errorMessage, "last_checked_at": &now,
	}
	if req.Success {
		updates["consecutive_failures"] = 0
	} else {
		updates["consecutive_failures"] = gorm.Expr("consecutive_failures + 1")
	}
	if err := s.db.Transaction(func(tx *gorm.DB) error {
		result := tx.Model(&models.LineProbe{}).
			Where("id = ? AND revision = ?", probe.ID, req.Revision).
			Updates(updates)
		if result.Error != nil {
			return result.Error
		}
		if result.RowsAffected != 1 {
			return errStaleLineProbeResult
		}
		return tx.Create(&models.LineProbeSample{
			ProbeID: probe.ID, CircuitID: probe.CircuitID, NodeID: node.ID,
			Success: req.Success, LatencyMs: req.LatencyMs, Error: errorMessage, CheckedAt: now,
		}).Error
	}); err != nil {
		if errors.Is(err, errStaleLineProbeResult) {
			bad(c, err)
			return
		}
		fail(c, err)
		return
	}
	if previousStatus != status {
		severity := "info"
		if status == "down" {
			severity = "error"
		}
		s.agentEvent(node.ID, "line_probe."+status, severity, status, errorMessage, map[string]any{
			"probeId": probe.ID, "circuitId": probe.CircuitID, "latencyMs": req.LatencyMs, "previousStatus": previousStatus,
		})
	}
	s.maybePruneProbeSamples(now)
	c.Status(http.StatusNoContent)
}

func bumpNodeRevisionWithDB(db *gorm.DB, nodeID uint, revision int64) error {
	if nodeID == 0 {
		return nil
	}
	return db.Model(&models.Node{}).
		Where("id = ?", nodeID).
		Update("desired_revision", desiredRevisionExpr(revision)).Error
}

func (s *Server) maybePruneProbeSamples(now time.Time) {
	s.maintenanceMu.Lock()
	if !s.lastProbePrune.IsZero() && now.Sub(s.lastProbePrune) < time.Hour {
		s.maintenanceMu.Unlock()
		return
	}
	s.lastProbePrune = now
	s.maintenanceMu.Unlock()
	_ = s.db.Where("checked_at < ?", now.Add(-30*24*time.Hour)).Delete(&models.LineProbeSample{}).Error
}
