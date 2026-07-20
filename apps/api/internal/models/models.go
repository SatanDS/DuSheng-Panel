package models

import "time"

type BaseModel struct {
	ID        uint      `gorm:"primaryKey" json:"id"`
	CreatedAt time.Time `json:"createdAt"`
	UpdatedAt time.Time `json:"updatedAt"`
}

type SchemaMigration struct {
	Version   string    `gorm:"primaryKey;size:80" json:"version"`
	AppliedAt time.Time `json:"appliedAt"`
}

type Tenant struct {
	BaseModel
	Name              string     `gorm:"uniqueIndex;size:120;not null" json:"name"`
	Code              string     `gorm:"uniqueIndex;size:60;not null" json:"code"`
	Status            string     `gorm:"index;size:20;not null;default:active" json:"status"`
	TrafficLimitBytes int64      `gorm:"not null;default:0" json:"trafficLimitBytes"`
	UsedBytes         int64      `gorm:"not null;default:0" json:"usedBytes"`
	ForwardLimit      int        `gorm:"not null;default:0" json:"forwardLimit"`
	UserLimit         int        `gorm:"not null;default:0" json:"userLimit"`
	ResetIntervalDays int        `gorm:"not null;default:0" json:"resetIntervalDays"`
	PeriodStartedAt   *time.Time `gorm:"index" json:"periodStartedAt"`
	NextResetAt       *time.Time `gorm:"index" json:"nextResetAt"`
	QuotaBlocked      bool       `gorm:"index;not null;default:false" json:"quotaBlocked"`
	QuotaBlockedAt    *time.Time `json:"quotaBlockedAt"`
	ExpiresAt         *time.Time `gorm:"index" json:"expiresAt"`
	Notes             string     `gorm:"type:text" json:"notes"`
}

type TenantTunnelGrant struct {
	BaseModel
	TenantID     uint `gorm:"uniqueIndex:idx_tenant_tunnel_grant;index;not null" json:"tenantId"`
	TunnelID     uint `gorm:"uniqueIndex:idx_tenant_tunnel_grant;index;not null" json:"tunnelId"`
	ForwardLimit int  `gorm:"not null;default:0" json:"forwardLimit"`
	PortStart    int  `gorm:"not null;default:0" json:"portStart"`
	PortEnd      int  `gorm:"not null;default:0" json:"portEnd"`
}

type TenantTrafficHourlyBucket struct {
	BaseModel
	TenantID        uint      `gorm:"uniqueIndex:idx_tenant_traffic_hour;index;not null" json:"tenantId"`
	BucketStartedAt time.Time `gorm:"uniqueIndex:idx_tenant_traffic_hour;index;not null" json:"bucketStartedAt"`
	InBytes         int64     `gorm:"not null;default:0" json:"inBytes"`
	OutBytes        int64     `gorm:"not null;default:0" json:"outBytes"`
	BilledBytes     int64     `gorm:"not null;default:0" json:"billedBytes"`
}

type PortLease struct {
	BaseModel
	EntryGroupID uint   `gorm:"uniqueIndex:idx_port_lease_scope;index;not null" json:"entryGroupId"`
	BindIP       string `gorm:"uniqueIndex:idx_port_lease_scope;size:80;not null;default:*" json:"bindIp"`
	Transport    string `gorm:"uniqueIndex:idx_port_lease_scope;uniqueIndex:idx_port_lease_rule_transport;size:8;not null" json:"transport"`
	ListenPort   int    `gorm:"uniqueIndex:idx_port_lease_scope;index;not null" json:"listenPort"`
	RuleID       uint   `gorm:"uniqueIndex:idx_port_lease_rule_transport;index;not null" json:"ruleId"`
}

type User struct {
	BaseModel
	TenantID       *uint      `gorm:"index" json:"tenantId"`
	Username       string     `gorm:"uniqueIndex;size:80;not null" json:"username"`
	DisplayName    string     `gorm:"size:120" json:"displayName"`
	PasswordHash   string     `gorm:"size:255;not null" json:"-"`
	Role           string     `gorm:"index;size:20;not null;default:user" json:"role"`
	Status         string     `gorm:"index;size:20;not null;default:active" json:"status"`
	FlowLimitBytes int64      `json:"flowLimitBytes"`
	UsedBytes      int64      `json:"usedBytes"`
	ForwardLimit   int        `json:"forwardLimit"`
	ExpiresAt      *time.Time `json:"expiresAt"`
}

type DeviceGroup struct {
	BaseModel
	Name             string  `gorm:"size:120;not null" json:"name"`
	Role             string  `gorm:"size:20;not null" json:"role"`
	BindIPs          string  `gorm:"size:255" json:"bindIPs"`
	PortStart        int     `json:"portStart"`
	PortEnd          int     `json:"portEnd"`
	TrafficRatio     float64 `gorm:"not null;default:1" json:"trafficRatio"`
	ProtocolPolicyID *uint   `json:"protocolPolicyId"`
	FailoverGroupID  *uint   `json:"failoverGroupId"`
	AdvancedJSON     string  `gorm:"type:text" json:"advancedJson"`
}

type LineProvider struct {
	BaseModel
	Name           string `gorm:"size:120;not null" json:"name"`
	Code           string `gorm:"index;size:60" json:"code"`
	Status         string `gorm:"index;size:30;not null;default:active" json:"status"`
	SupportContact string `gorm:"size:120" json:"supportContact"`
	SupportPhone   string `gorm:"size:80" json:"supportPhone"`
	SupportEmail   string `gorm:"size:160" json:"supportEmail"`
	PortalURL      string `gorm:"size:255" json:"portalUrl"`
	Notes          string `gorm:"type:text" json:"notes"`
}

type LineSite struct {
	BaseModel
	Name    string `gorm:"size:120;not null" json:"name"`
	Code    string `gorm:"index;size:60" json:"code"`
	Status  string `gorm:"index;size:30;not null;default:active" json:"status"`
	Country string `gorm:"size:80" json:"country"`
	Region  string `gorm:"size:120" json:"region"`
	City    string `gorm:"size:120" json:"city"`
	Address string `gorm:"size:255" json:"address"`
	Notes   string `gorm:"type:text" json:"notes"`
}

type LineCircuit struct {
	BaseModel
	ProviderID       uint       `gorm:"index;not null" json:"providerId"`
	Name             string     `gorm:"size:120;not null" json:"name"`
	CircuitCode      string     `gorm:"index;size:100" json:"circuitCode"`
	ServiceType      string     `gorm:"index;size:40;not null;default:iepl" json:"serviceType"`
	Status           string     `gorm:"index;size:30;not null;default:planned" json:"status"`
	BandwidthMbps    int        `json:"bandwidthMbps"`
	CommittedMbps    int        `json:"committedMbps"`
	LatencySLAms     float64    `gorm:"column:latency_sla_ms" json:"latencySlaMs"`
	PacketLossSLAPct float64    `gorm:"column:packet_loss_sla_pct" json:"packetLossSlaPct"`
	MonthlyCost      float64    `json:"monthlyCost"`
	Currency         string     `gorm:"size:10" json:"currency"`
	StartsAt         *time.Time `json:"startsAt"`
	ExpiresAt        *time.Time `gorm:"index" json:"expiresAt"`
	MaintenanceStart *time.Time `json:"maintenanceStart"`
	MaintenanceEnd   *time.Time `json:"maintenanceEnd"`
	Tags             string     `gorm:"type:text" json:"tags"`
	Notes            string     `gorm:"type:text" json:"notes"`
}

type LineEndpoint struct {
	BaseModel
	CircuitID     uint   `gorm:"index;uniqueIndex:idx_line_endpoint_side;not null" json:"circuitId"`
	Side          string `gorm:"size:10;uniqueIndex:idx_line_endpoint_side;not null" json:"side"`
	SiteID        *uint  `gorm:"index" json:"siteId"`
	DeviceGroupID *uint  `gorm:"index" json:"deviceGroupId"`
	Address       string `gorm:"size:255" json:"address"`
	Interface     string `gorm:"size:120" json:"interface"`
	VLAN          int    `json:"vlan"`
	IPCIDRs       string `gorm:"column:ip_cidrs;type:text" json:"ipCidrs"`
	Notes         string `gorm:"type:text" json:"notes"`
}

type LineProbe struct {
	BaseModel
	CircuitID           uint       `gorm:"index;not null" json:"circuitId"`
	NodeID              uint       `gorm:"index;not null" json:"nodeId"`
	Name                string     `gorm:"size:120;not null" json:"name"`
	Type                string     `gorm:"index;size:30;not null" json:"type"`
	Target              string     `gorm:"size:255;not null" json:"target"`
	Payload             string     `gorm:"type:text" json:"payload"`
	IntervalSeconds     int        `gorm:"not null;default:30" json:"intervalSeconds"`
	TimeoutMs           int        `gorm:"not null;default:3000" json:"timeoutMs"`
	Enabled             bool       `gorm:"index;not null;default:true" json:"enabled"`
	Revision            int64      `gorm:"index;not null" json:"revision"`
	Status              string     `gorm:"index;size:20;not null;default:pending" json:"status"`
	LastLatencyMs       float64    `json:"lastLatencyMs"`
	LastError           string     `gorm:"type:text" json:"lastError"`
	LastCheckedAt       *time.Time `gorm:"index" json:"lastCheckedAt"`
	ConsecutiveFailures int        `json:"consecutiveFailures"`
}

type LineProbeSample struct {
	BaseModel
	ProbeID   uint      `gorm:"index;index:idx_probe_sample_time;not null" json:"probeId"`
	CircuitID uint      `gorm:"index;not null" json:"circuitId"`
	NodeID    uint      `gorm:"index;not null" json:"nodeId"`
	Success   bool      `gorm:"index;not null" json:"success"`
	LatencyMs float64   `json:"latencyMs"`
	Error     string    `gorm:"type:text" json:"error"`
	CheckedAt time.Time `gorm:"index;index:idx_probe_sample_time;not null" json:"checkedAt"`
}

type Node struct {
	BaseModel
	DeviceGroupID        uint       `gorm:"index;not null" json:"deviceGroupId"`
	Name                 string     `gorm:"size:120;not null" json:"name"`
	UUID                 string     `gorm:"uniqueIndex;size:80;not null" json:"uuid"`
	TokenHash            string     `gorm:"index;size:128;not null" json:"-"`
	Status               string     `gorm:"index;size:20;not null;default:offline" json:"status"`
	Version              string     `gorm:"size:80" json:"version"`
	Capabilities         []string   `gorm:"serializer:json;type:text" json:"capabilities"`
	PublicIP             string     `gorm:"size:80" json:"publicIp"`
	ConnectHost          string     `gorm:"size:160" json:"connectHost"`
	LastSeenAt           *time.Time `gorm:"index" json:"lastSeenAt"`
	SystemJSON           string     `gorm:"type:text" json:"systemJson"`
	AppliedRevision      int64      `json:"appliedRevision"`
	DesiredRevision      int64      `json:"desiredRevision"`
	LastGoodRevision     int64      `json:"lastGoodRevision"`
	ConfigAckRevision    int64      `json:"configAckRevision"`
	ConfigNonce          string     `gorm:"size:80" json:"configNonce"`
	ConfigStatus         string     `gorm:"index;size:30" json:"configStatus"`
	ConfigMessage        string     `gorm:"type:text" json:"configMessage"`
	ConfigAckAt          *time.Time `gorm:"index" json:"configAckAt"`
	UninstallRequestedAt *time.Time `json:"uninstallRequestedAt"`
	UninstallConfirmedAt *time.Time `json:"uninstallConfirmedAt"`
	UninstallCommandID   string     `gorm:"index;size:120" json:"uninstallCommandId"`
	UninstallAckStatus   string     `gorm:"size:30" json:"uninstallAckStatus"`
	UninstallAckMessage  string     `gorm:"type:text" json:"uninstallAckMessage"`
	UninstallAckAt       *time.Time `json:"uninstallAckAt"`
	UninstallLegacy      bool       `gorm:"not null;default:false" json:"uninstallLegacy"`
}

type Tunnel struct {
	BaseModel
	Name              string  `gorm:"size:120;not null" json:"name"`
	Mode              string  `gorm:"size:30;not null;default:single" json:"mode"`
	EntryGroupID      uint    `gorm:"index;not null" json:"entryGroupId"`
	ExitGroupID       *uint   `gorm:"index" json:"exitGroupId"`
	Protocol          string  `gorm:"size:40;not null;default:direct" json:"protocol"`
	FlowAccounting    string  `gorm:"size:20;not null;default:single" json:"flowAccounting"`
	EntryTrafficRatio float64 `gorm:"not null;default:1" json:"entryTrafficRatio"`
	ExitTrafficRatio  float64 `gorm:"not null;default:1" json:"exitTrafficRatio"`
	ProtocolPolicyID  *uint   `json:"protocolPolicyId"`
	LineCircuitID     *uint   `gorm:"index" json:"lineCircuitId"`
	AdvancedJSON      string  `gorm:"type:text" json:"advancedJson"`
}

type ForwardRule struct {
	BaseModel
	TenantID         *uint  `gorm:"index" json:"tenantId"`
	UserID           uint   `gorm:"index;not null" json:"userId"`
	TunnelID         uint   `gorm:"index;not null" json:"tunnelId"`
	Name             string `gorm:"size:120;not null" json:"name"`
	Protocol         string `gorm:"size:20;not null;default:tcp" json:"protocol"`
	ListenPort       int    `gorm:"index;not null" json:"listenPort"`
	RemoteHost       string `gorm:"size:255;not null" json:"remoteHost"`
	RemotePort       int    `gorm:"not null" json:"remotePort"`
	Status           string `gorm:"index;size:30;not null;default:unsynced" json:"status"`
	QuotaSource      string `gorm:"index;size:20" json:"quotaSource"`
	Strategy         string `gorm:"size:40;not null;default:least_conn" json:"strategy"`
	ProtocolPolicyID *uint  `json:"protocolPolicyId"`
	InBytes          int64  `json:"inBytes"`
	OutBytes         int64  `json:"outBytes"`
	Revision         int64  `gorm:"index" json:"revision"`
	LastSyncError    string `gorm:"type:text" json:"lastSyncError"`
	ViolationCount   int    `json:"violationCount"`
}

type ProtocolPolicy struct {
	BaseModel
	Name                    string `gorm:"size:120;uniqueIndex;not null" json:"name"`
	Template                string `gorm:"size:60;not null" json:"template"`
	Purpose                 string `gorm:"size:40;not null;default:custom" json:"purpose"`
	InspectionLevel         string `gorm:"size:20;not null;default:light" json:"inspectionLevel"`
	Mode                    string `gorm:"size:20;not null;default:block" json:"mode"`
	BlockTLS                bool   `json:"blockTls"`
	BlockQUIC               bool   `json:"blockQuic"`
	AllowPlainTCPOnly       bool   `json:"allowPlainTcpOnly"`
	AllowHTTPOnly           bool   `json:"allowHttpOnly"`
	BlockProxyLike          bool   `json:"blockProxyLike"`
	BlockEncryptedTunnel    bool   `json:"blockEncryptedTunnel"`
	ObservationMinutes      int    `json:"observationMinutes"`
	AuthorizedProtocols     string `gorm:"type:text" json:"authorizedProtocols"`
	BlockedProtocolGroups   string `gorm:"type:text" json:"blockedProtocolGroups"`
	HostAllowlist           string `gorm:"type:text" json:"hostAllowlist"`
	HostBlocklist           string `gorm:"type:text" json:"hostBlocklist"`
	SNIAllowlist            string `gorm:"type:text" json:"sniAllowlist"`
	SNIBlocklist            string `gorm:"type:text" json:"sniBlocklist"`
	ALPNAllowlist           string `gorm:"type:text" json:"alpnAllowlist"`
	ALPNBlocklist           string `gorm:"type:text" json:"alpnBlocklist"`
	TLSNoSNIAction          string `gorm:"size:20" json:"tlsNoSniAction"`
	QUICAction              string `gorm:"size:20" json:"quicAction"`
	SSHAction               string `gorm:"size:20" json:"sshAction"`
	UnknownTCPAction        string `gorm:"size:20" json:"unknownTcpAction"`
	UnknownUDPAction        string `gorm:"size:20" json:"unknownUdpAction"`
	NDPILowConfidenceAction string `gorm:"size:20" json:"ndpiLowConfidenceAction"`
	DPITimeoutMs            int    `json:"dpiTimeoutMs"`
	Description             string `gorm:"type:text" json:"description"`
}

type SpeedLimit struct {
	BaseModel
	Name        string `gorm:"size:120;not null" json:"name"`
	TenantID    *uint  `gorm:"index" json:"tenantId"`
	UserID      *uint  `gorm:"index" json:"userId"`
	TunnelID    *uint  `gorm:"index" json:"tunnelId"`
	RuleID      *uint  `gorm:"index" json:"ruleId"`
	UploadBps   int64  `json:"uploadBps"`
	DownloadBps int64  `json:"downloadBps"`
	MaxConns    int    `json:"maxConns"`
	MaxIPs      int    `json:"maxIps"`
}

type TrafficSample struct {
	BaseModel
	TenantID  *uint     `gorm:"index;index:idx_traffic_tenant_sampled" json:"tenantId"`
	UserID    uint      `gorm:"index;index:idx_traffic_user_sampled" json:"userId"`
	RuleID    uint      `gorm:"index;index:idx_traffic_rule_sampled" json:"ruleId"`
	NodeID    uint      `gorm:"index;index:idx_traffic_node_sampled" json:"nodeId"`
	Direction string    `gorm:"size:10" json:"direction"`
	Bytes     int64     `json:"bytes"`
	SampledAt time.Time `gorm:"index;index:idx_traffic_tenant_sampled;index:idx_traffic_user_sampled;index:idx_traffic_rule_sampled;index:idx_traffic_node_sampled" json:"sampledAt"`
}

type AgentTrafficReport struct {
	BaseModel
	NodeID   uint   `gorm:"index;uniqueIndex:idx_agent_traffic_report_node_report;not null" json:"nodeId"`
	ReportID string `gorm:"size:120;uniqueIndex:idx_agent_traffic_report_node_report;not null" json:"reportId"`
	Accepted int    `json:"accepted"`
}

type AuditLog struct {
	BaseModel
	ActorID      *uint  `gorm:"index" json:"actorId"`
	Action       string `gorm:"index;size:100;not null" json:"action"`
	ResourceType string `gorm:"index;size:80;not null" json:"resourceType"`
	ResourceID   string `gorm:"index;size:80" json:"resourceId"`
	MetadataJSON string `gorm:"type:text" json:"metadataJson"`
}

type AgentEvent struct {
	BaseModel
	NodeID     uint      `gorm:"index;not null" json:"nodeId"`
	Type       string    `gorm:"index;size:80;not null" json:"type"`
	Severity   string    `gorm:"index;size:20;not null" json:"severity"`
	Status     string    `gorm:"index;size:30" json:"status"`
	Message    string    `gorm:"type:text" json:"message"`
	DetailJSON string    `gorm:"type:text" json:"detailJson"`
	OccurredAt time.Time `gorm:"index" json:"occurredAt"`
}

type InstallToken struct {
	BaseModel
	Label         string     `gorm:"size:120" json:"label"`
	TokenHash     string     `gorm:"uniqueIndex;size:128;not null" json:"-"`
	DeviceGroupID uint       `gorm:"index;not null" json:"deviceGroupId"`
	ExpiresAt     time.Time  `json:"expiresAt"`
	UsedAt        *time.Time `json:"usedAt"`
}

type ProtocolViolation struct {
	BaseModel
	RuleID     uint      `gorm:"index" json:"ruleId"`
	NodeID     uint      `gorm:"index" json:"nodeId"`
	PolicyID   uint      `gorm:"index" json:"policyId"`
	Protocol   string    `gorm:"index;size:60" json:"protocol"`
	SourceIP   string    `gorm:"size:120" json:"sourceIp"`
	Action     string    `gorm:"index;size:20" json:"action"`
	Detail     string    `gorm:"type:text" json:"detail"`
	OccurredAt time.Time `gorm:"index" json:"occurredAt"`
}
