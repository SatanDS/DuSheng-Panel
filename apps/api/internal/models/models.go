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

type User struct {
	BaseModel
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

type Node struct {
	BaseModel
	DeviceGroupID        uint       `gorm:"index;not null" json:"deviceGroupId"`
	Name                 string     `gorm:"size:120;not null" json:"name"`
	UUID                 string     `gorm:"uniqueIndex;size:80;not null" json:"uuid"`
	TokenHash            string     `gorm:"index;size:128;not null" json:"-"`
	Status               string     `gorm:"index;size:20;not null;default:offline" json:"status"`
	Version              string     `gorm:"size:80" json:"version"`
	PublicIP             string     `gorm:"size:80" json:"publicIp"`
	ConnectHost          string     `gorm:"size:160" json:"connectHost"`
	LastSeenAt           *time.Time `gorm:"index" json:"lastSeenAt"`
	SystemJSON           string     `gorm:"type:text" json:"systemJson"`
	AppliedRevision      int64      `json:"appliedRevision"`
	DesiredRevision      int64      `json:"desiredRevision"`
	UninstallRequestedAt *time.Time `json:"uninstallRequestedAt"`
	UninstallConfirmedAt *time.Time `json:"uninstallConfirmedAt"`
	UninstallCommandID   string     `gorm:"index;size:120" json:"uninstallCommandId"`
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
	AdvancedJSON      string  `gorm:"type:text" json:"advancedJson"`
}

type ForwardRule struct {
	BaseModel
	UserID           uint   `gorm:"index;not null" json:"userId"`
	TunnelID         uint   `gorm:"index;uniqueIndex:idx_forward_rules_tunnel_listen;not null" json:"tunnelId"`
	Name             string `gorm:"size:120;not null" json:"name"`
	Protocol         string `gorm:"size:20;not null;default:tcp" json:"protocol"`
	ListenPort       int    `gorm:"index;uniqueIndex:idx_forward_rules_tunnel_listen;not null" json:"listenPort"`
	RemoteHost       string `gorm:"size:255;not null" json:"remoteHost"`
	RemotePort       int    `gorm:"not null" json:"remotePort"`
	Status           string `gorm:"index;size:30;not null;default:unsynced" json:"status"`
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
	UserID    uint      `gorm:"index;index:idx_traffic_user_sampled" json:"userId"`
	RuleID    uint      `gorm:"index;index:idx_traffic_rule_sampled" json:"ruleId"`
	NodeID    uint      `gorm:"index;index:idx_traffic_node_sampled" json:"nodeId"`
	Direction string    `gorm:"size:10" json:"direction"`
	Bytes     int64     `json:"bytes"`
	SampledAt time.Time `gorm:"index;index:idx_traffic_user_sampled;index:idx_traffic_rule_sampled;index:idx_traffic_node_sampled" json:"sampledAt"`
}

type AuditLog struct {
	BaseModel
	ActorID      *uint  `gorm:"index" json:"actorId"`
	Action       string `gorm:"index;size:100;not null" json:"action"`
	ResourceType string `gorm:"index;size:80;not null" json:"resourceType"`
	ResourceID   string `gorm:"index;size:80" json:"resourceId"`
	MetadataJSON string `gorm:"type:text" json:"metadataJson"`
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
