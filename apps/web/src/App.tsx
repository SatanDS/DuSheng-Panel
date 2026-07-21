import { useCallback, useEffect, useMemo, useState } from "react";
import type { FormEvent, ReactNode } from "react";
import {
  Activity,
  AlertTriangle,
  Boxes,
	Check,
	ChevronDown,
	ChevronRight,
  Download,
  Gauge,
  KeyRound,
  LogOut,
	Menu,
  Network,
  Pencil,
  Plus,
  RefreshCw,
	Rocket,
  Route,
  Save,
  ScrollText,
  Server,
	Settings2,
  ShieldCheck,
  SlidersHorizontal,
  Trash2,
  Upload,
  Users,
  X
} from "lucide-react";
import type { LucideIcon } from "lucide-react";
import { api, clearSession, getStoredSession, saveSession, setUnauthorizedHandler } from "./api";
import type {
  DashboardPayload,
  Entity,
  ForwardRule,
  InstallToken,
  InstallTokenResponse,
  LoginResponse,
  ProtocolViolation,
  AuditLog,
	AgentEvent,
	Session,
	TenantTrafficPayload,
	UserTunnelGrant
} from "./types";

type PageKey =
  | "dashboard"
	| "quick-start"
	| "tenant-overview"
	| "tenants"
	| "tenant-tunnel-grants"
  | "forward-rules"
  | "nodes"
	| "line-assets"
  | "device-groups"
  | "tunnels"
  | "protocol-policies"
  | "speed-limits"
  | "violations"
	| "node-events"
  | "audit-logs"
  | "users";

type FieldType = "text" | "password" | "number" | "select" | "textarea" | "checkbox" | "datetime-local";

interface FieldConfig {
  key: string;
  label: string;
  type?: FieldType;
  options?: { value: string; label: string }[];
  placeholder?: string;
  required?: boolean;
  requiredOnCreate?: boolean;
  optional?: boolean;
  min?: number;
  max?: number;
  step?: number | string;
  rows?: number;
  fullWidth?: boolean;
	reference?: ReferenceKey;
	defaultValue?: string | boolean;
	advanced?: boolean;
}

interface ColumnConfig {
  key: string;
  label: string;
  render?: (row: Entity) => ReactNode;
  className?: string;
}

type CRUDPageKey = Exclude<PageKey, "dashboard" | "quick-start" | "tenant-overview" | "line-assets" | "violations" | "node-events" | "audit-logs">;
type LineAssetKey = "line-providers" | "line-sites" | "line-circuits" | "line-endpoints" | "line-probes";

type NavSectionKey = "workspace" | "business" | "operations" | "advanced";

interface NavItem {
	key: PageKey;
	label: string;
	icon: LucideIcon;
	section: NavSectionKey;
	roles?: string[];
}

interface ResourceConfig {
  key: CRUDPageKey | LineAssetKey;
  title: string;
  eyebrow: string;
  endpoint: string;
  fields: FieldConfig[];
  columns: ColumnConfig[];
  createLabel: string;
  disableCreate?: boolean;
  disableDelete?: boolean;
}

type FormDraft = Record<string, string | boolean>;
type ReferenceKey =
	| "tenants"
	| "users"
	| "tunnels"
	| "protocol-policies"
	| "device-groups"
	| "forward-rules"
	| "line-providers"
	| "line-sites"
	| "line-circuits"
	| "nodes";

const pageSize = 25;

const valueLabels: Record<string, string> = {
  active: "启用",
  disabled: "禁用",
  suspended: "暂停",
  uninstalling: "卸载中",
  uninstall_legacy: "旧版卸载待确认",
  uninstall_timeout: "卸载确认超时",
  uninstall_failed: "卸载失败",
  accepted: "已接收",
  done: "已完成",
  failed: "失败",
  timeout: "超时",
  legacy: "旧版确认",
  online: "在线",
  offline: "离线",
  maintenance: "维护中",
	inactive: "停用",
	planned: "规划中",
	provisioning: "开通中",
	retired: "已退役",
	terminated: "已终止",
	iepl: "IEPL",
	iplc: "IPLC",
	mpls: "MPLS",
	internet: "互联网",
	a: "A 端",
	z: "Z 端",
	pending: "等待探测",
	up: "正常",
	down: "故障",
	tcp: "TCP",
	http: "HTTP",
	udp_echo: "UDP 回显",
  entry: "入口",
  exit: "出口",
  relay: "中继",
  single: "单端",
  failover: "故障切换",
  direct: "直连",
  tcp_udp: "TCP + UDP",
  least_conn: "最少连接",
  round_robin: "轮询",
  random: "随机",
  source_hash: "源地址哈希",
  both: "双侧",
  block: "阻断",
  alert: "告警",
  observe: "观察",
  limit: "限速",
  allow: "允许",
  gaming: "游戏加速",
  authorized_ss: "授权 SS",
  ssh_ops: "SSH 运维",
  daily: "日常上网",
  normal: "普通转发",
  strict: "严格合规",
  custom: "自定义",
  light: "轻量首包",
  advanced: "高级 DPI",
  deep: "深度 DPI",
  ndpi: "nDPI",
  game_acceleration: "游戏加速",
  daily_browsing: "日常上网",
  normal_forward: "普通转发",
  strict_compliance: "严格合规",
  synced: "已同步",
  unsynced: "未同步",
	applied: "已应用",
	rejected: "已拒绝",
	rolled_back: "已回滚",
	lease_expired: "配置租约过期",
	warning: "警告",
	info: "信息",
	error: "错误",
  quota_exhausted: "流量用尽",
  running: "运行中",
  unknown: "未知",
  missing: "缺失",
  not_configured: "未配置",
  iepl_iplc_no_tls: "IEPL/IPLC 禁止 TLS/QUIC",
  plain_tcp_only: "仅允许明文 TCP",
  http_only: "仅允许 HTTP",
  block_proxy_like: "阻断代理特征",
  admin: "管理员",
	tenant_admin: "租户管理员",
  user: "普通用户",
  create: "创建",
  update: "更新",
  delete: "删除",
  login: "登录",
  forward_rule: "转发规则",
  forward_rules: "转发规则",
  node: "节点",
  nodes: "节点",
  device_group: "设备组",
  device_groups: "设备组",
  tunnel: "线路",
  tunnels: "线路",
  protocol_policy: "协议策略",
  protocol_policies: "协议策略",
  speed_limit: "限速策略",
  speed_limits: "限速策略",
  install_token: "安装令牌",
  install_tokens: "安装令牌"
};

const navSections: { key: NavSectionKey; label: string }[] = [
	{ key: "workspace", label: "工作台" },
	{ key: "business", label: "业务管理" },
	{ key: "operations", label: "运行与安全" },
	{ key: "advanced", label: "高级设置" }
];

const navItems: NavItem[] = [
	{ key: "dashboard", label: "总览", icon: Gauge, section: "workspace" },
	{ key: "quick-start", label: "快速开通", icon: Rocket, section: "workspace" },
	{ key: "forward-rules", label: "转发规则", icon: Route, section: "business" },
	{ key: "nodes", label: "节点", icon: Server, section: "business", roles: ["admin"] },
	{ key: "tunnels", label: "转发线路", icon: Network, section: "business", roles: ["admin"] },
	{ key: "users", label: "用户", icon: Users, section: "business", roles: ["admin", "tenant_admin"] },
	{ key: "violations", label: "协议告警", icon: AlertTriangle, section: "operations", roles: ["admin"] },
	{ key: "node-events", label: "节点日志", icon: Activity, section: "operations", roles: ["admin"] },
	{ key: "audit-logs", label: "操作日志", icon: ScrollText, section: "operations", roles: ["admin"] },
	{ key: "line-assets", label: "专线资产", icon: Network, section: "advanced", roles: ["admin"] },
	{ key: "device-groups", label: "节点分组", icon: Boxes, section: "advanced", roles: ["admin"] },
	{ key: "protocol-policies", label: "协议策略", icon: ShieldCheck, section: "advanced", roles: ["admin"] },
	{ key: "speed-limits", label: "限速策略", icon: SlidersHorizontal, section: "advanced", roles: ["admin"] }
];

const protocolOptions = [
  { value: "tcp", label: "TCP" },
  { value: "udp", label: "UDP" },
  { value: "tcp_udp", label: "TCP + UDP" }
];

const policyOptions = [
  { value: "game_acceleration", label: "游戏加速" },
  { value: "authorized_ss", label: "授权 SS 代理" },
  { value: "ssh_ops", label: "SSH 运维加速" },
  { value: "daily_browsing", label: "日常上网" },
  { value: "normal_forward", label: "普通转发" },
  { value: "strict_compliance", label: "严格合规" },
  { value: "iepl_iplc_no_tls", label: "IEPL/IPLC 禁止 TLS/QUIC" },
  { value: "plain_tcp_only", label: "仅允许明文 TCP" },
  { value: "http_only", label: "仅允许 HTTP" },
  { value: "block_proxy_like", label: "阻断代理特征" },
  { value: "custom", label: "自定义" }
];

const policyPurposeOptions = [
  { value: "gaming", label: "游戏加速" },
  { value: "authorized_ss", label: "授权 SS" },
  { value: "ssh_ops", label: "SSH 运维" },
  { value: "daily", label: "日常上网" },
  { value: "normal", label: "普通转发" },
  { value: "strict", label: "严格合规" },
  { value: "custom", label: "自定义" }
];

const inspectionOptions = [
  { value: "off", label: "关闭" },
  { value: "light", label: "轻量首包" },
  { value: "advanced", label: "高级 DPI" },
  { value: "deep", label: "深度 DPI" },
  { value: "ndpi", label: "nDPI" }
];

const policyActionOptions = [
  { value: "allow", label: "允许" },
  { value: "observe", label: "观察" },
  { value: "alert", label: "告警" },
  { value: "limit", label: "限速" },
  { value: "block", label: "阻断" }
];

const lineAssetConfigs: Record<LineAssetKey, ResourceConfig> = {
	"line-providers": {
		key: "line-providers",
		title: "运营商",
		eyebrow: "专线供应商与支持渠道",
		endpoint: "/line-providers",
		createLabel: "新增运营商",
		fields: [
			{ key: "name", label: "名称", required: true },
			{ key: "code", label: "代码" },
			{ key: "status", label: "状态", type: "select", options: [
				{ value: "active", label: "启用" }, { value: "inactive", label: "停用" }, { value: "suspended", label: "暂停" }
			] },
			{ key: "supportContact", label: "支持联系人" },
			{ key: "supportPhone", label: "支持电话" },
			{ key: "supportEmail", label: "支持邮箱" },
			{ key: "portalUrl", label: "工单门户" },
			{ key: "notes", label: "备注", type: "textarea", rows: 4, fullWidth: true }
		],
		columns: [
			{ key: "id", label: "ID", className: "mono" }, { key: "name", label: "名称" }, { key: "code", label: "代码" },
			{ key: "status", label: "状态", render: (row) => <StatusPill value={text(row.status)} /> },
			{ key: "supportContact", label: "联系人" }, { key: "supportPhone", label: "电话" },
			{ key: "updatedAt", label: "更新于", render: (row) => formatDate(row.updatedAt) }
		]
	},
	"line-sites": {
		key: "line-sites",
		title: "站点",
		eyebrow: "机房、POP 与业务位置",
		endpoint: "/line-sites",
		createLabel: "新增站点",
		fields: [
			{ key: "name", label: "名称", required: true }, { key: "code", label: "代码" },
			{ key: "status", label: "状态", type: "select", options: [
				{ value: "active", label: "启用" }, { value: "planned", label: "规划中" },
				{ value: "maintenance", label: "维护中" }, { value: "retired", label: "已退役" }
			] },
			{ key: "country", label: "国家/地区" }, { key: "region", label: "区域" }, { key: "city", label: "城市" },
			{ key: "address", label: "地址", fullWidth: true },
			{ key: "notes", label: "备注", type: "textarea", rows: 4, fullWidth: true }
		],
		columns: [
			{ key: "id", label: "ID", className: "mono" }, { key: "name", label: "名称" }, { key: "code", label: "代码" },
			{ key: "status", label: "状态", render: (row) => <StatusPill value={text(row.status)} /> },
			{ key: "country", label: "国家/地区" }, { key: "region", label: "区域" }, { key: "city", label: "城市" },
			{ key: "updatedAt", label: "更新于", render: (row) => formatDate(row.updatedAt) }
		]
	},
	"line-circuits": {
		key: "line-circuits",
		title: "物理线路",
		eyebrow: "IEPL/IPLC 合同、带宽与 SLA",
		endpoint: "/line-circuits",
		createLabel: "新增线路",
		fields: [
			{ key: "providerId", label: "运营商", type: "number", required: true, min: 1, reference: "line-providers" },
			{ key: "name", label: "线路名称", required: true }, { key: "circuitCode", label: "运营商线路号" },
			{ key: "serviceType", label: "业务类型", type: "select", options: [
				{ value: "iepl", label: "IEPL" }, { value: "iplc", label: "IPLC" }, { value: "mpls", label: "MPLS" },
				{ value: "internet", label: "互联网" }, { value: "custom", label: "自定义" }
			] },
			{ key: "status", label: "状态", type: "select", options: [
				{ value: "planned", label: "规划中" }, { value: "provisioning", label: "开通中" }, { value: "active", label: "启用" },
				{ value: "maintenance", label: "维护中" }, { value: "suspended", label: "暂停" }, { value: "terminated", label: "已终止" }
			] },
			{ key: "bandwidthMbps", label: "峰值带宽 Mbps", type: "number", min: 0 },
			{ key: "committedMbps", label: "承诺带宽 Mbps", type: "number", min: 0 },
			{ key: "latencySlaMs", label: "时延 SLA ms", type: "number", min: 0, step: 0.1 },
			{ key: "packetLossSlaPct", label: "丢包 SLA %", type: "number", min: 0, max: 100, step: 0.01 },
			{ key: "monthlyCost", label: "月成本", type: "number", min: 0, step: 0.01 }, { key: "currency", label: "币种" },
			{ key: "startsAt", label: "开始时间", type: "datetime-local", optional: true },
			{ key: "expiresAt", label: "到期时间", type: "datetime-local", optional: true },
			{ key: "maintenanceStart", label: "维护开始", type: "datetime-local", optional: true },
			{ key: "maintenanceEnd", label: "维护结束", type: "datetime-local", optional: true },
			{ key: "tags", label: "标签", fullWidth: true }, { key: "notes", label: "备注", type: "textarea", rows: 4, fullWidth: true }
		],
		columns: [
			{ key: "id", label: "ID", className: "mono" }, { key: "name", label: "名称" }, { key: "providerId", label: "运营商" },
			{ key: "serviceType", label: "类型", render: (row) => <Badge>{displayValue(row.serviceType)}</Badge> },
			{ key: "status", label: "状态", render: (row) => <StatusPill value={text(row.status)} /> },
			{ key: "bandwidthMbps", label: "峰值 Mbps" }, { key: "committedMbps", label: "承诺 Mbps" },
			{ key: "latencySlaMs", label: "时延 SLA" }, { key: "packetLossSlaPct", label: "丢包 SLA" },
			{ key: "expiresAt", label: "到期", render: (row) => formatDate(row.expiresAt) }
		]
	},
	"line-endpoints": {
		key: "line-endpoints",
		title: "A/Z 端点",
		eyebrow: "线路两端机房、接口与地址",
		endpoint: "/line-endpoints",
		createLabel: "新增端点",
		fields: [
			{ key: "circuitId", label: "物理线路", type: "number", required: true, min: 1, reference: "line-circuits" },
			{ key: "side", label: "端点", type: "select", options: [{ value: "a", label: "A 端" }, { value: "z", label: "Z 端" }] },
			{ key: "siteId", label: "站点", type: "number", optional: true, min: 1, reference: "line-sites" },
			{ key: "deviceGroupId", label: "设备组", type: "number", optional: true, min: 1, reference: "device-groups" },
			{ key: "address", label: "对接地址", fullWidth: true }, { key: "interface", label: "接口" },
			{ key: "vlan", label: "VLAN", type: "number", min: 0, max: 4094 },
			{ key: "ipCidrs", label: "IP/CIDR", type: "textarea", rows: 3, fullWidth: true },
			{ key: "notes", label: "备注", type: "textarea", rows: 4, fullWidth: true }
		],
		columns: [
			{ key: "id", label: "ID", className: "mono" }, { key: "circuitId", label: "线路" },
			{ key: "side", label: "端点", render: (row) => <Badge>{displayValue(row.side)}</Badge> },
			{ key: "siteId", label: "站点" }, { key: "deviceGroupId", label: "设备组" }, { key: "interface", label: "接口" },
			{ key: "vlan", label: "VLAN" }, { key: "ipCidrs", label: "IP/CIDR" },
			{ key: "updatedAt", label: "更新于", render: (row) => formatDate(row.updatedAt) }
		]
	},
	"line-probes": {
		key: "line-probes",
		title: "线路探测",
		eyebrow: "由指定 Agent 测量线路可达性与时延",
		endpoint: "/line-probes",
		createLabel: "新增探测",
		fields: [
			{ key: "circuitId", label: "物理线路", type: "number", required: true, min: 1, reference: "line-circuits" },
			{ key: "nodeId", label: "执行节点", type: "number", required: true, min: 1, reference: "nodes" },
			{ key: "name", label: "名称", required: true },
			{ key: "type", label: "探测类型", type: "select", options: [
				{ value: "tcp", label: "TCP 建连" }, { value: "http", label: "HTTP" }, { value: "udp_echo", label: "UDP 回显" }
			] },
			{ key: "target", label: "目标", required: true, placeholder: "host:port 或 https://..." },
			{ key: "payload", label: "UDP 回显内容" },
			{ key: "intervalSeconds", label: "间隔秒", type: "number", min: 5, max: 3600 },
			{ key: "timeoutMs", label: "超时 ms", type: "number", min: 100, max: 30000 },
			{ key: "enabled", label: "启用", type: "checkbox", defaultValue: true }
		],
		columns: [
			{ key: "id", label: "ID", className: "mono" }, { key: "name", label: "名称" }, { key: "circuitId", label: "线路" },
			{ key: "nodeId", label: "节点" }, { key: "type", label: "类型", render: (row) => <Badge>{displayValue(row.type)}</Badge> },
			{ key: "target", label: "目标" }, { key: "status", label: "状态", render: (row) => <StatusPill value={text(row.status)} /> },
			{ key: "lastLatencyMs", label: "时延", render: (row) => formatLatency(row.lastLatencyMs) },
			{ key: "consecutiveFailures", label: "连续失败" }, { key: "lastCheckedAt", label: "最后探测", render: (row) => formatDate(row.lastCheckedAt) },
			{ key: "lastError", label: "错误" }
		]
	}
};

const resourceConfigs: Record<CRUDPageKey, ResourceConfig> = {
  "forward-rules": {
    key: "forward-rules",
    title: "转发规则",
    eyebrow: "入口端口与上游映射",
    endpoint: "/forward-rules",
    createLabel: "新建规则",
    fields: [
      { key: "name", label: "名称", required: true },
      { key: "userId", label: "用户", type: "number", required: true, min: 1, reference: "users" },
      { key: "tunnelId", label: "转发线路", type: "number", required: true, min: 1, reference: "tunnels" },
      { key: "protocol", label: "传输协议", type: "select", options: protocolOptions, required: true, defaultValue: "tcp" },
      { key: "listenPort", label: "入口端口", type: "number", optional: true, min: 0, max: 65535, placeholder: "留空自动分配" },
      { key: "remoteHost", label: "目标地址", required: true, placeholder: "例如 10.0.0.2" },
      { key: "remotePort", label: "目标端口", type: "number", required: true, min: 1, max: 65535 },
      {
        key: "strategy",
        label: "调度策略",
        type: "select",
		advanced: true,
		defaultValue: "least_conn",
        options: [
          { value: "least_conn", label: "最少连接" },
          { value: "round_robin", label: "轮询" },
          { value: "random", label: "随机" },
          { value: "source_hash", label: "源地址哈希" }
        ]
      },
      {
        key: "status",
        label: "状态",
        type: "select",
        optional: true,
		advanced: true,
		defaultValue: "active",
        options: [
          { value: "active", label: "启用" },
          { value: "paused", label: "暂停" },
          { value: "disabled", label: "禁用" }
        ]
      },
      {
        key: "protocolPolicyId",
        label: "协议策略",
        type: "number",
        optional: true,
        min: 1,
        reference: "protocol-policies",
		advanced: true
      }
    ],
    columns: [
      { key: "id", label: "ID", className: "mono" },
      { key: "name", label: "名称" },
      { key: "protocol", label: "协议", render: (row) => <Badge>{displayValue(row.protocol)}</Badge> },
      { key: "listenPort", label: "监听" },
      { key: "remoteHost", label: "上游" },
      { key: "remotePort", label: "端口" },
      { key: "status", label: "状态", render: (row) => <StatusPill value={text(row.status)} /> },
      { key: "violationCount", label: "违规" },
      { key: "inBytes", label: "入站", render: (row) => formatBytes(row.inBytes) },
      { key: "outBytes", label: "出站", render: (row) => formatBytes(row.outBytes) }
    ]
  },
  nodes: {
    key: "nodes",
    title: "节点",
    eyebrow: "Agent 节点清单",
    endpoint: "/nodes",
    createLabel: "节点通过安装令牌注册",
    disableCreate: true,
    fields: [
      { key: "deviceGroupId", label: "设备组", type: "number", required: true, min: 1, reference: "device-groups" },
      { key: "name", label: "名称", required: true },
      {
        key: "status",
        label: "状态",
        type: "select",
        options: [
          { value: "online", label: "在线" },
          { value: "offline", label: "离线" },
          { value: "disabled", label: "已禁用" },
          { value: "maintenance", label: "维护中" },
          { value: "uninstalling", label: "卸载中" },
          { value: "uninstall_legacy", label: "旧版卸载待确认" },
          { value: "uninstall_timeout", label: "卸载确认超时" },
          { value: "uninstall_failed", label: "卸载失败" }
        ]
      },
      { key: "connectHost", label: "连接地址" }
    ],
    columns: [
      { key: "id", label: "ID", className: "mono" },
      { key: "name", label: "名称" },
      { key: "deviceGroupId", label: "组" },
      { key: "status", label: "状态", render: (row) => <StatusPill value={text(row.status)} /> },
      { key: "publicIp", label: "公网 IP" },
      { key: "connectHost", label: "连接地址" },
      { key: "version", label: "版本" },
	  { key: "capabilities", label: "能力", render: renderNodeCapabilities },
      { key: "sync", label: "同步", render: renderNodeSync },
	  { key: "configStatus", label: "配置结果", render: renderNodeConfig },
      { key: "uninstallAckStatus", label: "卸载确认", render: renderNodeUninstall },
      { key: "systemJson", label: "Agent", render: renderNodeHealth },
      { key: "lastSeenAt", label: "最后心跳", render: (row) => formatDate(row.lastSeenAt) }
    ]
  },
  "device-groups": {
    key: "device-groups",
    title: "节点分组",
    eyebrow: "入口、出口与中继池",
    endpoint: "/device-groups",
    createLabel: "新建节点分组",
    fields: [
      { key: "name", label: "名称", required: true },
      {
        key: "role",
        label: "角色",
        type: "select",
        options: [
          { value: "entry", label: "入口" },
          { value: "exit", label: "出口" },
          { value: "relay", label: "中继" }
        ],
        required: true
      },
      { key: "bindIPs", label: "绑定 IP" },
      { key: "portStart", label: "起始端口", type: "number", min: 0, max: 65535 },
      { key: "portEnd", label: "结束端口", type: "number", min: 0, max: 65535 },
      { key: "trafficRatio", label: "流量倍率", type: "number", min: 0, step: 0.1 },
      {
        key: "protocolPolicyId",
        label: "协议策略",
        type: "number",
        optional: true,
        min: 1,
        reference: "protocol-policies"
      },
      {
        key: "failoverGroupId",
        label: "故障切换组",
        type: "number",
        optional: true,
        min: 1,
        reference: "device-groups"
      },
      { key: "advancedJson", label: "高级 JSON", type: "textarea", rows: 4, fullWidth: true }
    ],
    columns: [
      { key: "id", label: "ID", className: "mono" },
      { key: "name", label: "名称" },
      { key: "role", label: "角色", render: (row) => <Badge>{displayValue(row.role)}</Badge> },
      { key: "bindIPs", label: "绑定 IP" },
      { key: "portStart", label: "起始" },
      { key: "portEnd", label: "结束" },
      { key: "trafficRatio", label: "倍率" },
      { key: "protocolPolicyId", label: "策略" },
      { key: "updatedAt", label: "更新于", render: (row) => formatDate(row.updatedAt) }
    ]
  },
  tunnels: {
    key: "tunnels",
    title: "转发线路",
    eyebrow: "链路路径与计费控制",
    endpoint: "/tunnels",
    createLabel: "新建转发线路",
    fields: [
      { key: "name", label: "名称", required: true },
      {
        key: "mode",
        label: "模式",
        type: "select",
        options: [
          { value: "single", label: "单端" },
          { value: "relay", label: "中继" },
          { value: "failover", label: "故障切换" }
        ]
      },
      { key: "entryGroupId", label: "入口组", type: "number", required: true, min: 1, reference: "device-groups" },
      { key: "exitGroupId", label: "出口组", type: "number", optional: true, min: 1, reference: "device-groups" },
      {
        key: "protocol",
        label: "协议",
        type: "select",
        options: [
          { value: "direct", label: "直连" },
          { value: "tcp", label: "TCP" },
          { value: "tls", label: "TLS" },
          { value: "ws", label: "WebSocket" },
          { value: "wss", label: "WebSocket TLS" },
          { value: "quic", label: "QUIC" }
        ]
      },
      {
        key: "flowAccounting",
        label: "流量计费",
        type: "select",
        options: [
          { value: "single", label: "单侧" },
          { value: "entry", label: "入口侧" },
          { value: "exit", label: "出口侧" },
          { value: "both", label: "双侧" }
        ]
      },
      { key: "entryTrafficRatio", label: "入口倍率", type: "number", min: 0, step: 0.1 },
      { key: "exitTrafficRatio", label: "出口倍率", type: "number", min: 0, step: 0.1 },
      {
        key: "protocolPolicyId",
        label: "协议策略",
        type: "number",
        optional: true,
        min: 1,
        reference: "protocol-policies"
      },
	  { key: "lineCircuitId", label: "物理线路", type: "number", optional: true, min: 1, reference: "line-circuits" },
      { key: "advancedJson", label: "高级 JSON", type: "textarea", rows: 4, fullWidth: true }
    ],
    columns: [
      { key: "id", label: "ID", className: "mono" },
      { key: "name", label: "名称" },
      { key: "mode", label: "模式", render: (row) => <Badge>{displayValue(row.mode)}</Badge> },
      { key: "entryGroupId", label: "入口" },
      { key: "exitGroupId", label: "出口" },
      { key: "protocol", label: "协议", render: (row) => displayValue(row.protocol) },
      { key: "flowAccounting", label: "计费" },
      { key: "protocolPolicyId", label: "策略" },
	  { key: "lineCircuitId", label: "物理线路" },
      { key: "updatedAt", label: "更新于", render: (row) => formatDate(row.updatedAt) }
    ]
  },
  "protocol-policies": {
    key: "protocol-policies",
    title: "协议策略",
    eyebrow: "首包检测与执行动作",
    endpoint: "/protocol-policies",
    createLabel: "新建策略",
    fields: [
      { key: "name", label: "名称", required: true },
      { key: "template", label: "模板", type: "select", options: policyOptions, required: true },
      { key: "purpose", label: "用途", type: "select", options: policyPurposeOptions },
      { key: "inspectionLevel", label: "检测级别", type: "select", options: inspectionOptions },
      {
        key: "mode",
        label: "动作",
        type: "select",
        options: policyActionOptions.filter((item) => item.value !== "allow")
      },
      { key: "blockTls", label: "阻断 TLS", type: "checkbox" },
      { key: "blockQuic", label: "阻断 QUIC", type: "checkbox" },
      { key: "allowPlainTcpOnly", label: "仅允许明文 TCP", type: "checkbox" },
      { key: "allowHttpOnly", label: "仅允许 HTTP", type: "checkbox" },
      { key: "blockProxyLike", label: "阻断代理特征", type: "checkbox" },
      { key: "blockEncryptedTunnel", label: "阻断加密线路", type: "checkbox" },
      { key: "observationMinutes", label: "观察期分钟", type: "number", min: 0 },
      { key: "tlsNoSniAction", label: "TLS 无 SNI", type: "select", options: policyActionOptions, optional: true },
      { key: "quicAction", label: "QUIC 动作", type: "select", options: policyActionOptions, optional: true },
      { key: "sshAction", label: "SSH 动作", type: "select", options: policyActionOptions, optional: true },
      { key: "unknownTcpAction", label: "未知 TCP", type: "select", options: policyActionOptions, optional: true },
      { key: "unknownUdpAction", label: "未知 UDP", type: "select", options: policyActionOptions, optional: true },
      { key: "ndpiLowConfidenceAction", label: "DPI 低置信度", type: "select", options: policyActionOptions, optional: true },
      { key: "dpiTimeoutMs", label: "DPI 超时 ms", type: "number", min: 0 },
      { key: "authorizedProtocols", label: "授权协议", type: "textarea", rows: 3, fullWidth: true, placeholder: "ss, shadowsocks, ss2022" },
      { key: "blockedProtocolGroups", label: "阻断协议组", type: "textarea", rows: 3, fullWidth: true, placeholder: "proxy, p2p, vpn, remote_access" },
      { key: "hostAllowlist", label: "Host 白名单", type: "textarea", rows: 3, fullWidth: true },
      { key: "hostBlocklist", label: "Host 黑名单", type: "textarea", rows: 3, fullWidth: true },
      { key: "sniAllowlist", label: "SNI 白名单", type: "textarea", rows: 3, fullWidth: true },
      { key: "sniBlocklist", label: "SNI 黑名单", type: "textarea", rows: 3, fullWidth: true },
      { key: "alpnAllowlist", label: "ALPN 白名单", type: "textarea", rows: 2, fullWidth: true, placeholder: "h2, http/1.1, h3" },
      { key: "alpnBlocklist", label: "ALPN 黑名单", type: "textarea", rows: 2, fullWidth: true },
      { key: "description", label: "说明", type: "textarea", rows: 5, fullWidth: true }
    ],
    columns: [
      { key: "id", label: "ID", className: "mono" },
      { key: "name", label: "名称" },
      { key: "template", label: "模板", render: (row) => <Badge>{displayValue(row.template)}</Badge> },
      { key: "purpose", label: "用途", render: (row) => <Badge>{displayValue(row.purpose)}</Badge> },
      { key: "inspectionLevel", label: "检测", render: (row) => displayValue(row.inspectionLevel) },
      { key: "mode", label: "动作", render: (row) => <StatusPill value={text(row.mode)} /> },
      { key: "flags", label: "控制项", render: renderPolicyFlags },
      { key: "updatedAt", label: "更新于", render: (row) => formatDate(row.updatedAt) }
    ]
  },
  "speed-limits": {
    key: "speed-limits",
    title: "限速策略",
    eyebrow: "带宽、连接数与 IP 限制",
    endpoint: "/speed-limits",
    createLabel: "新建限速",
	fields: [
	  { key: "name", label: "名称", required: true },
	  { key: "userId", label: "用户", type: "number", optional: true, min: 1, reference: "users" },
      { key: "tunnelId", label: "线路", type: "number", optional: true, min: 1, reference: "tunnels" },
      { key: "ruleId", label: "转发规则", type: "number", optional: true, min: 1, reference: "forward-rules" },
      { key: "uploadBps", label: "上传 Bps", type: "number", min: 0 },
      { key: "downloadBps", label: "下载 Bps", type: "number", min: 0 },
      { key: "maxConns", label: "最大连接数", type: "number", min: 0 },
      { key: "maxIps", label: "最大 IP 数", type: "number", min: 0 }
    ],
	columns: [
	  { key: "id", label: "ID", className: "mono" },
	  { key: "name", label: "名称" },
	  { key: "userId", label: "用户" },
      { key: "tunnelId", label: "线路" },
      { key: "ruleId", label: "规则" },
      { key: "uploadBps", label: "上行", render: (row) => formatBps(row.uploadBps) },
      { key: "downloadBps", label: "下行", render: (row) => formatBps(row.downloadBps) },
      { key: "maxConns", label: "连接" },
      { key: "maxIps", label: "IP" }
    ]
  },
	tenants: {
		key: "tenants",
		title: "租户",
		eyebrow: "组织、周期配额与运营状态",
		endpoint: "/tenants",
		createLabel: "新建租户",
		fields: [
			{ key: "name", label: "名称", required: true },
			{ key: "code", label: "租户代码", required: true, placeholder: "例如 game-team-a" },
			{ key: "status", label: "状态", type: "select", options: [
				{ value: "active", label: "启用" }, { value: "suspended", label: "暂停" }, { value: "disabled", label: "禁用" }
			] },
			{ key: "trafficLimitBytes", label: "周期流量上限 Bytes", type: "number", min: 0 },
			{ key: "forwardLimit", label: "规则数量上限", type: "number", min: 0 },
			{ key: "userLimit", label: "用户数量上限", type: "number", min: 0 },
			{ key: "resetIntervalDays", label: "重置周期（天）", type: "number", min: 0, max: 3660 },
			{ key: "expiresAt", label: "租户到期时间", type: "datetime-local", optional: true },
			{ key: "notes", label: "运营备注", type: "textarea", rows: 4, fullWidth: true }
		],
		columns: [
			{ key: "id", label: "ID", className: "mono" },
			{ key: "name", label: "名称" },
			{ key: "code", label: "代码", className: "mono" },
			{ key: "status", label: "状态", render: (row) => <StatusPill value={text(row.status)} /> },
			{ key: "usedBytes", label: "已用", render: (row) => formatBytes(row.usedBytes) },
			{ key: "trafficLimitBytes", label: "周期上限", render: (row) => formatBytes(row.trafficLimitBytes) },
			{ key: "quotaBlocked", label: "配额", render: (row) => <StatusPill value={row.quotaBlocked ? "quota_exhausted" : "active"} /> },
			{ key: "nextResetAt", label: "下次重置", render: (row) => formatDate(row.nextResetAt) }
		]
	},
	"tenant-tunnel-grants": {
		key: "tenant-tunnel-grants",
		title: "线路授权",
		eyebrow: "可用线路、端口段与规则额度",
		endpoint: "/tenant-tunnel-grants",
		createLabel: "新增授权",
		fields: [
			{ key: "tenantId", label: "租户", type: "number", required: true, min: 1, reference: "tenants" },
			{ key: "tunnelId", label: "线路", type: "number", required: true, min: 1, reference: "tunnels" },
			{ key: "forwardLimit", label: "本线路规则上限", type: "number", min: 0 },
			{ key: "portStart", label: "授权起始端口", type: "number", min: 0, max: 65535 },
			{ key: "portEnd", label: "授权结束端口", type: "number", min: 0, max: 65535 }
		],
		columns: [
			{ key: "id", label: "ID", className: "mono" },
			{ key: "tenantId", label: "租户" },
			{ key: "tunnelId", label: "线路" },
			{ key: "forwardLimit", label: "规则上限" },
			{ key: "portStart", label: "起始端口" },
			{ key: "portEnd", label: "结束端口" },
			{ key: "updatedAt", label: "更新于", render: (row) => formatDate(row.updatedAt) }
		]
	},
  users: {
    key: "users",
    title: "用户",
    eyebrow: "账号、配额与到期时间",
    endpoint: "/users",
	createLabel: "新建用户",
	fields: [
	  { key: "username", label: "用户名", required: true },
	  { key: "displayName", label: "显示名称" },
	  { key: "password", label: "密码", type: "password", requiredOnCreate: true, placeholder: "编辑时留空则不修改" },
      {
        key: "status",
        label: "状态",
        type: "select",
        options: [
          { value: "active", label: "启用" },
          { value: "disabled", label: "禁用" },
          { value: "suspended", label: "暂停" }
        ]
      },
      { key: "flowLimitBytes", label: "流量上限 Bytes", type: "number", min: 0 },
      { key: "forwardLimit", label: "规则数量上限", type: "number", min: 0 },
      { key: "expiresAt", label: "到期时间", type: "datetime-local", optional: true }
    ],
	columns: [
	  { key: "id", label: "ID", className: "mono" },
	  { key: "username", label: "用户名" },
	  { key: "displayName", label: "显示名" },
      { key: "role", label: "角色", render: (row) => <Badge>{displayValue(row.role)}</Badge> },
      { key: "status", label: "状态", render: (row) => <StatusPill value={text(row.status)} /> },
      { key: "usedBytes", label: "已用", render: (row) => formatBytes(row.usedBytes) },
      { key: "flowLimitBytes", label: "上限", render: (row) => formatBytes(row.flowLimitBytes) },
      { key: "forwardLimit", label: "规则数" },
      { key: "expiresAt", label: "到期", render: (row) => formatDate(row.expiresAt) }
    ]
  }
};

export default function App() {
  const [session, setSession] = useState<Session | null>(() => getStoredSession());
  const [activePage, setActivePage] = useState<PageKey>("dashboard");
  const [refreshSeed, setRefreshSeed] = useState(0);
	const [advancedOpen, setAdvancedOpen] = useState(false);
	const [mobileNavOpen, setMobileNavOpen] = useState(false);

  useEffect(() => {
    setUnauthorizedHandler(() => {
      setSession(null);
      setActivePage("dashboard");
    });

    return () => setUnauthorizedHandler(undefined);
  }, []);

	useEffect(() => {
		if (navItems.find((item) => item.key === activePage)?.section === "advanced") {
			setAdvancedOpen(true);
		}
	}, [activePage]);

  const logout = useCallback(() => {
    clearSession();
    setSession(null);
    setActivePage("dashboard");
  }, []);

  if (!session) {
    return <LoginPage onLogin={(nextSession) => setSession(nextSession)} />;
  }
	const visibleNavItems = navItems.filter((item) => !item.roles || item.roles.includes(session.user.role));

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div className="brand">
          <div className="brand-mark">DS</div>
          <div>
            <strong>DuSheng 转发面板</strong>
            <span>节点与规则控制台</span>
          </div>
			<button
				className="icon-button mobile-menu-button"
				type="button"
				title={mobileNavOpen ? "收起菜单" : "展开菜单"}
				aria-label={mobileNavOpen ? "收起菜单" : "展开菜单"}
				aria-expanded={mobileNavOpen}
				onClick={() => setMobileNavOpen((current) => !current)}
			>
				{mobileNavOpen ? <X size={17} /> : <Menu size={17} />}
			</button>
        </div>

		<nav className={`nav-list${mobileNavOpen ? " mobile-open" : ""}`} aria-label="主导航">
			{navSections.map((section) => {
				const items = visibleNavItems.filter((item) => item.section === section.key);
				if (items.length === 0) {
					return null;
				}
				const collapsible = section.key === "advanced";
				return (
					<div className="nav-section" key={section.key}>
						{collapsible ? (
							<button
								type="button"
								className="nav-section-toggle"
								aria-expanded={advancedOpen}
								onClick={() => setAdvancedOpen((current) => !current)}
							>
								<span>{section.label}</span>
								{advancedOpen ? <ChevronDown size={15} /> : <ChevronRight size={15} />}
							</button>
						) : <p className="nav-section-label">{section.label}</p>}
						{!collapsible || advancedOpen ? (
							<div className="nav-section-items">
								{items.map((item) => {
									const Icon = item.icon;
									return (
										<button
											key={item.key}
											className={activePage === item.key ? "nav-item active" : "nav-item"}
											onClick={() => {
												setActivePage(item.key);
												setMobileNavOpen(false);
											}}
										>
											<Icon size={17} />
											<span>{item.label}</span>
										</button>
									);
								})}
							</div>
						) : null}
					</div>
				);
			})}
        </nav>
      </aside>

      <main className="main">
        <header className="topbar">
          <div>
            <p>{visibleNavItems.find((item) => item.key === activePage)?.label}</p>
            <h1>{pageTitle(activePage)}</h1>
          </div>
          <div className="topbar-actions">
			<button className="primary-action topbar-create" type="button" title="新建转发" aria-label="新建转发" onClick={() => setActivePage("forward-rules")}>
				<Plus size={16} />
				<span>新建转发</span>
			</button>
            <button className="icon-button" title="刷新" onClick={() => setRefreshSeed((seed) => seed + 1)}>
              <RefreshCw size={16} />
            </button>
            <div className="user-chip">
              <span>{session.user.displayName || session.user.username}</span>
              <small>{displayValue(session.user.role)}</small>
            </div>
            <button className="icon-button danger" title="退出登录" onClick={logout}>
              <LogOut size={16} />
            </button>
          </div>
        </header>

        <section className="content">{renderPage(activePage, refreshSeed, session.user.role, setActivePage)}</section>
      </main>
    </div>
  );
}

function LoginPage({ onLogin }: { onLogin: (session: Session) => void }) {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function submit(event: FormEvent) {
    event.preventDefault();
    setLoading(true);
    setError(null);

    try {
      const response = await api.post<LoginResponse>("/auth/login", { username, password });
      saveSession(response);
      onLogin(response);
    } catch (err) {
      setError(err instanceof Error ? err.message : "登录失败");
    } finally {
      setLoading(false);
    }
  }

  return (
    <main className="login-page">
      <form className="login-panel" onSubmit={submit}>
        <div className="brand login-brand">
          <div className="brand-mark">DS</div>
          <div>
            <strong>DuSheng 转发面板</strong>
            <span>节点与规则控制台</span>
          </div>
        </div>

        <label>
          用户名
          <input autoFocus value={username} onChange={(event) => setUsername(event.target.value)} required />
        </label>
        <label>
          密码
          <input
            type="password"
            value={password}
            onChange={(event) => setPassword(event.target.value)}
            required
          />
        </label>

        {error ? <div className="notice error">{error}</div> : null}

        <button className="primary-action" type="submit" disabled={loading}>
          <KeyRound size={16} />
          {loading ? "正在登录" : "登录"}
        </button>
      </form>
    </main>
  );
}

function renderPage(activePage: PageKey, refreshSeed: number, role: string, onNavigate: (page: PageKey) => void) {
  if (activePage === "dashboard") {
    return <Dashboard refreshSeed={refreshSeed} onNavigate={onNavigate} />;
  }

	if (activePage === "quick-start") {
		return <QuickStartPage refreshSeed={refreshSeed} role={role} onNavigate={onNavigate} />;
	}

	if (activePage === "tenant-overview") {
		return <TenantOverviewPage refreshSeed={refreshSeed} />;
	}

  if (activePage === "violations") {
    return <ViolationsPage refreshSeed={refreshSeed} />;
  }

  if (activePage === "node-events") {
    return <NodeEventsPage refreshSeed={refreshSeed} />;
  }

	if (activePage === "line-assets") {
		return <LineAssetsPage refreshSeed={refreshSeed} />;
	}

  if (activePage === "audit-logs") {
    return <AuditLogsPage refreshSeed={refreshSeed} />;
  }

	if (activePage === "forward-rules") {
    return (
      <>
		<ResourcePage config={resourceConfigs["forward-rules"]} refreshSeed={refreshSeed} role={role} />
        <ForwardRuleTools role={role} />
      </>
    );
  }

  if (activePage === "nodes") {
    return (
		<div className="stack">
        <InstallTokensPanel refreshSeed={refreshSeed} />
		<ResourcePage config={resourceConfigs.nodes} refreshSeed={refreshSeed} role={role} />
		</div>
    );
  }

	return <ResourcePage config={resourceConfigs[activePage]} refreshSeed={refreshSeed} role={role} />;
}

function LineAssetsPage({ refreshSeed }: { refreshSeed: number }) {
	const tabs: { key: LineAssetKey; label: string }[] = [
		{ key: "line-circuits", label: "物理线路" },
		{ key: "line-probes", label: "线路探测" },
		{ key: "line-endpoints", label: "A/Z 端点" },
		{ key: "line-providers", label: "运营商" },
		{ key: "line-sites", label: "站点" }
	];
	const [activeTab, setActiveTab] = useState<LineAssetKey>("line-circuits");
	return <div className="stack">
		<div className="segmented-control" role="tablist" aria-label="线路资产视图">
			{tabs.map((tab) => <button key={tab.key} type="button" role="tab" aria-selected={activeTab === tab.key} className={activeTab === tab.key ? "active" : ""} onClick={() => setActiveTab(tab.key)}>{tab.label}</button>)}
		</div>
		<ResourcePage config={lineAssetConfigs[activeTab]} refreshSeed={refreshSeed} />
	</div>;
}

function TenantOverviewPage({ refreshSeed }: { refreshSeed: number }) {
	const [payload, setPayload] = useState<TenantTrafficPayload | null>(null);
	const [loading, setLoading] = useState(true);
	const [error, setError] = useState<string | null>(null);

	const load = useCallback(async () => {
		setLoading(true);
		setError(null);
		try {
			setPayload(await api.get<TenantTrafficPayload>("/tenant/traffic?page=1&pageSize=168"));
		} catch (err) {
			setError(err instanceof Error ? err.message : "租户用量请求失败");
		} finally {
			setLoading(false);
		}
	}, []);

	useEffect(() => {
		void load();
	}, [load, refreshSeed]);

	return (
		<div className="stack">
			<section className="section-heading">
				<div><p>当前租户</p><h2>{payload?.tenant.name ?? "租户用量"}</h2></div>
				<button className="ghost-action" onClick={() => void load()} disabled={loading}><RefreshCw size={15} />刷新</button>
			</section>
			{error ? <div className="notice error">{error}</div> : null}
			{loading && !payload ? <StateBlock tone="loading" title="正在加载租户用量" /> : null}
			{payload ? <TenantTrafficView payload={payload} /> : null}
		</div>
	);
}

function TenantTrafficPanel({ tenantId, refreshSeed }: { tenantId: number; refreshSeed: number }) {
	const [payload, setPayload] = useState<TenantTrafficPayload | null>(null);
	const [loading, setLoading] = useState(true);
	const [resetting, setResetting] = useState(false);
	const [error, setError] = useState<string | null>(null);
	const [reloadSeed, setReloadSeed] = useState(0);

	const load = useCallback(async () => {
		setLoading(true);
		setError(null);
		try {
			setPayload(await api.get<TenantTrafficPayload>(`/tenants/${tenantId}/traffic?page=1&pageSize=168`));
		} catch (err) {
			setError(err instanceof Error ? err.message : "租户流量趋势请求失败");
		} finally {
			setLoading(false);
		}
	}, [tenantId]);

	useEffect(() => {
		void load();
	}, [load, refreshSeed, reloadSeed]);

	async function resetTraffic() {
		if (!window.confirm("确认清零该租户当前周期用量并恢复因租户配额停用的规则？")) {
			return;
		}
		setResetting(true);
		setError(null);
		try {
			await api.post(`/tenants/${tenantId}/traffic/reset`, {});
			setReloadSeed((seed) => seed + 1);
		} catch (err) {
			setError(err instanceof Error ? err.message : "重置租户流量失败");
		} finally {
			setResetting(false);
		}
	}

	return (
		<section className="panel tenant-traffic-panel">
			<PanelHeader title="租户流量与周期" icon={Activity} meta={payload ? formatDate(payload.tenant.nextResetAt) : undefined} />
			{error ? <div className="notice error">{error}</div> : null}
			{loading && !payload ? <StateBlock tone="loading" title="正在加载租户流量" /> : null}
			{payload ? <TenantTrafficView payload={payload} /> : null}
			<div className="tenant-traffic-actions">
				<button className="ghost-action danger" type="button" disabled={resetting} onClick={() => void resetTraffic()}>
					<RefreshCw size={15} />{resetting ? "重置中" : "重置周期用量"}
				</button>
			</div>
		</section>
	);
}

function TenantTrafficView({ payload }: { payload: TenantTrafficPayload }) {
	const tenant = payload.tenant;
	const limit = Number(tenant.trafficLimitBytes ?? 0);
	const used = Number(tenant.usedBytes ?? 0);
	const remaining = limit > 0 ? Math.max(0, limit - used) : 0;
	const buckets = payload.buckets.items.slice().reverse();
	const peak = Math.max(1, ...buckets.map((bucket) => Number(bucket.billedBytes ?? 0)));
	return (
		<div className="tenant-traffic-content">
			<div className="metric-grid compact">
				<div className="metric"><span>当前周期已用</span><strong>{formatBytes(used)}</strong></div>
				<div className="metric"><span>周期上限</span><strong>{limit > 0 ? formatBytes(limit) : "不限"}</strong></div>
				<div className="metric"><span>剩余额度</span><strong>{limit > 0 ? formatBytes(remaining) : "不限"}</strong></div>
				<div className="metric"><span>配额状态</span><strong><StatusPill value={tenant.quotaBlocked ? "quota_exhausted" : tenant.status} /></strong></div>
			</div>
			<div className="traffic-bars" aria-label="租户小时流量趋势">
				{buckets.slice(-48).map((bucket) => (
					<div key={bucket.id ?? bucket.bucketStartedAt} className="traffic-bar-column" title={`${formatDate(bucket.bucketStartedAt)} ${formatBytes(bucket.billedBytes)}`}>
						<div className="traffic-bar" style={{ height: `${Math.max(3, Number(bucket.billedBytes ?? 0) / peak * 100)}%` }} />
					</div>
				))}
			</div>
			<DataTable rows={payload.buckets.items.slice(0, 24)} columns={[
				{ key: "bucketStartedAt", label: "小时", render: (row) => formatDate(row.bucketStartedAt) },
				{ key: "inBytes", label: "入站", render: (row) => formatBytes(row.inBytes) },
				{ key: "outBytes", label: "出站", render: (row) => formatBytes(row.outBytes) },
				{ key: "billedBytes", label: "计费流量", render: (row) => formatBytes(row.billedBytes) }
			]} />
		</div>
	);
}

interface QuickStartSnapshot {
	onlineNodes: number;
	tunnels: number;
	users: number;
	grants: number;
	rules: number;
}

function QuickStartPage({
	refreshSeed,
	role,
	onNavigate
}: {
	refreshSeed: number;
	role: string;
	onNavigate: (page: PageKey) => void;
}) {
	const [snapshot, setSnapshot] = useState<QuickStartSnapshot | null>(null);
	const [loading, setLoading] = useState(true);
	const [error, setError] = useState<string | null>(null);

	useEffect(() => {
		let alive = true;
		async function load() {
			setLoading(true);
			setError(null);
			try {
				const rulesPromise = api.page<Entity>("/forward-rules", { pageSize: 1 });
				if (role === "admin") {
					const [nodes, tunnels, users, grants, rules] = await Promise.all([
						api.page<Entity>("/nodes", { pageSize: 200 }),
						api.page<Entity>("/tunnels", { pageSize: 1 }),
						api.page<Entity>("/users", { pageSize: 200 }),
						api.page<UserTunnelGrant>("/user-tunnel-grants", { pageSize: 1 }),
						rulesPromise
					]);
					if (alive) {
						setSnapshot({
							onlineNodes: nodes.items.filter((node) => node.status === "online").length,
							tunnels: tunnels.total,
							users: users.items.filter((user) => user.role === "user").length,
							grants: grants.total,
							rules: rules.total
						});
					}
				} else if (role === "tenant_admin") {
					const [users, rules] = await Promise.all([
						api.page<Entity>("/users", { pageSize: 200 }),
						rulesPromise
					]);
					if (alive) {
						setSnapshot({
							onlineNodes: -1,
							tunnels: -1,
							users: users.items.filter((user) => user.role === "user").length,
							grants: -1,
							rules: rules.total
						});
					}
				} else {
					const rules = await rulesPromise;
					if (alive) {
						setSnapshot({ onlineNodes: -1, tunnels: -1, users: -1, grants: -1, rules: rules.total });
					}
				}
			} catch (err) {
				if (alive) {
					setError(err instanceof Error ? err.message : "开通状态请求失败");
				}
			} finally {
				if (alive) {
					setLoading(false);
				}
			}
		}
		void load();
		return () => {
			alive = false;
		};
	}, [refreshSeed, role]);

	if (loading && !snapshot) {
		return <StateBlock tone="loading" title="正在检查开通状态" />;
	}

	const steps: { title: string; status: string; ready: boolean; target: PageKey; action: string }[] = [];
	if (role === "admin") {
		steps.push(
			{ title: "接入节点", status: snapshot?.onlineNodes ? `${snapshot.onlineNodes} 个在线` : "等待节点上线", ready: Boolean(snapshot?.onlineNodes), target: "nodes", action: "安装节点" },
			{ title: "创建业务用户", status: snapshot?.users ? `${snapshot.users} 个用户` : "尚未创建", ready: Boolean(snapshot?.users), target: "users", action: "创建用户" },
			{
				title: "授权用户线路",
				status: snapshot?.grants ? `${snapshot.grants} 条授权` : snapshot?.tunnels ? "等待授权" : "尚无可授权线路",
				ready: Boolean(snapshot?.grants),
				target: snapshot?.tunnels ? "users" : "tunnels",
				action: snapshot?.tunnels ? "授权线路" : "配置线路"
			}
		);
	} else if (role === "tenant_admin") {
		steps.push({ title: "创建业务用户", status: snapshot?.users ? `${snapshot.users} 个用户` : "尚未创建", ready: Boolean(snapshot?.users), target: "users", action: "创建用户" });
	}
	steps.push({ title: "创建转发规则", status: snapshot?.rules ? `${snapshot.rules} 条已创建` : "等待创建", ready: Boolean(snapshot?.rules), target: "forward-rules", action: "新建转发" });
	const firstPending = steps.findIndex((step) => !step.ready);
	const readyCount = steps.filter((step) => step.ready).length;

	return (
		<div className="stack quick-start-page">
			<section className="quick-start-heading">
				<div><p>业务开通</p><h2>{role === "admin" ? "四步完成第一条转发" : "创建可用转发"}</h2></div>
				<div className="setup-progress"><strong>{readyCount}/{steps.length}</strong><span>已就绪</span></div>
			</section>
			{error ? <div className="notice error">{error}</div> : null}
			<div className="setup-grid">
				{steps.map((step, index) => {
					const current = firstPending === index;
					return (
						<section className={`setup-step${step.ready ? " ready" : current ? " current" : ""}`} key={step.title}>
							<div className="setup-step-index">{step.ready ? <Check size={17} /> : index + 1}</div>
							<div className="setup-step-copy"><strong>{step.title}</strong><span>{step.status}</span></div>
							<button className={current ? "primary-action" : "ghost-action"} type="button" onClick={() => onNavigate(step.target)}>{step.action}<ChevronRight size={15} /></button>
						</section>
					);
				})}
			</div>
			<section className="quick-start-actions">
				<div><span>下一步</span><strong>创建转发规则</strong></div>
				<button className="primary-action" type="button" onClick={() => onNavigate("forward-rules")}><Plus size={16} />新建转发</button>
			</section>
		</div>
	);
}

function Dashboard({ refreshSeed, onNavigate }: { refreshSeed: number; onNavigate: (page: PageKey) => void }) {
  const [payload, setPayload] = useState<DashboardPayload | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let alive = true;

    async function load() {
      setLoading(true);
      setError(null);
      try {
        const data = await api.get<DashboardPayload>("/dashboard");
        if (alive) {
          setPayload(data);
        }
      } catch (err) {
        if (alive) {
          setError(err instanceof Error ? err.message : "总览请求失败");
        }
      } finally {
        if (alive) {
          setLoading(false);
        }
      }
    }

    void load();
    return () => {
      alive = false;
    };
  }, [refreshSeed]);

  if (loading && !payload) {
    return <StateBlock tone="loading" title="正在加载总览" />;
  }

  if (error && !payload) {
    return <StateBlock tone="error" title={error} />;
  }

  const stats = [
    { label: "用户数", value: payload?.users ?? 0 },
    { label: "在线节点", value: `${payload?.onlineNodes ?? 0}/${payload?.nodes ?? 0}` },
    { label: "转发规则", value: payload?.forwardRules ?? 0 },
    { label: "今日流量", value: formatBytes(payload?.todayBytes ?? 0) },
    { label: "24 小时违规", value: payload?.violations24h ?? 0 }
  ];

  return (
    <div className="stack">
      {error ? <div className="notice error">{error}</div> : null}

		<section className="dashboard-command-bar">
			<div><span>常用操作</span><strong>开通与管理转发业务</strong></div>
			<div className="dashboard-command-actions">
				<button className="ghost-action" type="button" onClick={() => onNavigate("quick-start")}><Rocket size={15} />快速开通</button>
				<button className="primary-action" type="button" onClick={() => onNavigate("forward-rules")}><Plus size={15} />新建转发</button>
			</div>
		</section>

      <div className="metric-grid">
        {stats.map((stat) => (
          <div className="metric" key={stat.label}>
            <span>{stat.label}</span>
            <strong>{stat.value}</strong>
          </div>
        ))}
      </div>

      <div className="split-grid">
        <section className="panel">
          <PanelHeader title="最近规则" icon={Route} />
          <DataTable
            rows={payload?.recentRules ?? []}
            columns={[
              { key: "id", label: "ID", className: "mono" },
              { key: "name", label: "名称" },
              { key: "protocol", label: "协议", render: (row) => <Badge>{displayValue(row.protocol)}</Badge> },
              { key: "listenPort", label: "监听" },
              { key: "status", label: "状态", render: (row) => <StatusPill value={text(row.status)} /> },
              { key: "updatedAt", label: "更新于", render: (row) => formatDate(row.updatedAt) }
            ]}
          />
        </section>

        <section className="panel">
          <PanelHeader title="最近违规" icon={AlertTriangle} />
          <DataTable
            rows={payload?.recentViolations ?? []}
            columns={[
              { key: "occurredAt", label: "时间", render: (row) => formatDate(row.occurredAt) },
              { key: "protocol", label: "协议", render: (row) => <Badge>{displayValue(row.protocol)}</Badge> },
              { key: "action", label: "动作", render: (row) => <StatusPill value={text(row.action)} /> },
              { key: "sourceIp", label: "来源" },
              { key: "ruleId", label: "规则" }
            ]}
          />
        </section>
      </div>
    </div>
  );
}

function ResourcePage({ config, refreshSeed, role }: { config: ResourceConfig; refreshSeed: number; role?: string }) {
	const fields = useMemo(() => {
		let visible = config.fields;
		if (config.key === "users" && role === "tenant_admin") {
			visible = visible.filter((field) => field.key !== "tenantId" && field.key !== "role");
		}
		if (config.key === "forward-rules" && role !== "admin") {
			visible = visible.filter((field) => field.key !== "protocolPolicyId");
			if (role === "user") {
				visible = visible.filter((field) => field.key !== "userId");
			}
		}
		return visible;
	}, [config.fields, config.key, role]);
  const [rows, setRows] = useState<Entity[]>([]);
	const [draft, setDraft] = useState<FormDraft>(() => emptyDraft(fields));
  const [editingId, setEditingId] = useState<number | null>(null);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [reloadSeed, setReloadSeed] = useState(0);
  const [query, setQuery] = useState("");
  const [statusFilter, setStatusFilter] = useState("");
  const [page, setPage] = useState(1);
  const [total, setTotal] = useState(0);
  const [references, setReferences] = useState<Record<string, { value: string; label: string }[]>>({});
	const [showAdvanced, setShowAdvanced] = useState(false);
	const hasStatusFilter = fields.some((field) => field.key === "status");
	const standardFields = fields.filter((field) => !field.advanced);
	const advancedFields = fields.filter((field) => field.advanced);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await api.page<Entity>(config.endpoint, {
        page,
        pageSize,
        q: query,
        status: statusFilter || undefined
      });
      setRows(data.items);
      setTotal(data.total);
    } catch (err) {
      setError(err instanceof Error ? err.message : `${config.title}请求失败`);
    } finally {
      setLoading(false);
    }
  }, [config.endpoint, config.title, page, query, statusFilter]);

  useEffect(() => {
	setDraft(emptyDraft(fields));
    setEditingId(null);
    setNotice(null);
    setQuery("");
    setStatusFilter("");
    setPage(1);
	setShowAdvanced(false);
	}, [config.key, fields]);

  useEffect(() => {
    void load();
  }, [load, refreshSeed, reloadSeed]);

  useEffect(() => {
    let alive = true;
	const keys = Array.from(new Set(fields.map((field) => field.reference).filter(Boolean))) as ReferenceKey[];

    async function loadReferences() {
      const next: Record<string, { value: string; label: string }[]> = {};
      await Promise.all(
        keys.map(async (key) => {
          try {
            const page = await api.page<Entity>(referenceEndpoint(key), { pageSize: 200 });
			const candidates = key === "users" ? page.items.filter((row) => row.role === "user") : page.items;
            next[key] = candidates.map((row) => ({
              value: String(row.id ?? ""),
              label: referenceLabel(key, row)
            }));
          } catch {
            next[key] = [];
          }
        })
      );
      if (alive) {
        setReferences(next);
      }
    }

    void loadReferences();
    return () => {
      alive = false;
    };
	}, [fields]);

	const pageCount = Math.max(1, Math.ceil(total / pageSize));
	const currentPage = Math.min(page, pageCount);
	const visibleRows = rows;
	const selectedRow = editingId === null ? undefined : rows.find((row) => row.id === editingId);

  async function submit(event: FormEvent) {
    event.preventDefault();

    if (config.disableCreate && editingId === null) {
      return;
    }

    setSaving(true);
    setError(null);
    setNotice(null);

    try {
	  const payload = payloadFromDraft(fields, draft);
	  let saved: Entity;
	  if (editingId === null) {
		saved = await api.post<Entity>(config.endpoint, payload);
		setNotice(config.key === "users" ? "用户已创建，可继续配置线路授权" : `${config.title}已创建`);
	  } else {
		saved = await api.put<Entity>(`${config.endpoint}/${editingId}`, payload);
		setNotice(`${config.title} #${editingId} 已更新`);
	  }

	  if (config.key === "users" && typeof saved.id === "number") {
		setEditingId(saved.id);
		setDraft(draftFromRow(fields, saved));
		setRows((current) => [saved, ...current.filter((row) => row.id !== saved.id)].slice(0, pageSize));
	  } else {
		resetDraft();
	  }
	  setReloadSeed((seed) => seed + 1);
    } catch (err) {
      setError(err instanceof Error ? err.message : "保存失败");
    } finally {
      setSaving(false);
    }
  }

  async function deleteRow(row: Entity) {
    if (config.disableDelete || typeof row.id !== "number") {
      return;
    }

    const nodeStatus = String(row.status ?? "");
    const forceNodeDelete =
      config.key === "nodes" && ["offline", "uninstalling", "uninstall_legacy", "uninstall_timeout", "uninstall_failed"].includes(nodeStatus);
    const confirmText = forceNodeDelete
      ? `节点 #${row.id} 当前为${displayValue(nodeStatus)}，将强制删除面板记录，不等待 Agent 卸载回执。确认继续？`
      : `确认删除${config.title} #${row.id}？`;

    if (!window.confirm(confirmText)) {
      return;
    }

    setSaving(true);
    setError(null);
    setNotice(null);

    try {
      await api.delete<void>(`${config.endpoint}/${row.id}${forceNodeDelete ? "?force=true" : ""}`);
      setNotice(
        config.key === "nodes"
          ? forceNodeDelete
            ? `节点 #${row.id} 已强制删除`
            : `节点 #${row.id} 卸载指令已下发`
          : `${config.title} #${row.id} 已删除`
      );
      resetDraft();
      setReloadSeed((seed) => seed + 1);
    } catch (err) {
      setError(err instanceof Error ? err.message : "删除失败");
    } finally {
      setSaving(false);
    }
  }

  function editRow(row: Entity) {
    if (typeof row.id !== "number") {
      return;
    }

    setEditingId(row.id);
	setDraft(draftFromRow(fields, row));
    setNotice(null);
  }

  function resetDraft() {
    setEditingId(null);
	setDraft(emptyDraft(fields));
	setShowAdvanced(false);
  }

  return (
    <div className="stack">
      <section className="section-heading">
        <div>
          <p>{config.eyebrow}</p>
          <h2>{config.title}</h2>
        </div>
        <button className="ghost-action" onClick={() => setReloadSeed((seed) => seed + 1)} disabled={loading}>
          <RefreshCw size={15} />
          刷新
        </button>
      </section>

      <section className="table-toolbar">
        <input
          aria-label={`搜索${config.title}`}
          placeholder="搜索记录"
          value={query}
          onChange={(event) => {
            setQuery(event.target.value);
            setPage(1);
          }}
        />
        {hasStatusFilter ? (
          <select
            aria-label="按状态筛选"
            value={statusFilter}
            onChange={(event) => {
              setStatusFilter(event.target.value);
              setPage(1);
            }}
          >
            <option value="">全部状态</option>
			{fields
              .find((field) => field.key === "status")
              ?.options?.map((option) => (
                <option key={option.value} value={option.value}>
                  {option.label}
                </option>
              ))}
          </select>
        ) : null}
        <PaginationControls page={currentPage} pageCount={pageCount} onPage={setPage} />
      </section>

      {error ? <div className="notice error">{error}</div> : null}
      {notice ? <div className="notice success">{notice}</div> : null}
      {config.key === "protocol-policies" ? <PolicyEvaluator policies={rows} /> : null}

      <div className="resource-grid">
        <section className="panel table-panel">
          <PanelHeader title="记录列表" icon={Activity} meta={`${rows.length}/${total} 条`} />
          {loading ? (
            <StateBlock tone="loading" title="正在加载记录" />
          ) : (
            <DataTable
              rows={visibleRows}
              columns={config.columns}
              onRowClick={editRow}
              selectedId={editingId}
              actions={(row) => (
                <div className="row-actions">
                  <button className="icon-button small" title="编辑" onClick={() => editRow(row)}>
                    <Pencil size={14} />
                  </button>
                  {!config.disableDelete ? (
                    <button className="icon-button small danger" title="删除" onClick={() => void deleteRow(row)}>
                      <Trash2 size={14} />
                    </button>
                  ) : null}
                </div>
              )}
            />
          )}
        </section>

        <section className="panel form-panel">
          <PanelHeader
            title={editingId === null ? config.createLabel : `编辑 #${editingId}`}
            icon={editingId === null ? Plus : Pencil}
            meta={config.disableCreate && editingId === null ? "请选择一条记录" : undefined}
          />
          <form className="resource-form" onSubmit={submit}>
			{standardFields.map((field) => (
              <FieldControl
                key={field.key}
                field={field}
                value={draft[field.key]}
                disabled={saving || (Boolean(config.disableCreate) && editingId === null)}
                editing={editingId !== null}
                referenceOptions={references}
                onChange={(value) => setDraft((current) => ({ ...current, [field.key]: value }))}
              />
            ))}
			{advancedFields.length > 0 ? (
				<button className="advanced-fields-toggle" type="button" aria-expanded={showAdvanced} onClick={() => setShowAdvanced((current) => !current)}>
					<Settings2 size={15} />
					<span>{showAdvanced ? "收起高级设置" : "高级设置"}</span>
					{showAdvanced ? <ChevronDown size={15} /> : <ChevronRight size={15} />}
				</button>
			) : null}
			{showAdvanced ? advancedFields.map((field) => (
				<FieldControl
					key={field.key}
					field={field}
					value={draft[field.key]}
					disabled={saving || (Boolean(config.disableCreate) && editingId === null)}
					editing={editingId !== null}
					referenceOptions={references}
					onChange={(value) => setDraft((current) => ({ ...current, [field.key]: value }))}
				/>
			)) : null}

            <div className="form-actions">
              <button
                className="primary-action"
                type="submit"
                disabled={saving || (Boolean(config.disableCreate) && editingId === null)}
              >
                <Save size={15} />
                {saving ? "保存中" : "保存"}
              </button>
              <button className="ghost-action" type="button" onClick={resetDraft} disabled={saving}>
                <X size={15} />
                清空
              </button>
            </div>
          </form>
        </section>
		</div>
		{config.key === "users" && role === "admin" && editingId !== null && selectedRow?.role === "user" ? (
			<UserTunnelGrantPanel
				userId={editingId}
				username={text(selectedRow.username)}
				refreshSeed={reloadSeed + refreshSeed}
			/>
		) : null}
		{config.key === "tenants" && editingId !== null ? <TenantTrafficPanel tenantId={editingId} refreshSeed={reloadSeed + refreshSeed} /> : null}
	  </div>
	);
}

function UserTunnelGrantPanel({ userId, username, refreshSeed }: { userId: number; username: string; refreshSeed: number }) {
	const [rows, setRows] = useState<UserTunnelGrant[]>([]);
	const [tunnels, setTunnels] = useState<Entity[]>([]);
	const [editingId, setEditingId] = useState<number | null>(null);
	const [tunnelId, setTunnelId] = useState("");
	const [forwardLimit, setForwardLimit] = useState("0");
	const [portStart, setPortStart] = useState("0");
	const [portEnd, setPortEnd] = useState("0");
	const [loading, setLoading] = useState(true);
	const [saving, setSaving] = useState(false);
	const [error, setError] = useState<string | null>(null);
	const [notice, setNotice] = useState<string | null>(null);

	const load = useCallback(async () => {
		setLoading(true);
		setError(null);
		try {
			const [grants, tunnelPage] = await Promise.all([
				api.page<UserTunnelGrant>("/user-tunnel-grants", { pageSize: 200, userId }),
				api.page<Entity>("/tunnels", { pageSize: 200 })
			]);
			setRows(grants.items);
			setTunnels(tunnelPage.items);
		} catch (err) {
			setError(err instanceof Error ? err.message : "用户线路授权请求失败");
		} finally {
			setLoading(false);
		}
	}, [userId]);

	useEffect(() => {
		setEditingId(null);
		setTunnelId("");
		setForwardLimit("0");
		setPortStart("0");
		setPortEnd("0");
		setNotice(null);
		void load();
	}, [load, refreshSeed]);

	function resetForm() {
		setEditingId(null);
		setTunnelId("");
		setForwardLimit("0");
		setPortStart("0");
		setPortEnd("0");
	}

	function editGrant(row: UserTunnelGrant) {
		setEditingId(row.id);
		setTunnelId(String(row.tunnelId));
		setForwardLimit(String(row.forwardLimit ?? 0));
		setPortStart(String(row.portStart ?? 0));
		setPortEnd(String(row.portEnd ?? 0));
		setError(null);
		setNotice(null);
	}

	async function submit(event: FormEvent) {
		event.preventDefault();
		setSaving(true);
		setError(null);
		setNotice(null);
		const payload = {
			userId,
			tunnelId: Number(tunnelId),
			forwardLimit: Number(forwardLimit || 0),
			portStart: Number(portStart || 0),
			portEnd: Number(portEnd || 0)
		};
		try {
			if (editingId === null) {
				await api.post<UserTunnelGrant>("/user-tunnel-grants", payload);
				setNotice("线路授权已创建");
			} else {
				await api.put<UserTunnelGrant>(`/user-tunnel-grants/${editingId}`, payload);
				setNotice("线路授权已更新");
			}
			resetForm();
			await load();
		} catch (err) {
			setError(err instanceof Error ? err.message : "线路授权保存失败");
		} finally {
			setSaving(false);
		}
	}

	async function deleteGrant(row: UserTunnelGrant) {
		if (!window.confirm(`确认删除 ${username} 的线路 #${row.tunnelId} 授权？`)) {
			return;
		}
		setSaving(true);
		setError(null);
		setNotice(null);
		try {
			await api.delete<void>(`/user-tunnel-grants/${row.id}`);
			setNotice("线路授权已删除");
			if (editingId === row.id) {
				resetForm();
			}
			await load();
		} catch (err) {
			setError(err instanceof Error ? err.message : "线路授权删除失败");
		} finally {
			setSaving(false);
		}
	}

	const tunnelNames = new Map(tunnels.map((tunnel) => [Number(tunnel.id), referenceLabel("tunnels", tunnel)]));
	const availableTunnels = tunnels.filter((tunnel) => {
		const id = Number(tunnel.id);
		return (editingId !== null && id === Number(tunnelId)) || !rows.some((row) => row.tunnelId === id);
	});

	return (
		<section className="panel user-grant-panel">
			<PanelHeader title={`线路授权 · ${username}`} icon={Route} meta={`${rows.length} 条`} />
			{error ? <div className="notice error grant-notice">{error}</div> : null}
			{notice ? <div className="notice success grant-notice">{notice}</div> : null}
			<div className="user-grant-layout">
				<div className="user-grant-table">
					{loading ? <StateBlock tone="loading" title="正在加载线路授权" /> : (
						<DataTable
							rows={rows}
							selectedId={editingId}
							onRowClick={(row) => editGrant(row as UserTunnelGrant)}
							columns={[
								{ key: "tunnelId", label: "线路", render: (row) => tunnelNames.get(Number(row.tunnelId)) ?? `#${row.tunnelId}` },
								{ key: "forwardLimit", label: "规则上限", render: (row) => Number(row.forwardLimit) > 0 ? row.forwardLimit as number : "不限" },
								{ key: "portStart", label: "端口范围", render: (row) => Number(row.portStart) > 0 ? `${row.portStart}-${row.portEnd}` : "跟随线路" },
								{ key: "updatedAt", label: "更新于", render: (row) => formatDate(row.updatedAt) }
							]}
							actions={(row) => <div className="row-actions">
								<button className="icon-button small" type="button" title="编辑" onClick={() => editGrant(row as UserTunnelGrant)}><Pencil size={14} /></button>
								<button className="icon-button small danger" type="button" title="删除" disabled={saving} onClick={() => void deleteGrant(row as UserTunnelGrant)}><Trash2 size={14} /></button>
							</div>}
						/>
					)}
				</div>
				<form className="resource-form user-grant-form" onSubmit={submit}>
					<label className="field full">
						<span>转发线路</span>
						<select value={tunnelId} required disabled={saving} onChange={(event) => setTunnelId(event.target.value)}>
							<option value="">请选择线路</option>
							{availableTunnels.map((tunnel) => <option key={Number(tunnel.id)} value={Number(tunnel.id)}>{referenceLabel("tunnels", tunnel)}</option>)}
						</select>
					</label>
					<label className="field"><span>本线路规则上限</span><input type="number" min={0} value={forwardLimit} disabled={saving} onChange={(event) => setForwardLimit(event.target.value)} /></label>
					<label className="field"><span>授权起始端口</span><input type="number" min={0} max={65535} value={portStart} disabled={saving} onChange={(event) => setPortStart(event.target.value)} /></label>
					<label className="field"><span>授权结束端口</span><input type="number" min={0} max={65535} value={portEnd} disabled={saving} onChange={(event) => setPortEnd(event.target.value)} /></label>
					<div className="form-actions">
						<button className="primary-action" type="submit" disabled={saving || !tunnelId}><Save size={15} />{saving ? "保存中" : editingId === null ? "授权" : "更新"}</button>
						<button className="ghost-action" type="button" disabled={saving} onClick={resetForm}><X size={15} />清空</button>
					</div>
				</form>
			</div>
		</section>
	);
}

function PolicyEvaluator({ policies }: { policies: Entity[] }) {
  const [policyId, setPolicyId] = useState("");
  const [network, setNetwork] = useState("tcp");
  const [protocol, setProtocol] = useState("unknown");
  const [host, setHost] = useState("");
  const [alpn, setAlpn] = useState("");
  const [ndpiProtocol, setNdpiProtocol] = useState("");
  const [ndpiCategory, setNdpiCategory] = useState("");
  const [confidence, setConfidence] = useState("0");
  const [riskScore, setRiskScore] = useState("0");
  const [result, setResult] = useState<Entity | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  async function submit(event: FormEvent) {
    event.preventDefault();
    if (!policyId) {
      setError("请选择要测试的策略");
      return;
    }
    setLoading(true);
    setError(null);
    setResult(null);
    try {
      const payload = await api.post<Entity>("/protocol-policies/evaluate", {
        policyId: Number(policyId),
        network,
        protocol,
        host,
        alpn: alpn
          .split(/[,\s]+/)
          .map((item) => item.trim())
          .filter(Boolean),
        ndpiProtocol,
        ndpiCategory,
        confidence: Number(confidence || 0),
        riskScore: Number(riskScore || 0)
      });
      setResult(payload);
    } catch (err) {
      setError(err instanceof Error ? err.message : "策略测试失败");
    } finally {
      setLoading(false);
    }
  }

  return (
    <section className="panel">
      <PanelHeader title="策略测试" icon={ShieldCheck} meta="模拟协议命中结果" />
      <form className="inline-form policy-evaluator" onSubmit={submit}>
        <select value={policyId} onChange={(event) => setPolicyId(event.target.value)}>
          <option value="">选择策略</option>
          {policies.map((policy) => (
            <option key={String(policy.id)} value={String(policy.id ?? "")}>
              #{String(policy.id)} {text(policy.name)}
            </option>
          ))}
        </select>
        <select value={network} onChange={(event) => setNetwork(event.target.value)}>
          <option value="tcp">TCP</option>
          <option value="udp">UDP</option>
        </select>
        <select value={protocol} onChange={(event) => setProtocol(event.target.value)}>
          <option value="unknown">unknown</option>
          <option value="tls">TLS</option>
          <option value="quic">QUIC</option>
          <option value="http">HTTP</option>
          <option value="http_connect">HTTP CONNECT</option>
          <option value="socks">SOCKS</option>
          <option value="ssh">SSH</option>
        </select>
        <input placeholder="Host/SNI" value={host} onChange={(event) => setHost(event.target.value)} />
        <input placeholder="ALPN: h2,http/1.1" value={alpn} onChange={(event) => setAlpn(event.target.value)} />
        <input placeholder="nDPI 协议" value={ndpiProtocol} onChange={(event) => setNdpiProtocol(event.target.value)} />
        <input placeholder="nDPI 分类" value={ndpiCategory} onChange={(event) => setNdpiCategory(event.target.value)} />
        <input type="number" min={0} max={100} placeholder="置信度" value={confidence} onChange={(event) => setConfidence(event.target.value)} />
        <input type="number" min={0} max={100} placeholder="风险分" value={riskScore} onChange={(event) => setRiskScore(event.target.value)} />
        <button className="primary-action" type="submit" disabled={loading}>
          <ShieldCheck size={15} />
          测试
        </button>
      </form>
      {error ? <div className="notice error">{error}</div> : null}
      {result ? (
        <div className="policy-result">
          <StatusPill value={text(result.action)} />
          <span>{text(result.reason)}</span>
          {result.matchedRule ? <Badge>{text(result.matchedRule)}</Badge> : null}
        </div>
      ) : null}
    </section>
  );
}

function InstallTokensPanel({ refreshSeed }: { refreshSeed: number }) {
  const [tokens, setTokens] = useState<InstallToken[]>([]);
  const [label, setLabel] = useState("");
  const [deviceGroupId, setDeviceGroupId] = useState("");
  const [ttlHours, setTtlHours] = useState("24");
  const [created, setCreated] = useState<InstallTokenResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [total, setTotal] = useState(0);
	const [groups, setGroups] = useState<{ value: string; label: string }[]>([]);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
		const [data, groupPage] = await Promise.all([
			api.page<InstallToken>("/install-tokens", { pageSize: 50 }),
			api.page<Entity>("/device-groups", { pageSize: 200 })
		]);
      setTokens(data.items);
      setTotal(data.total);
		const options = groupPage.items
			.filter((group) => group.role === "entry")
			.map((group) => ({ value: String(group.id ?? ""), label: referenceLabel("device-groups", group) }));
		setGroups(options);
		setDeviceGroupId((current) => current || options[0]?.value || "");
    } catch (err) {
      setError(err instanceof Error ? err.message : "安装令牌请求失败");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load, refreshSeed]);

  async function submit(event: FormEvent) {
    event.preventDefault();
    setSaving(true);
    setError(null);
    setCreated(null);

    try {
      const response = await api.post<InstallTokenResponse>("/install-tokens", {
        label,
        deviceGroupId: Number(deviceGroupId),
        ttlHours: Number(ttlHours || 24)
      });
      setCreated(response);
      setLabel("");
      setDeviceGroupId("");
      setTtlHours("24");
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : "安装令牌创建失败");
    } finally {
      setSaving(false);
    }
  }

  async function copy(value: string) {
    await navigator.clipboard?.writeText(value);
  }

  async function revokeToken(row: Entity) {
    if (typeof row.id !== "number") {
      return;
    }
    if (!window.confirm(`确认撤销安装令牌 #${row.id}？撤销后该令牌不能再注册节点。`)) {
      return;
    }
    setSaving(true);
    setError(null);
    setCreated(null);
    try {
      await api.delete<void>(`/install-tokens/${row.id}`);
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : "安装令牌撤销失败");
    } finally {
      setSaving(false);
    }
  }

  return (
    <section className="panel">
      <PanelHeader title="安装令牌" icon={KeyRound} meta={`显示 ${tokens.length}/${total} 个`} />
      {error ? <div className="notice error">{error}</div> : null}
      {created ? (
        <div className="token-output">
          <div>
            <span>令牌</span>
            <code>{created.token}</code>
            <button className="ghost-action small-action" onClick={() => void copy(created.token)}>
              复制
            </button>
          </div>
          <div>
            <span>安装命令</span>
            <code>{created.command}</code>
            <button className="ghost-action small-action" onClick={() => void copy(created.command)}>
              复制
            </button>
          </div>
        </div>
      ) : null}

      <div className="install-grid">
        <form className="inline-form" onSubmit={submit}>
          <label>
            标签
            <input value={label} onChange={(event) => setLabel(event.target.value)} />
          </label>
          <label>
            节点分组
            <select
              value={deviceGroupId}
              onChange={(event) => setDeviceGroupId(event.target.value)}
              required
			>
				<option value="">请选择入口分组</option>
				{groups.map((group) => <option key={group.value} value={group.value}>{group.label}</option>)}
			</select>
          </label>
          <label>
            有效期（小时）
            <input
              type="number"
              min={1}
              value={ttlHours}
              onChange={(event) => setTtlHours(event.target.value)}
              required
            />
          </label>
          <button className="primary-action" disabled={saving}>
            <Plus size={15} />
            签发
          </button>
        </form>

        {loading ? (
          <StateBlock tone="loading" title="正在加载令牌" />
        ) : (
          <DataTable
            rows={tokens}
            columns={[
              { key: "id", label: "ID", className: "mono" },
              { key: "label", label: "标签" },
              { key: "deviceGroupId", label: "设备组" },
              { key: "expiresAt", label: "到期", render: (row) => formatDate(row.expiresAt) },
              { key: "usedAt", label: "使用时间", render: (row) => formatDate(row.usedAt) }
            ]}
            actions={(row) => (
              <button
                className="icon-button small danger"
                title="撤销"
                disabled={saving}
                onClick={() => void revokeToken(row)}
              >
                <Trash2 size={14} />
              </button>
            )}
          />
        )}
      </div>
    </section>
  );
}

function ViolationsPage({ refreshSeed }: { refreshSeed: number }) {
  const [rows, setRows] = useState<ProtocolViolation[]>([]);
  const [selected, setSelected] = useState<ProtocolViolation | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [query, setQuery] = useState("");
  const [page, setPage] = useState(1);
  const [total, setTotal] = useState(0);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await api.page<ProtocolViolation>("/protocol-violations", { page, pageSize, q: query });
      setRows(data.items);
      setTotal(data.total);
      setSelected((current) => {
        if (!current) {
          return data.items[0] ?? null;
        }
        return data.items.find((row) => row.id === current.id) ?? data.items[0] ?? null;
      });
    } catch (err) {
      setError(err instanceof Error ? err.message : "协议违规请求失败");
    } finally {
      setLoading(false);
    }
  }, [page, query]);

  useEffect(() => {
    void load();
  }, [load, refreshSeed]);

  const blocked = rows.filter((row) => row.action === "block").length;
  const uniqueProtocols = new Set(rows.map((row) => row.protocol).filter(Boolean)).size;
  const pageCount = Math.max(1, Math.ceil(total / pageSize));
  const currentPage = Math.min(page, pageCount);
  const visibleRows = rows;

  return (
    <div className="stack">
      <section className="section-heading">
        <div>
          <p>协议执行</p>
          <h2>违规事件</h2>
        </div>
        <button className="ghost-action" onClick={() => void load()} disabled={loading}>
          <RefreshCw size={15} />
          刷新
        </button>
      </section>

      {error ? <div className="notice error">{error}</div> : null}

      <section className="table-toolbar">
        <input
          aria-label="搜索协议违规"
          placeholder="搜索违规事件"
          value={query}
          onChange={(event) => {
            setQuery(event.target.value);
            setPage(1);
          }}
        />
        <PaginationControls page={currentPage} pageCount={pageCount} onPage={setPage} />
      </section>

      <div className="metric-grid compact">
        <div className="metric">
          <span>匹配总数</span>
          <strong>{total}</strong>
        </div>
        <div className="metric">
          <span>已阻断</span>
          <strong>{blocked}</strong>
        </div>
        <div className="metric">
          <span>协议数</span>
          <strong>{uniqueProtocols}</strong>
        </div>
      </div>

      <div className="resource-grid">
        <section className="panel table-panel">
          <PanelHeader title="事件列表" icon={AlertTriangle} meta={`${rows.length}/${total} 条`} />
          {loading ? (
            <StateBlock tone="loading" title="正在加载违规事件" />
          ) : (
            <DataTable
              rows={visibleRows}
              selectedId={selected?.id ?? null}
              onRowClick={(row) => setSelected(row as ProtocolViolation)}
              columns={[
                { key: "occurredAt", label: "发生时间", render: (row) => formatDate(row.occurredAt) },
                { key: "action", label: "动作", render: (row) => <StatusPill value={text(row.action)} /> },
                { key: "protocol", label: "协议", render: (row) => <Badge>{displayValue(row.protocol)}</Badge> },
                { key: "sourceIp", label: "来源 IP" },
                { key: "ruleId", label: "规则" },
                { key: "nodeId", label: "节点" },
                { key: "policyId", label: "策略" }
              ]}
            />
          )}
        </section>

        <section className="panel detail-panel">
          <PanelHeader title="事件详情" icon={Activity} />
          {selected ? (
            <dl className="detail-list">
              <div>
                <dt>事件 ID</dt>
                <dd>{selected.id}</dd>
              </div>
              <div>
                <dt>发生时间</dt>
                <dd>{formatDate(selected.occurredAt)}</dd>
              </div>
              <div>
                <dt>动作</dt>
                <dd>
                  <StatusPill value={selected.action} />
                </dd>
              </div>
              <div>
                <dt>协议</dt>
                <dd>{displayValue(selected.protocol)}</dd>
              </div>
              <div>
                <dt>来源 IP</dt>
                <dd>{selected.sourceIp || "-"}</dd>
              </div>
              <div>
                <dt>规则 / 节点 / 策略</dt>
                <dd>
                  {selected.ruleId} / {selected.nodeId} / {selected.policyId}
                </dd>
              </div>
              <div className="full">
                <dt>详情</dt>
                <dd className="prewrap">{selected.detail || "-"}</dd>
              </div>
            </dl>
          ) : (
            <StateBlock tone="empty" title="请选择一条违规事件" />
          )}
        </section>
      </div>
    </div>
  );
}

function NodeEventsPage({ refreshSeed }: { refreshSeed: number }) {
	const [rows, setRows] = useState<AgentEvent[]>([]);
	const [selected, setSelected] = useState<AgentEvent | null>(null);
	const [loading, setLoading] = useState(true);
	const [error, setError] = useState<string | null>(null);
	const [query, setQuery] = useState("");
	const [page, setPage] = useState(1);
	const [total, setTotal] = useState(0);

	const load = useCallback(async () => {
		setLoading(true);
		setError(null);
		try {
			const data = await api.page<AgentEvent>("/node-events", { page, pageSize, q: query });
			setRows(data.items);
			setTotal(data.total);
			setSelected((current) => data.items.find((row) => row.id === current?.id) ?? data.items[0] ?? null);
		} catch (err) {
			setError(err instanceof Error ? err.message : "节点事件请求失败");
		} finally {
			setLoading(false);
		}
	}, [page, query]);

	useEffect(() => {
		void load();
	}, [load, refreshSeed]);

	const pageCount = Math.max(1, Math.ceil(total / pageSize));
	return (
		<div className="stack">
			<section className="section-heading">
				<div><p>Agent 控制面</p><h2>节点事件</h2></div>
				<button className="ghost-action" onClick={() => void load()} disabled={loading}>
					<RefreshCw size={15} />刷新
				</button>
			</section>
			<section className="table-toolbar">
				<input aria-label="搜索节点事件" placeholder="搜索类型、状态或错误" value={query} onChange={(event) => { setQuery(event.target.value); setPage(1); }} />
				<PaginationControls page={Math.min(page, pageCount)} pageCount={pageCount} onPage={setPage} />
			</section>
			{error ? <div className="notice error">{error}</div> : null}
			<div className="resource-grid">
				<section className="panel table-panel">
					<PanelHeader title="事件列表" icon={Activity} meta={`${rows.length}/${total} 条`} />
					{loading ? <StateBlock tone="loading" title="正在加载节点事件" /> : (
						<DataTable rows={rows} selectedId={selected?.id ?? null} onRowClick={(row) => setSelected(row as AgentEvent)} columns={[
							{ key: "occurredAt", label: "时间", render: (row) => formatDate(row.occurredAt) },
							{ key: "nodeId", label: "节点" },
							{ key: "severity", label: "级别", render: (row) => <StatusPill value={text(row.severity)} /> },
							{ key: "type", label: "类型" },
							{ key: "status", label: "状态", render: (row) => <StatusPill value={text(row.status)} /> },
							{ key: "message", label: "消息" }
						]} />
					)}
				</section>
				<section className="panel detail-panel">
					<PanelHeader title="事件详情" icon={ScrollText} />
					{selected ? <dl className="detail-list">
						<div><dt>节点</dt><dd>{selected.nodeId}</dd></div>
						<div><dt>类型</dt><dd>{selected.type}</dd></div>
						<div><dt>状态</dt><dd>{displayValue(selected.status)}</dd></div>
						<div><dt>发生时间</dt><dd>{formatDate(selected.occurredAt)}</dd></div>
						<div className="full"><dt>消息</dt><dd className="prewrap">{selected.message || "-"}</dd></div>
						<div className="full"><dt>运行详情</dt><dd className="prewrap">{prettyJSON(selected.detailJson)}</dd></div>
					</dl> : <StateBlock tone="empty" title="请选择一条节点事件" />}
				</section>
			</div>
		</div>
	);
}

function AuditLogsPage({ refreshSeed }: { refreshSeed: number }) {
  const [rows, setRows] = useState<AuditLog[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [query, setQuery] = useState("");
  const [page, setPage] = useState(1);
  const [total, setTotal] = useState(0);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await api.page<AuditLog>("/audit-logs", { page, pageSize, q: query });
      setRows(data.items);
      setTotal(data.total);
    } catch (err) {
      setError(err instanceof Error ? err.message : "审计日志请求失败");
    } finally {
      setLoading(false);
    }
  }, [page, query]);

  useEffect(() => {
    void load();
  }, [load, refreshSeed]);

  const pageCount = Math.max(1, Math.ceil(total / pageSize));
  const currentPage = Math.min(page, pageCount);
  const visibleRows = rows;

  return (
    <div className="stack">
      <section className="section-heading">
        <div>
          <p>管理活动</p>
          <h2>审计日志</h2>
        </div>
        <button className="ghost-action" onClick={() => void load()} disabled={loading}>
          <RefreshCw size={15} />
          刷新
        </button>
      </section>

      <section className="table-toolbar">
        <input
          aria-label="搜索审计日志"
          placeholder="搜索日志"
          value={query}
          onChange={(event) => {
            setQuery(event.target.value);
            setPage(1);
          }}
        />
        <PaginationControls page={currentPage} pageCount={pageCount} onPage={setPage} />
      </section>

      {error ? <div className="notice error">{error}</div> : null}

      <section className="panel table-panel">
        <PanelHeader title="事件列表" icon={ScrollText} meta={`${rows.length}/${total} 条`} />
        {loading ? (
          <StateBlock tone="loading" title="正在加载审计日志" />
        ) : (
          <DataTable
            rows={visibleRows}
            columns={[
              { key: "createdAt", label: "时间", render: (row) => formatDate(row.createdAt) },
              { key: "actorId", label: "操作者" },
              { key: "action", label: "动作", render: (row) => <Badge>{displayValue(row.action)}</Badge> },
              { key: "resourceType", label: "资源", render: (row) => displayValue(row.resourceType) },
              { key: "resourceId", label: "ID", className: "mono" },
              { key: "metadataJson", label: "元数据" }
            ]}
          />
        )}
      </section>
    </div>
  );
}

function ForwardRuleTools({ role }: { role?: string }) {
  const [notice, setNotice] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function exportRules() {
    setBusy(true);
    setNotice(null);
    setError(null);
    try {
      const rules: ForwardRule[] = [];
      let current = 1;
      for (;;) {
        const page = await api.page<ForwardRule>("/forward-rules", { page: current, pageSize: 200 });
        rules.push(...page.items);
        if (rules.length >= page.total || page.items.length === 0) {
          break;
        }
        current += 1;
      }
      const bundle = {
        schemaVersion: "dusheng.forwarding-rules.v1",
        exportedAt: new Date().toISOString(),
        mode: "export",
        rules
      };
      const blob = new Blob([JSON.stringify(bundle, null, 2)], { type: "application/json" });
      const url = URL.createObjectURL(blob);
      const link = document.createElement("a");
      link.href = url;
      link.download = `dusheng-forward-rules-${new Date().toISOString().slice(0, 10)}.json`;
      link.click();
      URL.revokeObjectURL(url);
      setNotice(`已导出 ${rules.length} 条规则`);
    } catch (err) {
      setError(err instanceof Error ? err.message : "导出失败");
    } finally {
      setBusy(false);
    }
  }

  async function importRules(file: File | null) {
    if (!file) {
      return;
    }
    setBusy(true);
    setNotice(null);
    setError(null);
    try {
      const bundle = JSON.parse(await file.text()) as { rules?: Entity[] };
      const rules = Array.isArray(bundle.rules) ? bundle.rules : [];
      if (rules.length === 0) {
        throw new Error("导入文件中没有找到规则");
      }
		  if (rules.length > 100) {
			throw new Error("单次最多导入 100 条规则，请拆分文件后重试");
		  }
		  const payloads = rules.map((rule) => importRulePayload(rule, role === "admin", role !== "user"));
		  const preview = await api.post<{ items: ForwardRule[]; count: number }>("/forward-rules/batch/preview", { rules: payloads });
		  const ports = preview.items.slice(0, 8).map((rule) => `${rule.name}:${rule.listenPort}`).join("、");
		  if (!window.confirm(`预检通过 ${preview.count} 条规则${ports ? `，端口示例：${ports}` : ""}。确认原子提交？`)) {
			setNotice("已取消导入");
			return;
		  }
		  await api.post("/forward-rules/batch", { rules: payloads });
      setNotice(`已导入 ${rules.length} 条规则`);
    } catch (err) {
      setError(err instanceof Error ? err.message : "导入失败");
    } finally {
      setBusy(false);
    }
  }

  return (
    <section className="panel tool-panel">
      <PanelHeader title="导入 / 导出" icon={Route} />
      {error ? <div className="notice error">{error}</div> : null}
      {notice ? <div className="notice success">{notice}</div> : null}
      <div className="tool-actions">
        <button className="ghost-action" type="button" disabled={busy} onClick={() => void exportRules()}>
          <Download size={15} />
          导出 JSON
        </button>
        <label className="file-action">
          <Upload size={15} />
          导入 JSON
          <input
            type="file"
            accept="application/json,.json"
            disabled={busy}
            onChange={(event) => void importRules(event.target.files?.[0] ?? null)}
          />
        </label>
      </div>
    </section>
  );
}

function PaginationControls({
  page,
  pageCount,
  onPage
}: {
  page: number;
  pageCount: number;
  onPage: (page: number) => void;
}) {
  return (
    <div className="pagination">
      <button className="ghost-action small-action" type="button" disabled={page <= 1} onClick={() => onPage(page - 1)}>
        上一页
      </button>
      <span>
        {page} / {pageCount}
      </span>
      <button
        className="ghost-action small-action"
        type="button"
        disabled={page >= pageCount}
        onClick={() => onPage(page + 1)}
      >
        下一页
      </button>
    </div>
  );
}

function DataTable({
  rows,
  columns,
  onRowClick,
  selectedId,
  actions
}: {
  rows: Entity[];
  columns: ColumnConfig[];
  onRowClick?: (row: Entity) => void;
  selectedId?: number | null;
  actions?: (row: Entity) => ReactNode;
}) {
  if (rows.length === 0) {
    return <StateBlock tone="empty" title="暂无记录" />;
  }

  return (
    <div className="table-wrap">
      <table>
        <thead>
          <tr>
            {columns.map((column) => (
              <th key={column.key}>{column.label}</th>
            ))}
            {actions ? <th className="actions-col">操作</th> : null}
          </tr>
        </thead>
        <tbody>
          {rows.map((row, index) => {
            const rowId = typeof row.id === "number" ? row.id : index;
            return (
              <tr
                key={rowId}
                className={selectedId === row.id ? "selected" : undefined}
                onClick={onRowClick ? () => onRowClick(row) : undefined}
              >
                {columns.map((column) => (
                  <td key={column.key} className={column.className}>
                    {column.render ? column.render(row) : formatCell(row[column.key])}
                  </td>
                ))}
                {actions ? (
                  <td className="actions-col" onClick={(event) => event.stopPropagation()}>
                    {actions(row)}
                  </td>
                ) : null}
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}

function FieldControl({
  field,
  value,
  disabled,
  editing,
  referenceOptions,
  onChange
}: {
  field: FieldConfig;
  value: string | boolean | undefined;
  disabled: boolean;
  editing: boolean;
  referenceOptions?: Record<string, { value: string; label: string }[]>;
  onChange: (value: string | boolean) => void;
}) {
  const id = `field-${field.key}`;
  const required = field.required || (field.requiredOnCreate && !editing);
  const className = field.fullWidth || field.type === "checkbox" ? "field full" : "field";
  const referenced = field.reference ? referenceOptions?.[field.reference] ?? [] : [];

  if (field.type === "checkbox") {
    return (
      <label className={className} htmlFor={id}>
        <span>{field.label}</span>
        <input
          id={id}
          type="checkbox"
          checked={Boolean(value)}
          disabled={disabled}
          onChange={(event) => onChange(event.target.checked)}
        />
      </label>
    );
  }

  if (field.type === "select") {
    return (
      <label className={className} htmlFor={id}>
        <span>{field.label}</span>
        <select
          id={id}
          value={String(value ?? "")}
          required={required}
          disabled={disabled}
          onChange={(event) => onChange(event.target.value)}
        >
          <option value="">未设置</option>
          {field.options?.map((option) => (
            <option key={option.value} value={option.value}>
              {option.label}
            </option>
          ))}
        </select>
      </label>
    );
  }

  if (field.type === "number" && field.reference) {
    return (
      <label className={className} htmlFor={id}>
        <span>{field.label}</span>
        <select
          id={id}
          value={String(value ?? "")}
          required={required}
          disabled={disabled}
          onChange={(event) => onChange(event.target.value)}
        >
          <option value="">{field.optional ? "未设置" : referenced.length > 0 ? "请选择" : `暂无可选${field.label}`}</option>
          {referenced.map((option) => (
            <option key={option.value} value={option.value}>
              {option.label}
            </option>
          ))}
        </select>
      </label>
    );
  }

  if (field.type === "textarea") {
    return (
      <label className={className} htmlFor={id}>
        <span>{field.label}</span>
        <textarea
          id={id}
          rows={field.rows ?? 3}
          value={String(value ?? "")}
          placeholder={field.placeholder}
          required={required}
          disabled={disabled}
          onChange={(event) => onChange(event.target.value)}
        />
      </label>
    );
  }

  return (
    <label className={className} htmlFor={id}>
      <span>{field.label}</span>
      <input
        id={id}
        type={field.type ?? "text"}
        value={String(value ?? "")}
        placeholder={field.placeholder}
        required={required}
        min={field.min}
        max={field.max}
        step={field.step}
        disabled={disabled}
        onChange={(event) => onChange(event.target.value)}
      />
    </label>
  );
}

function PanelHeader({ title, icon: Icon, meta }: { title: string; icon: LucideIcon; meta?: string }) {
  return (
    <div className="panel-header">
      <div>
        <Icon size={16} />
        <h3>{title}</h3>
      </div>
      {meta ? <span>{meta}</span> : null}
    </div>
  );
}

function StateBlock({ title, tone }: { title: string; tone: "loading" | "error" | "empty" }) {
  return <div className={`state-block ${tone}`}>{title}</div>;
}

function Badge({ children }: { children: ReactNode }) {
  return <span className="badge">{children || "-"}</span>;
}

function StatusPill({ value }: { value: string }) {
  const normalized = value.toLowerCase();
  const tone =
    normalized.includes("online") ||
    normalized.includes("active") ||
    normalized.includes("allow") ||
    normalized.includes("在线") ||
    normalized.includes("启用") ||
    normalized.includes("允许") ||
    normalized.includes("已同步") ||
    normalized.includes("运行中") ||
    normalized === "synced" ||
    normalized === "running" ||
    normalized.startsWith("runtime ")
      ? "good"
      : normalized.includes("block") ||
          normalized.includes("violation") ||
          normalized.includes("disabled") ||
          normalized.includes("suspended") ||
          normalized.includes("阻断") ||
          normalized.includes("违规") ||
          normalized.includes("禁用") ||
          normalized.includes("暂停") ||
          normalized.includes("卸载失败")
        ? "bad"
        : normalized.includes("unsynced") ||
            normalized.includes("alert") ||
            normalized.includes("missing") ||
            normalized.includes("not_configured") ||
            normalized.includes("未同步") ||
            normalized.includes("告警") ||
            normalized.includes("缺失") ||
            normalized.includes("未配置") ||
            normalized.includes("卸载中")
          ? "warn"
          : "neutral";

  return <span className={`status-pill ${tone}`}>{displayValue(value)}</span>;
}

function renderPolicyFlags(row: Entity) {
  const flags = [
    ["TLS", row.blockTls],
    ["QUIC", row.blockQuic],
    ["仅明文 TCP", row.allowPlainTcpOnly],
    ["仅 HTTP", row.allowHttpOnly],
    ["代理特征", row.blockProxyLike],
    ["加密线路", row.blockEncryptedTunnel],
    ["DPI", Boolean(row.inspectionLevel && row.inspectionLevel !== "off" && row.inspectionLevel !== "light")],
    ["协议组", Boolean(row.blockedProtocolGroups)],
    ["授权协议", Boolean(row.authorizedProtocols)]
  ].filter(([, enabled]) => Boolean(enabled));

  if (flags.length === 0) {
    return <span className="muted">无</span>;
  }

  return (
    <div className="flag-list">
      {flags.map(([label]) => (
        <Badge key={String(label)}>{String(label)}</Badge>
      ))}
    </div>
  );
}

function renderNodeSync(row: Entity) {
  const applied = Number(row.appliedRevision ?? 0);
  const desired = Number(row.desiredRevision ?? 0);
  const synced = applied >= desired;
  return <StatusPill value={synced ? "synced" : `未同步 ${applied}/${desired}`} />;
}

function renderNodeCapabilities(row: Entity) {
	const values = Array.isArray(row.capabilities) ? row.capabilities.map(String).filter(Boolean) : [];
	if (values.length === 0) {
		return <span className="muted">旧版 Agent</span>;
	}
	const visible = values.slice(0, 3);
	return <div className="flag-list" title={values.join(", ")}>
		{visible.map((value) => <Badge key={value}>{value}</Badge>)}
		{values.length > visible.length ? <Badge>+{values.length - visible.length}</Badge> : null}
	</div>;
}

function renderNodeConfig(row: Entity) {
	const status = text(row.configStatus);
	if (status === "-") {
		return <span className="muted">等待新版 Agent 回执</span>;
	}
	const revision = Number(row.configAckRevision ?? 0);
	const message = text(row.configMessage);
	const label = `${displayValue(status)} r${revision}${message === "-" ? "" : `：${message}`}`;
	return <StatusPill value={label} />;
}

function renderNodeUninstall(row: Entity) {
  const status = text(row.status);
  if (!["uninstalling", "uninstall_legacy", "uninstall_timeout", "uninstall_failed"].includes(status)) {
    return <span className="muted">-</span>;
  }
  const ack = text(row.uninstallAckStatus);
  const message = text(row.uninstallAckMessage);
  const detail = message === "-" ? displayValue(status) : `${displayValue(status)}：${message}`;
  return <StatusPill value={ack === "-" ? detail : `${displayValue(ack)} / ${detail}`} />;
}

function renderNodeHealth(row: Entity) {
  const system = parseSystem(row.systemJson);
  const runtimeStatus = system?.runtime && typeof system.runtime === "object" ? (system.runtime as Record<string, unknown>) : null;
  if (runtimeStatus?.running) {
    const errors =
      runtimeStatus.listenerErrors && typeof runtimeStatus.listenerErrors === "object"
        ? Object.values(runtimeStatus.listenerErrors as Record<string, unknown>).reduce<number>(
            (sum, value) => sum + Number(value ?? 0),
            0
          )
        : 0;
    const applyError = text(runtimeStatus.lastApplyError);
    const parts = [
      `TCP ${runtimeStatus.tcpListeners ?? 0}`,
      `UDP ${runtimeStatus.udpListeners ?? 0}`,
      `连接 ${runtimeStatus.activeConnections ?? 0}`,
      `UDP会话 ${runtimeStatus.activeUDPSessions ?? 0}`
    ];
	const warming = Number(runtimeStatus.warmingListeners ?? 0);
	const draining = Number(runtimeStatus.drainingListeners ?? 0);
	const drainingConnections = Number(runtimeStatus.drainingConnections ?? 0);
	if (warming > 0) {
		parts.push(`预热 ${warming}`);
	}
	if (draining > 0 || drainingConnections > 0) {
		parts.push(`排空 ${draining}/${drainingConnections}`);
	}
    if (errors > 0) {
      parts.push(`错误 ${errors}`);
    }
    if (applyError !== "-") {
      parts.push(`同步异常 ${applyError}`);
    }
    return <StatusPill value={`runtime ${parts.join(" / ")}`} />;
  }
  return <StatusPill value={text(system?.gostStatus ?? (system?.gostActive ? "running" : "unknown"))} />;
}

function pageTitle(activePage: PageKey) {
  if (activePage === "dashboard") {
    return "运营总览";
  }

	if (activePage === "quick-start") {
		return "快速开通转发";
	}

  if (activePage === "violations") {
    return "协议告警";
  }

	if (activePage === "tenant-overview") {
		return "租户流量与配额";
	}

  if (activePage === "node-events") {
    return "节点事件";
  }

	if (activePage === "line-assets") {
		return "线路资产";
	}

  if (activePage === "audit-logs") {
    return "管理审计";
  }

  return resourceConfigs[activePage].eyebrow;
}

function referenceEndpoint(key: ReferenceKey) {
  return `/${key}`;
}

function referenceLabel(key: ReferenceKey, row: Entity) {
  const id = typeof row.id === "number" ? `#${row.id}` : "";
  const primary = key === "users" ? row.username : row.name;
  return [id, text(primary)].filter((part) => part && part !== "-").join(" ");
}

function importRulePayload(row: Entity, includePolicy = true, includeUser = true) {
  const keys = [
    "tunnelId",
    "name",
    "protocol",
    "listenPort",
    "remoteHost",
    "remotePort",
    "strategy"
  ];
	if (includeUser) {
		keys.unshift("userId");
	}
	if (includePolicy) {
		keys.push("protocolPolicyId");
	}
  return keys.reduce<Record<string, unknown>>((payload, key) => {
    if (typeof row[key] !== "undefined") {
      payload[key] = row[key];
    }
    return payload;
  }, {});
}

function emptyDraft(fields: FieldConfig[]): FormDraft {
  return fields.reduce<FormDraft>((draft, field) => {
	if (typeof field.defaultValue !== "undefined") {
	  draft[field.key] = field.defaultValue;
	} else if (field.type === "checkbox") {
      draft[field.key] = false;
    } else if (field.type === "select" && field.options?.[0]) {
      draft[field.key] = field.options[0].value;
    } else {
      draft[field.key] = "";
    }
    return draft;
  }, {});
}

function draftFromRow(fields: FieldConfig[], row: Entity): FormDraft {
  return fields.reduce<FormDraft>((draft, field) => {
    const value = row[field.key];
    if (field.type === "checkbox") {
      draft[field.key] = Boolean(value);
    } else if (field.type === "datetime-local") {
      draft[field.key] = toDateInput(value);
    } else if (typeof value === "undefined" || value === null) {
      draft[field.key] = "";
    } else {
      draft[field.key] = String(value);
    }
    return draft;
  }, {});
}

function payloadFromDraft(fields: FieldConfig[], draft: FormDraft) {
  return fields.reduce<Record<string, unknown>>((payload, field) => {
    const value = draft[field.key];

    if (field.type === "checkbox") {
      payload[field.key] = Boolean(value);
      return payload;
    }

    if (field.type === "number") {
      if (value === "" || typeof value === "undefined") {
        payload[field.key] = field.optional ? null : 0;
      } else {
        payload[field.key] = Number(value);
      }
      return payload;
    }

    if (field.type === "datetime-local") {
      payload[field.key] = value ? new Date(String(value)).toISOString() : null;
      return payload;
    }

    payload[field.key] = value ?? "";
    return payload;
  }, {});
}

function text(value: unknown) {
  if (value === null || typeof value === "undefined" || value === "") {
    return "-";
  }
  return String(value);
}

function displayValue(value: unknown) {
  const raw = text(value);
  if (raw === "-") {
    return raw;
  }

  const normalized = raw.toLowerCase();
  if (normalized.startsWith("runtime ")) {
    return `运行中 ${raw.slice("runtime ".length)}`;
  }
  if (normalized.startsWith("unsynced ")) {
    return `未同步 ${raw.slice("unsynced ".length)}`;
  }

  return valueLabels[normalized] ?? valueLabels[raw] ?? raw;
}

function formatCell(value: unknown) {
  if (typeof value === "boolean") {
    return value ? "是" : "否";
  }

  return displayValue(value);
}

function formatBytes(value: unknown) {
  const bytes = Number(value ?? 0);
  if (!Number.isFinite(bytes) || bytes <= 0) {
    return "0 B";
  }

  const units = ["B", "KB", "MB", "GB", "TB"];
  const index = Math.min(Math.floor(Math.log(bytes) / Math.log(1024)), units.length - 1);
  const scaled = bytes / 1024 ** index;
  return `${scaled.toFixed(scaled >= 10 || index === 0 ? 0 : 1)} ${units[index]}`;
}

function formatBps(value: unknown) {
  const bytes = Number(value ?? 0);
  if (!Number.isFinite(bytes) || bytes <= 0) {
    return "0 B/s";
  }
  return `${formatBytes(bytes)}/s`;
}

function formatLatency(value: unknown) {
	const latency = Number(value);
	if (!Number.isFinite(latency) || latency < 0) {
		return "-";
	}
	return `${latency.toFixed(latency >= 10 ? 1 : 2)} ms`;
}

function formatDate(value: unknown) {
  if (!value) {
    return "-";
  }

  const date = new Date(String(value));
  if (Number.isNaN(date.getTime())) {
    return String(value);
  }

  return new Intl.DateTimeFormat("zh-CN", {
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit"
  }).format(date);
}

function toDateInput(value: unknown) {
  if (!value) {
    return "";
  }

  const date = new Date(String(value));
  if (Number.isNaN(date.getTime())) {
    return "";
  }

  const pad = (part: number) => String(part).padStart(2, "0");
  return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())}T${pad(date.getHours())}:${pad(
    date.getMinutes()
  )}`;
}

function parseSystem(value: unknown): Record<string, unknown> | null {
  if (!value || typeof value !== "string") {
    return null;
  }
  try {
    const parsed = JSON.parse(value) as unknown;
    return parsed && typeof parsed === "object" ? (parsed as Record<string, unknown>) : null;
  } catch {
    return null;
  }
}

function prettyJSON(value: unknown) {
	if (typeof value !== "string" || value.trim() === "") {
		return "-";
	}
	try {
		return JSON.stringify(JSON.parse(value), null, 2);
	} catch {
		return value;
	}
}
