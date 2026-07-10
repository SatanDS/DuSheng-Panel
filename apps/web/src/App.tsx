import { useCallback, useEffect, useMemo, useState } from "react";
import type { FormEvent, ReactNode } from "react";
import {
  Activity,
  AlertTriangle,
  Boxes,
  Download,
  Gauge,
  KeyRound,
  LogOut,
  Network,
  Pencil,
  Plus,
  RefreshCw,
  Route,
  Save,
  ScrollText,
  Server,
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
  Session
} from "./types";

type PageKey =
  | "dashboard"
  | "forward-rules"
  | "nodes"
  | "device-groups"
  | "tunnels"
  | "protocol-policies"
  | "speed-limits"
  | "violations"
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
}

interface ColumnConfig {
  key: string;
  label: string;
  render?: (row: Entity) => ReactNode;
  className?: string;
}

interface ResourceConfig {
  key: Exclude<PageKey, "dashboard" | "violations" | "audit-logs">;
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
type ReferenceKey = "users" | "tunnels" | "protocol-policies" | "device-groups" | "forward-rules";

const pageSize = 25;

const valueLabels: Record<string, string> = {
  active: "启用",
  disabled: "禁用",
  suspended: "暂停",
  online: "在线",
  offline: "离线",
  maintenance: "维护中",
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
  allow: "允许",
  synced: "已同步",
  unsynced: "未同步",
  running: "运行中",
  unknown: "未知",
  missing: "缺失",
  not_configured: "未配置",
  iepl_iplc_no_tls: "IEPL/IPLC 禁止 TLS/QUIC",
  plain_tcp_only: "仅允许明文 TCP",
  http_only: "仅允许 HTTP",
  block_proxy_like: "阻断代理特征",
  custom: "自定义",
  admin: "管理员",
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
  tunnel: "隧道",
  tunnels: "隧道",
  protocol_policy: "协议策略",
  protocol_policies: "协议策略",
  speed_limit: "限速策略",
  speed_limits: "限速策略",
  install_token: "安装令牌",
  install_tokens: "安装令牌"
};

const navItems: { key: PageKey; label: string; icon: LucideIcon }[] = [
  { key: "dashboard", label: "总览", icon: Gauge },
  { key: "forward-rules", label: "转发规则", icon: Route },
  { key: "nodes", label: "节点", icon: Server },
  { key: "device-groups", label: "设备组", icon: Boxes },
  { key: "tunnels", label: "隧道", icon: Network },
  { key: "protocol-policies", label: "协议策略", icon: ShieldCheck },
  { key: "speed-limits", label: "限速策略", icon: SlidersHorizontal },
  { key: "violations", label: "违规事件", icon: AlertTriangle },
  { key: "audit-logs", label: "审计日志", icon: ScrollText },
  { key: "users", label: "用户", icon: Users }
];

const protocolOptions = [
  { value: "tcp", label: "TCP" },
  { value: "udp", label: "UDP" },
  { value: "tcp_udp", label: "TCP + UDP" }
];

const policyOptions = [
  { value: "iepl_iplc_no_tls", label: "IEPL/IPLC 禁止 TLS/QUIC" },
  { value: "plain_tcp_only", label: "仅允许明文 TCP" },
  { value: "http_only", label: "仅允许 HTTP" },
  { value: "block_proxy_like", label: "阻断代理特征" },
  { value: "custom", label: "自定义" }
];

const resourceConfigs: Record<Exclude<PageKey, "dashboard" | "violations" | "audit-logs">, ResourceConfig> = {
  "forward-rules": {
    key: "forward-rules",
    title: "转发规则",
    eyebrow: "入口端口与上游映射",
    endpoint: "/forward-rules",
    createLabel: "新建规则",
    fields: [
      { key: "name", label: "名称", required: true },
      { key: "userId", label: "用户", type: "number", optional: true, min: 1, reference: "users" },
      { key: "tunnelId", label: "隧道", type: "number", required: true, min: 1, reference: "tunnels" },
      { key: "protocol", label: "协议", type: "select", options: protocolOptions, required: true },
      { key: "listenPort", label: "监听端口", type: "number", min: 0, max: 65535 },
      { key: "remoteHost", label: "上游地址", required: true },
      { key: "remotePort", label: "上游端口", type: "number", required: true, min: 1, max: 65535 },
      {
        key: "strategy",
        label: "调度策略",
        type: "select",
        options: [
          { value: "least_conn", label: "最少连接" },
          { value: "round_robin", label: "轮询" },
          { value: "random", label: "随机" },
          { value: "source_hash", label: "源地址哈希" }
        ]
      },
      {
        key: "protocolPolicyId",
        label: "协议策略",
        type: "number",
        optional: true,
        min: 1,
        reference: "protocol-policies"
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
          { value: "maintenance", label: "维护中" }
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
      { key: "sync", label: "同步", render: renderNodeSync },
      { key: "systemJson", label: "Agent", render: renderNodeHealth },
      { key: "lastSeenAt", label: "最后心跳", render: (row) => formatDate(row.lastSeenAt) }
    ]
  },
  "device-groups": {
    key: "device-groups",
    title: "设备组",
    eyebrow: "入口、出口与中继池",
    endpoint: "/device-groups",
    createLabel: "新建设备组",
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
    title: "隧道",
    eyebrow: "链路路径与计费控制",
    endpoint: "/tunnels",
    createLabel: "新建隧道",
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
      {
        key: "mode",
        label: "动作",
        type: "select",
        options: [
          { value: "block", label: "阻断" },
          { value: "alert", label: "告警" },
          { value: "observe", label: "观察" }
        ]
      },
      { key: "blockTls", label: "阻断 TLS", type: "checkbox" },
      { key: "blockQuic", label: "阻断 QUIC", type: "checkbox" },
      { key: "allowPlainTcpOnly", label: "仅允许明文 TCP", type: "checkbox" },
      { key: "allowHttpOnly", label: "仅允许 HTTP", type: "checkbox" },
      { key: "blockProxyLike", label: "阻断代理特征", type: "checkbox" },
      { key: "blockEncryptedTunnel", label: "阻断加密隧道", type: "checkbox" },
      { key: "description", label: "说明", type: "textarea", rows: 5, fullWidth: true }
    ],
    columns: [
      { key: "id", label: "ID", className: "mono" },
      { key: "name", label: "名称" },
      { key: "template", label: "模板", render: (row) => <Badge>{displayValue(row.template)}</Badge> },
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
      { key: "tunnelId", label: "隧道", type: "number", optional: true, min: 1, reference: "tunnels" },
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
      { key: "tunnelId", label: "隧道" },
      { key: "ruleId", label: "规则" },
      { key: "uploadBps", label: "上行", render: (row) => formatBps(row.uploadBps) },
      { key: "downloadBps", label: "下行", render: (row) => formatBps(row.downloadBps) },
      { key: "maxConns", label: "连接" },
      { key: "maxIps", label: "IP" }
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
        key: "role",
        label: "角色",
        type: "select",
        options: [
          { value: "admin", label: "管理员" },
          { value: "user", label: "普通用户" }
        ]
      },
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

  useEffect(() => {
    setUnauthorizedHandler(() => {
      setSession(null);
      setActivePage("dashboard");
    });

    return () => setUnauthorizedHandler(undefined);
  }, []);

  const logout = useCallback(() => {
    clearSession();
    setSession(null);
    setActivePage("dashboard");
  }, []);

  if (!session) {
    return <LoginPage onLogin={(nextSession) => setSession(nextSession)} />;
  }

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div className="brand">
          <div className="brand-mark">DS</div>
          <div>
            <strong>DuSheng 转发面板</strong>
            <span>节点与规则控制台</span>
          </div>
        </div>

        <nav className="nav-list" aria-label="主导航">
          {navItems.map((item) => {
            const Icon = item.icon;
            return (
              <button
                key={item.key}
                className={activePage === item.key ? "nav-item active" : "nav-item"}
                onClick={() => setActivePage(item.key)}
              >
                <Icon size={17} />
                <span>{item.label}</span>
              </button>
            );
          })}
        </nav>
      </aside>

      <main className="main">
        <header className="topbar">
          <div>
            <p>{navItems.find((item) => item.key === activePage)?.label}</p>
            <h1>{pageTitle(activePage)}</h1>
          </div>
          <div className="topbar-actions">
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

        <section className="content">{renderPage(activePage, refreshSeed)}</section>
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

function renderPage(activePage: PageKey, refreshSeed: number) {
  if (activePage === "dashboard") {
    return <Dashboard refreshSeed={refreshSeed} />;
  }

  if (activePage === "violations") {
    return <ViolationsPage refreshSeed={refreshSeed} />;
  }

  if (activePage === "audit-logs") {
    return <AuditLogsPage refreshSeed={refreshSeed} />;
  }

  if (activePage === "forward-rules") {
    return (
      <>
        <ResourcePage config={resourceConfigs["forward-rules"]} refreshSeed={refreshSeed} />
        <ForwardRuleTools />
      </>
    );
  }

  if (activePage === "nodes") {
    return (
      <>
        <ResourcePage config={resourceConfigs.nodes} refreshSeed={refreshSeed} />
        <InstallTokensPanel refreshSeed={refreshSeed} />
      </>
    );
  }

  return <ResourcePage config={resourceConfigs[activePage]} refreshSeed={refreshSeed} />;
}

function Dashboard({ refreshSeed }: { refreshSeed: number }) {
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

function ResourcePage({ config, refreshSeed }: { config: ResourceConfig; refreshSeed: number }) {
  const [rows, setRows] = useState<Entity[]>([]);
  const [draft, setDraft] = useState<FormDraft>(() => emptyDraft(config.fields));
  const [editingId, setEditingId] = useState<number | null>(null);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [reloadSeed, setReloadSeed] = useState(0);
  const [query, setQuery] = useState("");
  const [page, setPage] = useState(1);
  const [references, setReferences] = useState<Record<string, { value: string; label: string }[]>>({});

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await api.get<Entity[]>(config.endpoint);
      setRows(Array.isArray(data) ? data : []);
      setPage(1);
    } catch (err) {
      setError(err instanceof Error ? err.message : `${config.title}请求失败`);
    } finally {
      setLoading(false);
    }
  }, [config.endpoint, config.title]);

  useEffect(() => {
    setDraft(emptyDraft(config.fields));
    setEditingId(null);
    setNotice(null);
    setQuery("");
    setPage(1);
  }, [config.key, config.fields]);

  useEffect(() => {
    void load();
  }, [load, refreshSeed, reloadSeed]);

  useEffect(() => {
    let alive = true;
    const keys = Array.from(new Set(config.fields.map((field) => field.reference).filter(Boolean))) as ReferenceKey[];

    async function loadReferences() {
      const next: Record<string, { value: string; label: string }[]> = {};
      await Promise.all(
        keys.map(async (key) => {
          try {
            const rows = await api.get<Entity[]>(referenceEndpoint(key));
            next[key] = rows.map((row) => ({
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
  }, [config.fields]);

  const filteredRows = useMemo(() => filterRows(rows, query), [rows, query]);
  const pageCount = Math.max(1, Math.ceil(filteredRows.length / pageSize));
  const currentPage = Math.min(page, pageCount);
  const visibleRows = filteredRows.slice((currentPage - 1) * pageSize, currentPage * pageSize);

  async function submit(event: FormEvent) {
    event.preventDefault();

    if (config.disableCreate && editingId === null) {
      return;
    }

    setSaving(true);
    setError(null);
    setNotice(null);

    try {
      const payload = payloadFromDraft(config.fields, draft);
      if (editingId === null) {
        await api.post<Entity>(config.endpoint, payload);
        setNotice(`${config.title}已创建`);
      } else {
        await api.put<Entity>(`${config.endpoint}/${editingId}`, payload);
        setNotice(`${config.title} #${editingId} 已更新`);
      }

      resetDraft();
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

    if (!window.confirm(`确认删除${config.title} #${row.id}？`)) {
      return;
    }

    setSaving(true);
    setError(null);
    setNotice(null);

    try {
      await api.delete<void>(`${config.endpoint}/${row.id}`);
      setNotice(`${config.title} #${row.id} 已删除`);
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
    setDraft(draftFromRow(config.fields, row));
    setNotice(null);
  }

  function resetDraft() {
    setEditingId(null);
    setDraft(emptyDraft(config.fields));
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
        <PaginationControls page={currentPage} pageCount={pageCount} onPage={setPage} />
      </section>

      {error ? <div className="notice error">{error}</div> : null}
      {notice ? <div className="notice success">{notice}</div> : null}

      <div className="resource-grid">
        <section className="panel table-panel">
          <PanelHeader title="记录列表" icon={Activity} meta={`${filteredRows.length}/${rows.length} 条`} />
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
            {config.fields.map((field) => (
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
    </div>
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

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await api.get<InstallToken[]>("/install-tokens");
      setTokens(Array.isArray(data) ? data : []);
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

  return (
    <section className="panel">
      <PanelHeader title="安装令牌" icon={KeyRound} meta={`已签发 ${tokens.length} 个`} />
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
            设备组 ID
            <input
              type="number"
              min={1}
              value={deviceGroupId}
              onChange={(event) => setDeviceGroupId(event.target.value)}
              required
            />
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

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await api.get<ProtocolViolation[]>("/protocol-violations");
      setRows(Array.isArray(data) ? data : []);
      setPage(1);
      setSelected((current) => {
        if (!current) {
          return data[0] ?? null;
        }
        return data.find((row) => row.id === current.id) ?? data[0] ?? null;
      });
    } catch (err) {
      setError(err instanceof Error ? err.message : "协议违规请求失败");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load, refreshSeed]);

  const blocked = rows.filter((row) => row.action === "block").length;
  const uniqueProtocols = new Set(rows.map((row) => row.protocol).filter(Boolean)).size;
  const filteredRows = useMemo(() => filterRows(rows, query), [rows, query]);
  const pageCount = Math.max(1, Math.ceil(filteredRows.length / pageSize));
  const currentPage = Math.min(page, pageCount);
  const visibleRows = filteredRows.slice((currentPage - 1) * pageSize, currentPage * pageSize);

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
          <span>总数</span>
          <strong>{rows.length}</strong>
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
          <PanelHeader title="事件列表" icon={AlertTriangle} meta={`${filteredRows.length}/${rows.length} 条`} />
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

function AuditLogsPage({ refreshSeed }: { refreshSeed: number }) {
  const [rows, setRows] = useState<AuditLog[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [query, setQuery] = useState("");
  const [page, setPage] = useState(1);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await api.get<AuditLog[]>("/audit-logs?limit=1000");
      setRows(Array.isArray(data) ? data : []);
      setPage(1);
    } catch (err) {
      setError(err instanceof Error ? err.message : "审计日志请求失败");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load, refreshSeed]);

  const filteredRows = useMemo(() => filterRows(rows, query), [rows, query]);
  const pageCount = Math.max(1, Math.ceil(filteredRows.length / pageSize));
  const currentPage = Math.min(page, pageCount);
  const visibleRows = filteredRows.slice((currentPage - 1) * pageSize, currentPage * pageSize);

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
        <PanelHeader title="事件列表" icon={ScrollText} meta={`${filteredRows.length}/${rows.length} 条`} />
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

function ForwardRuleTools() {
  const [notice, setNotice] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function exportRules() {
    setBusy(true);
    setNotice(null);
    setError(null);
    try {
      const rules = await api.get<ForwardRule[]>("/forward-rules");
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
      for (const rule of rules) {
        await api.post<Entity>("/forward-rules", importRulePayload(rule));
      }
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

  if (field.type === "number" && field.reference && referenced.length > 0) {
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
          <option value="">{field.optional ? "未设置" : "请选择"}</option>
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
          normalized.includes("暂停")
        ? "bad"
        : normalized.includes("unsynced") ||
            normalized.includes("alert") ||
            normalized.includes("missing") ||
            normalized.includes("not_configured") ||
            normalized.includes("未同步") ||
            normalized.includes("告警") ||
            normalized.includes("缺失") ||
            normalized.includes("未配置")
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
    ["加密隧道", row.blockEncryptedTunnel]
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

function renderNodeHealth(row: Entity) {
  const system = parseSystem(row.systemJson);
  const runtimeStatus = system?.runtime && typeof system.runtime === "object" ? (system.runtime as Record<string, unknown>) : null;
  const status = runtimeStatus?.running
    ? `运行中 ${runtimeStatus.listeners ?? 0}/${runtimeStatus.activeConnections ?? 0}`
    : text(system?.gostStatus ?? (system?.gostActive ? "running" : "unknown"));
  return <StatusPill value={status} />;
}

function pageTitle(activePage: PageKey) {
  if (activePage === "dashboard") {
    return "运营总览";
  }

  if (activePage === "violations") {
    return "协议告警";
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

function filterRows<T extends Entity>(rows: T[], query: string) {
  const needle = query.trim().toLowerCase();
  if (!needle) {
    return rows;
  }
  return rows.filter((row) =>
    Object.values(row).some((value) => {
      if (value === null || typeof value === "undefined") {
        return false;
      }
      return String(value).toLowerCase().includes(needle);
    })
  );
}

function importRulePayload(row: Entity) {
  const keys = [
    "userId",
    "tunnelId",
    "name",
    "protocol",
    "listenPort",
    "remoteHost",
    "remotePort",
    "strategy",
    "protocolPolicyId"
  ];
  return keys.reduce<Record<string, unknown>>((payload, key) => {
    if (typeof row[key] !== "undefined") {
      payload[key] = row[key];
    }
    return payload;
  }, {});
}

function emptyDraft(fields: FieldConfig[]): FormDraft {
  return fields.reduce<FormDraft>((draft, field) => {
    if (field.type === "checkbox") {
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
