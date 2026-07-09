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

const navItems: { key: PageKey; label: string; icon: LucideIcon }[] = [
  { key: "dashboard", label: "Dashboard", icon: Gauge },
  { key: "forward-rules", label: "Forward Rules", icon: Route },
  { key: "nodes", label: "Nodes", icon: Server },
  { key: "device-groups", label: "Device Groups", icon: Boxes },
  { key: "tunnels", label: "Tunnels", icon: Network },
  { key: "protocol-policies", label: "Protocol Policies", icon: ShieldCheck },
  { key: "speed-limits", label: "Speed Limits", icon: SlidersHorizontal },
  { key: "violations", label: "Violations", icon: AlertTriangle },
  { key: "audit-logs", label: "Audit Logs", icon: ScrollText },
  { key: "users", label: "Users", icon: Users }
];

const protocolOptions = [
  { value: "tcp", label: "TCP" },
  { value: "udp", label: "UDP" },
  { value: "tcp_udp", label: "TCP + UDP" }
];

const policyOptions = [
  { value: "iepl_iplc_no_tls", label: "IEPL/IPLC no TLS/QUIC" },
  { value: "plain_tcp_only", label: "Plain TCP only" },
  { value: "http_only", label: "HTTP only" },
  { value: "block_proxy_like", label: "Block proxy-like" },
  { value: "custom", label: "Custom" }
];

const resourceConfigs: Record<Exclude<PageKey, "dashboard" | "violations" | "audit-logs">, ResourceConfig> = {
  "forward-rules": {
    key: "forward-rules",
    title: "Forward Rules",
    eyebrow: "Traffic entry mapping",
    endpoint: "/forward-rules",
    createLabel: "New rule",
    fields: [
      { key: "name", label: "Name", required: true },
      { key: "userId", label: "User", type: "number", optional: true, min: 1, reference: "users" },
      { key: "tunnelId", label: "Tunnel", type: "number", required: true, min: 1, reference: "tunnels" },
      { key: "protocol", label: "Protocol", type: "select", options: protocolOptions, required: true },
      { key: "listenPort", label: "Listen Port", type: "number", min: 0, max: 65535 },
      { key: "remoteHost", label: "Remote Host", required: true },
      { key: "remotePort", label: "Remote Port", type: "number", required: true, min: 1, max: 65535 },
      {
        key: "strategy",
        label: "Strategy",
        type: "select",
        options: [
          { value: "least_conn", label: "Least connections" },
          { value: "round_robin", label: "Round robin" },
          { value: "random", label: "Random" },
          { value: "source_hash", label: "Source hash" }
        ]
      },
      {
        key: "protocolPolicyId",
        label: "Protocol Policy",
        type: "number",
        optional: true,
        min: 1,
        reference: "protocol-policies"
      }
    ],
    columns: [
      { key: "id", label: "ID", className: "mono" },
      { key: "name", label: "Name" },
      { key: "protocol", label: "Protocol", render: (row) => <Badge>{text(row.protocol)}</Badge> },
      { key: "listenPort", label: "Listen" },
      { key: "remoteHost", label: "Remote" },
      { key: "remotePort", label: "Port" },
      { key: "status", label: "Status", render: (row) => <StatusPill value={text(row.status)} /> },
      { key: "violationCount", label: "Violations" },
      { key: "inBytes", label: "In", render: (row) => formatBytes(row.inBytes) },
      { key: "outBytes", label: "Out", render: (row) => formatBytes(row.outBytes) }
    ]
  },
  nodes: {
    key: "nodes",
    title: "Nodes",
    eyebrow: "Agent inventory",
    endpoint: "/nodes",
    createLabel: "Nodes register with install tokens",
    disableCreate: true,
    fields: [
      { key: "deviceGroupId", label: "Device Group", type: "number", required: true, min: 1, reference: "device-groups" },
      { key: "name", label: "Name", required: true },
      {
        key: "status",
        label: "Status",
        type: "select",
        options: [
          { value: "online", label: "Online" },
          { value: "offline", label: "Offline" },
          { value: "disabled", label: "Disabled" },
          { value: "maintenance", label: "Maintenance" }
        ]
      },
      { key: "connectHost", label: "Connect Host" }
    ],
    columns: [
      { key: "id", label: "ID", className: "mono" },
      { key: "name", label: "Name" },
      { key: "deviceGroupId", label: "Group" },
      { key: "status", label: "Status", render: (row) => <StatusPill value={text(row.status)} /> },
      { key: "publicIp", label: "Public IP" },
      { key: "connectHost", label: "Connect Host" },
      { key: "version", label: "Version" },
      { key: "sync", label: "Sync", render: renderNodeSync },
      { key: "systemJson", label: "Agent", render: renderNodeHealth },
      { key: "lastSeenAt", label: "Last Seen", render: (row) => formatDate(row.lastSeenAt) }
    ]
  },
  "device-groups": {
    key: "device-groups",
    title: "Device Groups",
    eyebrow: "Entry and exit pools",
    endpoint: "/device-groups",
    createLabel: "New group",
    fields: [
      { key: "name", label: "Name", required: true },
      {
        key: "role",
        label: "Role",
        type: "select",
        options: [
          { value: "entry", label: "Entry" },
          { value: "exit", label: "Exit" },
          { value: "relay", label: "Relay" }
        ],
        required: true
      },
      { key: "bindIPs", label: "Bind IPs" },
      { key: "portStart", label: "Port Start", type: "number", min: 0, max: 65535 },
      { key: "portEnd", label: "Port End", type: "number", min: 0, max: 65535 },
      { key: "trafficRatio", label: "Traffic Ratio", type: "number", min: 0, step: 0.1 },
      {
        key: "protocolPolicyId",
        label: "Protocol Policy",
        type: "number",
        optional: true,
        min: 1,
        reference: "protocol-policies"
      },
      {
        key: "failoverGroupId",
        label: "Failover Group",
        type: "number",
        optional: true,
        min: 1,
        reference: "device-groups"
      },
      { key: "advancedJson", label: "Advanced JSON", type: "textarea", rows: 4, fullWidth: true }
    ],
    columns: [
      { key: "id", label: "ID", className: "mono" },
      { key: "name", label: "Name" },
      { key: "role", label: "Role", render: (row) => <Badge>{text(row.role)}</Badge> },
      { key: "bindIPs", label: "Bind IPs" },
      { key: "portStart", label: "Start" },
      { key: "portEnd", label: "End" },
      { key: "trafficRatio", label: "Ratio" },
      { key: "protocolPolicyId", label: "Policy" },
      { key: "updatedAt", label: "Updated", render: (row) => formatDate(row.updatedAt) }
    ]
  },
  tunnels: {
    key: "tunnels",
    title: "Tunnels",
    eyebrow: "Path and accounting control",
    endpoint: "/tunnels",
    createLabel: "New tunnel",
    fields: [
      { key: "name", label: "Name", required: true },
      {
        key: "mode",
        label: "Mode",
        type: "select",
        options: [
          { value: "single", label: "Single" },
          { value: "relay", label: "Relay" },
          { value: "failover", label: "Failover" }
        ]
      },
      { key: "entryGroupId", label: "Entry Group", type: "number", required: true, min: 1, reference: "device-groups" },
      { key: "exitGroupId", label: "Exit Group", type: "number", optional: true, min: 1, reference: "device-groups" },
      {
        key: "protocol",
        label: "Protocol",
        type: "select",
        options: [
          { value: "direct", label: "Direct" },
          { value: "tcp", label: "TCP" },
          { value: "tls", label: "TLS" },
          { value: "ws", label: "WebSocket" },
          { value: "wss", label: "WebSocket TLS" },
          { value: "quic", label: "QUIC" }
        ]
      },
      {
        key: "flowAccounting",
        label: "Flow Accounting",
        type: "select",
        options: [
          { value: "single", label: "Single side" },
          { value: "entry", label: "Entry side" },
          { value: "exit", label: "Exit side" },
          { value: "both", label: "Both sides" }
        ]
      },
      { key: "entryTrafficRatio", label: "Entry Ratio", type: "number", min: 0, step: 0.1 },
      { key: "exitTrafficRatio", label: "Exit Ratio", type: "number", min: 0, step: 0.1 },
      {
        key: "protocolPolicyId",
        label: "Protocol Policy",
        type: "number",
        optional: true,
        min: 1,
        reference: "protocol-policies"
      },
      { key: "advancedJson", label: "Advanced JSON", type: "textarea", rows: 4, fullWidth: true }
    ],
    columns: [
      { key: "id", label: "ID", className: "mono" },
      { key: "name", label: "Name" },
      { key: "mode", label: "Mode", render: (row) => <Badge>{text(row.mode)}</Badge> },
      { key: "entryGroupId", label: "Entry" },
      { key: "exitGroupId", label: "Exit" },
      { key: "protocol", label: "Protocol" },
      { key: "flowAccounting", label: "Accounting" },
      { key: "protocolPolicyId", label: "Policy" },
      { key: "updatedAt", label: "Updated", render: (row) => formatDate(row.updatedAt) }
    ]
  },
  "protocol-policies": {
    key: "protocol-policies",
    title: "Protocol Policies",
    eyebrow: "Detection and enforcement",
    endpoint: "/protocol-policies",
    createLabel: "New policy",
    fields: [
      { key: "name", label: "Name", required: true },
      { key: "template", label: "Template", type: "select", options: policyOptions, required: true },
      {
        key: "mode",
        label: "Mode",
        type: "select",
        options: [
          { value: "block", label: "Block" },
          { value: "alert", label: "Alert" },
          { value: "observe", label: "Observe" }
        ]
      },
      { key: "blockTls", label: "Block TLS", type: "checkbox" },
      { key: "blockQuic", label: "Block QUIC", type: "checkbox" },
      { key: "allowPlainTcpOnly", label: "Plain TCP only", type: "checkbox" },
      { key: "allowHttpOnly", label: "HTTP only", type: "checkbox" },
      { key: "blockProxyLike", label: "Block proxy-like", type: "checkbox" },
      { key: "blockEncryptedTunnel", label: "Block encrypted tunnel", type: "checkbox" },
      { key: "description", label: "Description", type: "textarea", rows: 5, fullWidth: true }
    ],
    columns: [
      { key: "id", label: "ID", className: "mono" },
      { key: "name", label: "Name" },
      { key: "template", label: "Template", render: (row) => <Badge>{text(row.template)}</Badge> },
      { key: "mode", label: "Mode", render: (row) => <StatusPill value={text(row.mode)} /> },
      { key: "flags", label: "Controls", render: renderPolicyFlags },
      { key: "updatedAt", label: "Updated", render: (row) => formatDate(row.updatedAt) }
    ]
  },
  "speed-limits": {
    key: "speed-limits",
    title: "Speed Limits",
    eyebrow: "Bandwidth and connection caps",
    endpoint: "/speed-limits",
    createLabel: "New limit",
    fields: [
      { key: "name", label: "Name", required: true },
      { key: "userId", label: "User", type: "number", optional: true, min: 1, reference: "users" },
      { key: "tunnelId", label: "Tunnel", type: "number", optional: true, min: 1, reference: "tunnels" },
      { key: "ruleId", label: "Forward Rule", type: "number", optional: true, min: 1, reference: "forward-rules" },
      { key: "uploadBps", label: "Upload Bps", type: "number", min: 0 },
      { key: "downloadBps", label: "Download Bps", type: "number", min: 0 },
      { key: "maxConns", label: "Max Connections", type: "number", min: 0 },
      { key: "maxIps", label: "Max IPs", type: "number", min: 0 }
    ],
    columns: [
      { key: "id", label: "ID", className: "mono" },
      { key: "name", label: "Name" },
      { key: "userId", label: "User" },
      { key: "tunnelId", label: "Tunnel" },
      { key: "ruleId", label: "Rule" },
      { key: "uploadBps", label: "Up", render: (row) => formatBps(row.uploadBps) },
      { key: "downloadBps", label: "Down", render: (row) => formatBps(row.downloadBps) },
      { key: "maxConns", label: "Conns" },
      { key: "maxIps", label: "IPs" }
    ]
  },
  users: {
    key: "users",
    title: "Users",
    eyebrow: "Accounts and quotas",
    endpoint: "/users",
    createLabel: "New user",
    fields: [
      { key: "username", label: "Username", required: true },
      { key: "displayName", label: "Display Name" },
      { key: "password", label: "Password", type: "password", requiredOnCreate: true, placeholder: "Leave blank on edit" },
      {
        key: "role",
        label: "Role",
        type: "select",
        options: [
          { value: "admin", label: "Admin" },
          { value: "user", label: "User" }
        ]
      },
      {
        key: "status",
        label: "Status",
        type: "select",
        options: [
          { value: "active", label: "Active" },
          { value: "disabled", label: "Disabled" },
          { value: "suspended", label: "Suspended" }
        ]
      },
      { key: "flowLimitBytes", label: "Flow Limit Bytes", type: "number", min: 0 },
      { key: "forwardLimit", label: "Forward Limit", type: "number", min: 0 },
      { key: "expiresAt", label: "Expires At", type: "datetime-local", optional: true }
    ],
    columns: [
      { key: "id", label: "ID", className: "mono" },
      { key: "username", label: "Username" },
      { key: "displayName", label: "Display" },
      { key: "role", label: "Role", render: (row) => <Badge>{text(row.role)}</Badge> },
      { key: "status", label: "Status", render: (row) => <StatusPill value={text(row.status)} /> },
      { key: "usedBytes", label: "Used", render: (row) => formatBytes(row.usedBytes) },
      { key: "flowLimitBytes", label: "Limit", render: (row) => formatBytes(row.flowLimitBytes) },
      { key: "forwardLimit", label: "Rules" },
      { key: "expiresAt", label: "Expires", render: (row) => formatDate(row.expiresAt) }
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
            <strong>DuSheng Panel</strong>
            <span>Operations Console</span>
          </div>
        </div>

        <nav className="nav-list" aria-label="Primary">
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
            <button className="icon-button" title="Refresh" onClick={() => setRefreshSeed((seed) => seed + 1)}>
              <RefreshCw size={16} />
            </button>
            <div className="user-chip">
              <span>{session.user.displayName || session.user.username}</span>
              <small>{session.user.role}</small>
            </div>
            <button className="icon-button danger" title="Logout" onClick={logout}>
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
      setError(err instanceof Error ? err.message : "Login failed");
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
            <strong>DuSheng Panel</strong>
            <span>Operations Console</span>
          </div>
        </div>

        <label>
          Username
          <input autoFocus value={username} onChange={(event) => setUsername(event.target.value)} required />
        </label>
        <label>
          Password
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
          {loading ? "Signing in" : "Sign in"}
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
          setError(err instanceof Error ? err.message : "Dashboard request failed");
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
    return <StateBlock tone="loading" title="Loading dashboard" />;
  }

  if (error && !payload) {
    return <StateBlock tone="error" title={error} />;
  }

  const stats = [
    { label: "Users", value: payload?.users ?? 0 },
    { label: "Nodes Online", value: `${payload?.onlineNodes ?? 0}/${payload?.nodes ?? 0}` },
    { label: "Forward Rules", value: payload?.forwardRules ?? 0 },
    { label: "Traffic Today", value: formatBytes(payload?.todayBytes ?? 0) },
    { label: "Violations 24h", value: payload?.violations24h ?? 0 }
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
          <PanelHeader title="Recent Rules" icon={Route} />
          <DataTable
            rows={payload?.recentRules ?? []}
            columns={[
              { key: "id", label: "ID", className: "mono" },
              { key: "name", label: "Name" },
              { key: "protocol", label: "Protocol", render: (row) => <Badge>{text(row.protocol)}</Badge> },
              { key: "listenPort", label: "Listen" },
              { key: "status", label: "Status", render: (row) => <StatusPill value={text(row.status)} /> },
              { key: "updatedAt", label: "Updated", render: (row) => formatDate(row.updatedAt) }
            ]}
          />
        </section>

        <section className="panel">
          <PanelHeader title="Recent Violations" icon={AlertTriangle} />
          <DataTable
            rows={payload?.recentViolations ?? []}
            columns={[
              { key: "occurredAt", label: "Time", render: (row) => formatDate(row.occurredAt) },
              { key: "protocol", label: "Protocol", render: (row) => <Badge>{text(row.protocol)}</Badge> },
              { key: "action", label: "Action", render: (row) => <StatusPill value={text(row.action)} /> },
              { key: "sourceIp", label: "Source" },
              { key: "ruleId", label: "Rule" }
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
      setError(err instanceof Error ? err.message : `${config.title} request failed`);
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
        setNotice(`${config.title} created`);
      } else {
        await api.put<Entity>(`${config.endpoint}/${editingId}`, payload);
        setNotice(`${config.title} #${editingId} updated`);
      }

      resetDraft();
      setReloadSeed((seed) => seed + 1);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Save failed");
    } finally {
      setSaving(false);
    }
  }

  async function deleteRow(row: Entity) {
    if (config.disableDelete || typeof row.id !== "number") {
      return;
    }

    if (!window.confirm(`Delete ${config.title} #${row.id}?`)) {
      return;
    }

    setSaving(true);
    setError(null);
    setNotice(null);

    try {
      await api.delete<void>(`${config.endpoint}/${row.id}`);
      setNotice(`${config.title} #${row.id} deleted`);
      resetDraft();
      setReloadSeed((seed) => seed + 1);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Delete failed");
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
          Refresh
        </button>
      </section>

      <section className="table-toolbar">
        <input
          aria-label={`Search ${config.title}`}
          placeholder="Search records"
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
          <PanelHeader title="Records" icon={Activity} meta={`${filteredRows.length}/${rows.length} rows`} />
          {loading ? (
            <StateBlock tone="loading" title="Loading records" />
          ) : (
            <DataTable
              rows={visibleRows}
              columns={config.columns}
              onRowClick={editRow}
              selectedId={editingId}
              actions={(row) => (
                <div className="row-actions">
                  <button className="icon-button small" title="Edit" onClick={() => editRow(row)}>
                    <Pencil size={14} />
                  </button>
                  {!config.disableDelete ? (
                    <button className="icon-button small danger" title="Delete" onClick={() => void deleteRow(row)}>
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
            title={editingId === null ? config.createLabel : `Edit #${editingId}`}
            icon={editingId === null ? Plus : Pencil}
            meta={config.disableCreate && editingId === null ? "Select a row" : undefined}
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
                {saving ? "Saving" : "Save"}
              </button>
              <button className="ghost-action" type="button" onClick={resetDraft} disabled={saving}>
                <X size={15} />
                Clear
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
      setError(err instanceof Error ? err.message : "Install token request failed");
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
      setError(err instanceof Error ? err.message : "Install token create failed");
    } finally {
      setSaving(false);
    }
  }

  async function copy(value: string) {
    await navigator.clipboard?.writeText(value);
  }

  return (
    <section className="panel">
      <PanelHeader title="Install Tokens" icon={KeyRound} meta={`${tokens.length} issued`} />
      {error ? <div className="notice error">{error}</div> : null}
      {created ? (
        <div className="token-output">
          <div>
            <span>Token</span>
            <code>{created.token}</code>
            <button className="ghost-action small-action" onClick={() => void copy(created.token)}>
              Copy
            </button>
          </div>
          <div>
            <span>Command</span>
            <code>{created.command}</code>
            <button className="ghost-action small-action" onClick={() => void copy(created.command)}>
              Copy
            </button>
          </div>
        </div>
      ) : null}

      <div className="install-grid">
        <form className="inline-form" onSubmit={submit}>
          <label>
            Label
            <input value={label} onChange={(event) => setLabel(event.target.value)} />
          </label>
          <label>
            Device Group ID
            <input
              type="number"
              min={1}
              value={deviceGroupId}
              onChange={(event) => setDeviceGroupId(event.target.value)}
              required
            />
          </label>
          <label>
            TTL Hours
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
            Issue
          </button>
        </form>

        {loading ? (
          <StateBlock tone="loading" title="Loading tokens" />
        ) : (
          <DataTable
            rows={tokens}
            columns={[
              { key: "id", label: "ID", className: "mono" },
              { key: "label", label: "Label" },
              { key: "deviceGroupId", label: "Group" },
              { key: "expiresAt", label: "Expires", render: (row) => formatDate(row.expiresAt) },
              { key: "usedAt", label: "Used", render: (row) => formatDate(row.usedAt) }
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
      setError(err instanceof Error ? err.message : "Protocol violations request failed");
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
          <p>Protocol enforcement</p>
          <h2>Violations</h2>
        </div>
        <button className="ghost-action" onClick={() => void load()} disabled={loading}>
          <RefreshCw size={15} />
          Refresh
        </button>
      </section>

      {error ? <div className="notice error">{error}</div> : null}

      <section className="table-toolbar">
        <input
          aria-label="Search protocol violations"
          placeholder="Search violations"
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
          <span>Total</span>
          <strong>{rows.length}</strong>
        </div>
        <div className="metric">
          <span>Blocked</span>
          <strong>{blocked}</strong>
        </div>
        <div className="metric">
          <span>Protocols</span>
          <strong>{uniqueProtocols}</strong>
        </div>
      </div>

      <div className="resource-grid">
        <section className="panel table-panel">
          <PanelHeader title="Events" icon={AlertTriangle} meta={`${filteredRows.length}/${rows.length} latest`} />
          {loading ? (
            <StateBlock tone="loading" title="Loading violations" />
          ) : (
            <DataTable
              rows={visibleRows}
              selectedId={selected?.id ?? null}
              onRowClick={(row) => setSelected(row as ProtocolViolation)}
              columns={[
                { key: "occurredAt", label: "Occurred", render: (row) => formatDate(row.occurredAt) },
                { key: "action", label: "Action", render: (row) => <StatusPill value={text(row.action)} /> },
                { key: "protocol", label: "Protocol", render: (row) => <Badge>{text(row.protocol)}</Badge> },
                { key: "sourceIp", label: "Source IP" },
                { key: "ruleId", label: "Rule" },
                { key: "nodeId", label: "Node" },
                { key: "policyId", label: "Policy" }
              ]}
            />
          )}
        </section>

        <section className="panel detail-panel">
          <PanelHeader title="Event Detail" icon={Activity} />
          {selected ? (
            <dl className="detail-list">
              <div>
                <dt>Event ID</dt>
                <dd>{selected.id}</dd>
              </div>
              <div>
                <dt>Occurred</dt>
                <dd>{formatDate(selected.occurredAt)}</dd>
              </div>
              <div>
                <dt>Action</dt>
                <dd>
                  <StatusPill value={selected.action} />
                </dd>
              </div>
              <div>
                <dt>Protocol</dt>
                <dd>{selected.protocol || "-"}</dd>
              </div>
              <div>
                <dt>Source IP</dt>
                <dd>{selected.sourceIp || "-"}</dd>
              </div>
              <div>
                <dt>Rule / Node / Policy</dt>
                <dd>
                  {selected.ruleId} / {selected.nodeId} / {selected.policyId}
                </dd>
              </div>
              <div className="full">
                <dt>Detail</dt>
                <dd className="prewrap">{selected.detail || "-"}</dd>
              </div>
            </dl>
          ) : (
            <StateBlock tone="empty" title="No violation selected" />
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
      setError(err instanceof Error ? err.message : "Audit log request failed");
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
          <p>Administrative activity</p>
          <h2>Audit Logs</h2>
        </div>
        <button className="ghost-action" onClick={() => void load()} disabled={loading}>
          <RefreshCw size={15} />
          Refresh
        </button>
      </section>

      <section className="table-toolbar">
        <input
          aria-label="Search audit logs"
          placeholder="Search logs"
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
        <PanelHeader title="Events" icon={ScrollText} meta={`${filteredRows.length}/${rows.length} rows`} />
        {loading ? (
          <StateBlock tone="loading" title="Loading audit logs" />
        ) : (
          <DataTable
            rows={visibleRows}
            columns={[
              { key: "createdAt", label: "Time", render: (row) => formatDate(row.createdAt) },
              { key: "actorId", label: "Actor" },
              { key: "action", label: "Action", render: (row) => <Badge>{text(row.action)}</Badge> },
              { key: "resourceType", label: "Resource" },
              { key: "resourceId", label: "ID", className: "mono" },
              { key: "metadataJson", label: "Metadata" }
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
      setNotice(`Exported ${rules.length} rules`);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Export failed");
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
        throw new Error("No rules found in import bundle");
      }
      for (const rule of rules) {
        await api.post<Entity>("/forward-rules", importRulePayload(rule));
      }
      setNotice(`Imported ${rules.length} rules`);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Import failed");
    } finally {
      setBusy(false);
    }
  }

  return (
    <section className="panel tool-panel">
      <PanelHeader title="Import / Export" icon={Route} />
      {error ? <div className="notice error">{error}</div> : null}
      {notice ? <div className="notice success">{notice}</div> : null}
      <div className="tool-actions">
        <button className="ghost-action" type="button" disabled={busy} onClick={() => void exportRules()}>
          <Download size={15} />
          Export JSON
        </button>
        <label className="file-action">
          <Upload size={15} />
          Import JSON
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
        Prev
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
        Next
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
    return <StateBlock tone="empty" title="No records" />;
  }

  return (
    <div className="table-wrap">
      <table>
        <thead>
          <tr>
            {columns.map((column) => (
              <th key={column.key}>{column.label}</th>
            ))}
            {actions ? <th className="actions-col">Actions</th> : null}
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
          <option value="">Unset</option>
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
          <option value="">{field.optional ? "Unset" : "Select"}</option>
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
    normalized === "synced" ||
    normalized === "running"
      ? "good"
      : normalized.includes("block") ||
          normalized.includes("violation") ||
          normalized.includes("disabled") ||
          normalized.includes("suspended")
        ? "bad"
        : normalized.includes("unsynced") ||
            normalized.includes("alert") ||
            normalized.includes("missing") ||
            normalized.includes("not_configured")
          ? "warn"
          : "neutral";

  return <span className={`status-pill ${tone}`}>{value || "-"}</span>;
}

function renderPolicyFlags(row: Entity) {
  const flags = [
    ["TLS", row.blockTls],
    ["QUIC", row.blockQuic],
    ["Plain TCP", row.allowPlainTcpOnly],
    ["HTTP", row.allowHttpOnly],
    ["Proxy-like", row.blockProxyLike],
    ["Encrypted tunnel", row.blockEncryptedTunnel]
  ].filter(([, enabled]) => Boolean(enabled));

  if (flags.length === 0) {
    return <span className="muted">None</span>;
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
  return <StatusPill value={synced ? "synced" : `unsynced ${applied}/${desired}`} />;
}

function renderNodeHealth(row: Entity) {
  const system = parseSystem(row.systemJson);
  const status = text(system?.gostStatus ?? (system?.gostActive ? "running" : "unknown"));
  return <StatusPill value={status} />;
}

function pageTitle(activePage: PageKey) {
  if (activePage === "dashboard") {
    return "Operational Overview";
  }

  if (activePage === "violations") {
    return "Protocol Alerts";
  }

  if (activePage === "audit-logs") {
    return "Administrative Activity";
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

function formatCell(value: unknown) {
  if (typeof value === "boolean") {
    return value ? "Yes" : "No";
  }

  return text(value);
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

  return new Intl.DateTimeFormat(undefined, {
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
