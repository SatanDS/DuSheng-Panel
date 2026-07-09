import { useCallback, useEffect, useMemo, useState } from "react";
import type { FormEvent, ReactNode } from "react";
import {
  Activity,
  AlertTriangle,
  Boxes,
  Gauge,
  KeyRound,
  LogOut,
  Network,
  Pencil,
  Plus,
  RefreshCw,
  Route,
  Save,
  Server,
  ShieldCheck,
  Trash2,
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
  Session
} from "./types";

type PageKey =
  | "dashboard"
  | "forward-rules"
  | "nodes"
  | "device-groups"
  | "tunnels"
  | "protocol-policies"
  | "violations"
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
}

interface ColumnConfig {
  key: string;
  label: string;
  render?: (row: Entity) => ReactNode;
  className?: string;
}

interface ResourceConfig {
  key: Exclude<PageKey, "dashboard" | "violations">;
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

const navItems: { key: PageKey; label: string; icon: LucideIcon }[] = [
  { key: "dashboard", label: "Dashboard", icon: Gauge },
  { key: "forward-rules", label: "Forward Rules", icon: Route },
  { key: "nodes", label: "Nodes", icon: Server },
  { key: "device-groups", label: "Device Groups", icon: Boxes },
  { key: "tunnels", label: "Tunnels", icon: Network },
  { key: "protocol-policies", label: "Protocol Policies", icon: ShieldCheck },
  { key: "violations", label: "Violations", icon: AlertTriangle },
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

const resourceConfigs: Record<Exclude<PageKey, "dashboard" | "violations">, ResourceConfig> = {
  "forward-rules": {
    key: "forward-rules",
    title: "Forward Rules",
    eyebrow: "Traffic entry mapping",
    endpoint: "/forward-rules",
    createLabel: "New rule",
    fields: [
      { key: "name", label: "Name", required: true },
      { key: "userId", label: "User ID", type: "number", required: true, min: 1 },
      { key: "tunnelId", label: "Tunnel ID", type: "number", required: true, min: 1 },
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
          { value: "source_hash", label: "Source hash" }
        ]
      },
      { key: "protocolPolicyId", label: "Protocol Policy ID", type: "number", optional: true, min: 1 }
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
      { key: "deviceGroupId", label: "Device Group ID", type: "number", required: true, min: 1 },
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
      { key: "appliedRevision", label: "Applied", className: "mono" },
      { key: "desiredRevision", label: "Desired", className: "mono" },
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
      { key: "protocolPolicyId", label: "Protocol Policy ID", type: "number", optional: true, min: 1 },
      { key: "failoverGroupId", label: "Failover Group ID", type: "number", optional: true, min: 1 },
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
      { key: "entryGroupId", label: "Entry Group ID", type: "number", required: true, min: 1 },
      { key: "exitGroupId", label: "Exit Group ID", type: "number", optional: true, min: 1 },
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
          { value: "double", label: "Double side" }
        ]
      },
      { key: "entryTrafficRatio", label: "Entry Ratio", type: "number", min: 0, step: 0.1 },
      { key: "exitTrafficRatio", label: "Exit Ratio", type: "number", min: 0, step: 0.1 },
      { key: "protocolPolicyId", label: "Protocol Policy ID", type: "number", optional: true, min: 1 },
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
          { value: "allow", label: "Allow" }
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

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await api.get<Entity[]>(config.endpoint);
      setRows(Array.isArray(data) ? data : []);
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
  }, [config.key, config.fields]);

  useEffect(() => {
    void load();
  }, [load, refreshSeed, reloadSeed]);

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

      {error ? <div className="notice error">{error}</div> : null}
      {notice ? <div className="notice success">{notice}</div> : null}

      <div className="resource-grid">
        <section className="panel table-panel">
          <PanelHeader title="Records" icon={Activity} meta={`${rows.length} rows`} />
          {loading ? (
            <StateBlock tone="loading" title="Loading records" />
          ) : (
            <DataTable
              rows={rows}
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

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await api.get<ProtocolViolation[]>("/protocol-violations");
      setRows(Array.isArray(data) ? data : []);
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
          <PanelHeader title="Events" icon={AlertTriangle} meta={`${rows.length} latest`} />
          {loading ? (
            <StateBlock tone="loading" title="Loading violations" />
          ) : (
            <DataTable
              rows={rows}
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
  onChange
}: {
  field: FieldConfig;
  value: string | boolean | undefined;
  disabled: boolean;
  editing: boolean;
  onChange: (value: string | boolean) => void;
}) {
  const id = `field-${field.key}`;
  const required = field.required || (field.requiredOnCreate && !editing);
  const className = field.fullWidth || field.type === "checkbox" ? "field full" : "field";

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
    normalized.includes("online") || normalized.includes("active") || normalized.includes("allow")
      ? "good"
      : normalized.includes("block") ||
          normalized.includes("violation") ||
          normalized.includes("disabled") ||
          normalized.includes("suspended")
        ? "bad"
        : normalized.includes("unsynced") || normalized.includes("alert")
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

function pageTitle(activePage: PageKey) {
  if (activePage === "dashboard") {
    return "Operational Overview";
  }

  if (activePage === "violations") {
    return "Protocol Alerts";
  }

  return resourceConfigs[activePage].eyebrow;
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
