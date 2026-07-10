export type Entity = Record<string, unknown> & {
  id?: number;
  createdAt?: string;
  updatedAt?: string;
};

export interface Page<T> {
  items: T[];
  total: number;
  page: number;
  pageSize: number;
}

export interface User extends Entity {
  id: number;
  username: string;
  displayName: string;
  role: string;
  status: string;
  flowLimitBytes: number;
  usedBytes: number;
  forwardLimit: number;
  expiresAt: string | null;
}

export interface ForwardRule extends Entity {
  id: number;
  userId: number;
  tunnelId: number;
  name: string;
  protocol: string;
  listenPort: number;
  remoteHost: string;
  remotePort: number;
  status: string;
  strategy: string;
  protocolPolicyId: number | null;
  inBytes: number;
  outBytes: number;
  revision: number;
  lastSyncError: string;
  violationCount: number;
}

export interface ProtocolViolation extends Entity {
  id: number;
  ruleId: number;
  nodeId: number;
  policyId: number;
  protocol: string;
  sourceIp: string;
  action: string;
  detail: string;
  occurredAt: string;
}

export interface AuditLog extends Entity {
  id: number;
  actorId: number | null;
  action: string;
  resourceType: string;
  resourceId: string;
  metadataJson: string;
}

export interface DashboardPayload {
  users: number;
  nodes: number;
  onlineNodes: number;
  forwardRules: number;
  todayBytes: number;
  violations24h: number;
  recentViolations: ProtocolViolation[];
  recentRules: ForwardRule[];
}

export interface LoginResponse {
  accessToken: string;
  refreshToken: string;
  user: User;
}

export interface Session {
  accessToken: string;
  refreshToken: string;
  user: User;
}

export interface InstallToken extends Entity {
  id: number;
  label: string;
  deviceGroupId: number;
  expiresAt: string;
  usedAt: string | null;
}

export interface InstallTokenResponse {
  installToken: InstallToken;
  token: string;
  command: string;
}
