import type { LoginResponse, Page, Session } from "./types";

const ACCESS_TOKEN_KEY = "dusheng.accessToken";
const REFRESH_TOKEN_KEY = "dusheng.refreshToken";
const USER_KEY = "dusheng.user";
const API_PREFIX = "/api/v1";

let onUnauthorized: (() => void) | undefined;

export class ApiError extends Error {
  status: number;
  payload: unknown;

  constructor(message: string, status: number, payload: unknown) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.payload = payload;
  }
}

export function setUnauthorizedHandler(handler: (() => void) | undefined) {
  onUnauthorized = handler;
}

export function getStoredSession(): Session | null {
  const accessToken = localStorage.getItem(ACCESS_TOKEN_KEY);
  const refreshToken = localStorage.getItem(REFRESH_TOKEN_KEY);
  const storedUser = localStorage.getItem(USER_KEY);

  if (!accessToken || !refreshToken || !storedUser) {
    return null;
  }

  try {
    return {
      accessToken,
      refreshToken,
      user: JSON.parse(storedUser) as Session["user"]
    };
  } catch {
    clearSession();
    return null;
  }
}

export function saveSession(response: LoginResponse) {
  localStorage.setItem(ACCESS_TOKEN_KEY, response.accessToken);
  localStorage.setItem(REFRESH_TOKEN_KEY, response.refreshToken);
  localStorage.setItem(USER_KEY, JSON.stringify(response.user));
}

function saveAccessToken(accessToken: string) {
  localStorage.setItem(ACCESS_TOKEN_KEY, accessToken);
}

export function clearSession() {
  localStorage.removeItem(ACCESS_TOKEN_KEY);
  localStorage.removeItem(REFRESH_TOKEN_KEY);
  localStorage.removeItem(USER_KEY);
}

function buildUrl(path: string) {
  const apiBase = (import.meta.env.VITE_API_BASE_URL ?? "").replace(/\/$/, "");
  const normalizedPath = path.startsWith("/") ? path : `/${path}`;
  return `${apiBase}${API_PREFIX}${normalizedPath}`;
}

function errorMessage(payload: unknown, fallback: string) {
  if (payload && typeof payload === "object" && "error" in payload) {
    const value = (payload as { error?: unknown }).error;
    if (typeof value === "string" && value.trim()) {
      return value;
    }
  }

  if (typeof payload === "string" && payload.trim()) {
    return payload;
  }

  return fallback;
}

async function readPayload(response: Response) {
  if (response.status === 204) {
    return undefined;
  }

  const type = response.headers.get("content-type") ?? "";
  if (type.includes("application/json")) {
    return response.json().catch(() => undefined);
  }

  return response.text().catch(() => undefined);
}

type RequestOptions = Omit<RequestInit, "body"> & {
  body?: unknown;
};

type QueryParams = Record<string, string | number | boolean | null | undefined>;

async function refreshAccessToken() {
  const refreshToken = localStorage.getItem(REFRESH_TOKEN_KEY);
  if (!refreshToken) {
    return false;
  }

  const response = await fetch(buildUrl("/auth/refresh"), {
    method: "POST",
    headers: {
      Accept: "application/json",
      Authorization: `Bearer ${refreshToken}`
    }
  });
  const payload = await readPayload(response);
  if (!response.ok) {
    return false;
  }
  if (payload && typeof payload === "object" && "accessToken" in payload) {
    const accessToken = (payload as { accessToken?: unknown }).accessToken;
    if (typeof accessToken === "string" && accessToken) {
      saveAccessToken(accessToken);
      return true;
    }
  }
  return false;
}

async function request<T>(path: string, options: RequestOptions = {}, retry = true): Promise<T> {
  const headers = new Headers(options.headers);
  const token = localStorage.getItem(ACCESS_TOKEN_KEY);

  if (token) {
    headers.set("Authorization", `Bearer ${token}`);
  }

  let body: BodyInit | undefined;
  if (typeof options.body !== "undefined") {
    if (options.body instanceof FormData) {
      body = options.body;
    } else {
      headers.set("Content-Type", "application/json");
      body = JSON.stringify(options.body);
    }
  }

  const response = await fetch(buildUrl(path), {
    ...options,
    headers,
    body
  });
  const payload = await readPayload(response);

  if (!response.ok) {
    if (response.status === 401 && retry && path !== "/auth/login" && path !== "/auth/refresh") {
      const refreshed = await refreshAccessToken().catch(() => false);
      if (refreshed) {
        return request<T>(path, options, false);
      }
    }

    if (response.status === 401) {
      clearSession();
      onUnauthorized?.();
    }

    throw new ApiError(errorMessage(payload, `请求失败，状态码 ${response.status}`), response.status, payload);
  }

  return payload as T;
}

function withQuery(path: string, params: QueryParams = {}) {
  const query = new URLSearchParams();
  Object.entries(params).forEach(([key, value]) => {
    if (value === null || typeof value === "undefined" || value === "") {
      return;
    }
    query.set(key, String(value));
  });
  const text = query.toString();
  if (!text) {
    return path;
  }
  return `${path}${path.includes("?") ? "&" : "?"}${text}`;
}

function normalizePage<T>(payload: unknown, params: QueryParams): Page<T> {
  if (payload && typeof payload === "object" && "items" in payload) {
    const page = payload as Partial<Page<T>>;
    return {
      items: Array.isArray(page.items) ? page.items : [],
      total: Number(page.total ?? 0),
      page: Number(page.page ?? params.page ?? 1),
      pageSize: Number(page.pageSize ?? params.pageSize ?? page.items?.length ?? 0)
    };
  }

  const items = Array.isArray(payload) ? (payload as T[]) : [];
  return {
    items,
    total: items.length,
    page: Number(params.page ?? 1),
    pageSize: Number(params.pageSize ?? items.length)
  };
}

export const api = {
  get: <T>(path: string) => request<T>(path, { method: "GET" }),
  page: async <T>(path: string, params: QueryParams = {}) =>
    normalizePage<T>(await request<unknown>(withQuery(path, params), { method: "GET" }), params),
  post: <T>(path: string, body: unknown) => request<T>(path, { method: "POST", body }),
  put: <T>(path: string, body: unknown) => request<T>(path, { method: "PUT", body }),
  delete: <T>(path: string) => request<T>(path, { method: "DELETE" })
};
