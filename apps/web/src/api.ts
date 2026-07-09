import type { LoginResponse, Session } from "./types";

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

async function request<T>(path: string, options: RequestOptions = {}): Promise<T> {
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
    if (response.status === 401) {
      clearSession();
      onUnauthorized?.();
    }

    throw new ApiError(
      errorMessage(payload, `Request failed with status ${response.status}`),
      response.status,
      payload
    );
  }

  return payload as T;
}

export const api = {
  get: <T>(path: string) => request<T>(path, { method: "GET" }),
  post: <T>(path: string, body: unknown) => request<T>(path, { method: "POST", body }),
  put: <T>(path: string, body: unknown) => request<T>(path, { method: "PUT", body }),
  delete: <T>(path: string) => request<T>(path, { method: "DELETE" })
};
