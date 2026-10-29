/**
 * 前端用户认证模块（后端 API 版）
 *
 * 认证已切换到大脑后端（FastAPI :6657，PostgreSQL 持久化）：
 *  - 注册 POST /api/auth/register、登录 POST /api/auth/login（docs/frontend-api.md 第 8 章契约）
 *  - 登录成功拿到 token 后，经 aisocApi 单例为后续所有大脑 /api/* 请求
 *    自动携带 Authorization: Bearer <token>
 *  - 会话令牌持久化在浏览器（remember me → localStorage，否则 sessionStorage），
 *    页面刷新时 restoreSession → getCurrentUser 重新注入 token
 *  - 按用户命名空间隔离本地数据（历史对话元数据、偏好等）的逻辑保持不变
 *
 * 3000 端口经 serve_frontend.py 反代：/api/* → http://127.0.0.1:6657/api/*，
 * 因此浏览器直接请求相对路径 /api/auth/* 即可。
 */

import { aisocApi } from "./aisoc-api";

// ─── 存储键常量（统一管理，避免散落硬编码）───────────────────────────────
const SESSION_KEY = "edushield:session";
const USER_DATA_PREFIX = "edushield:user:";
const AUTH_API_BASE = "/api/auth";

// ─── 类型定义 ──────────────────────────────────────────────────────────
export interface PublicUser {
  id: string;
  username: string;
  email: string;
  createdAt: string;
}

export interface Session {
  userId: string;
  token: string;
  issuedAt: number;
  expiresAt: number; // 0 = 永久（remember me），否则 Unix 毫秒时间戳
  user?: PublicUser; // 后端登录响应中的用户信息缓存（恢复会话时免查库）
}

export type AuthError =
  | "USERNAME_TAKEN"
  | "EMAIL_TAKEN"
  | "INVALID_CREDENTIALS"
  | "USER_NOT_FOUND"
  | "PASSWORD_MISMATCH"
  | "WEAK_PASSWORD"
  | "INVALID_USERNAME"
  | "INVALID_EMAIL"
  | "ACCOUNT_SUSPENDED"
  | "SESSION_EXPIRED"
  | "NETWORK_ERROR"
  | "SERVER_ERROR"
  | "UNKNOWN";

export const AUTH_ERROR_MESSAGES: Record<AuthError, string> = {
  USERNAME_TAKEN: "用户名已被注册",
  EMAIL_TAKEN: "该邮箱已被注册",
  INVALID_CREDENTIALS: "用户名或密码错误",
  USER_NOT_FOUND: "用户不存在",
  PASSWORD_MISMATCH: "两次输入的密码不一致",
  WEAK_PASSWORD: "密码至少 6 位",
  INVALID_USERNAME: "用户名需 3-20 位字母/数字/下划线",
  INVALID_EMAIL: "邮箱格式不正确",
  ACCOUNT_SUSPENDED: "账户已被封禁，请联系管理员",
  SESSION_EXPIRED: "登录已过期，请重新登录",
  NETWORK_ERROR: "无法连接认证服务，请检查网络后重试",
  SERVER_ERROR: "认证服务异常，请稍后重试",
  UNKNOWN: "未知错误，请稍后重试",
};

const KNOWN_ERROR_CODES: ReadonlySet<string> = new Set(Object.keys(AUTH_ERROR_MESSAGES));

// ─── 会话读写（remember me → localStorage，否则 sessionStorage）────────────
function getStorage(remember: boolean): Storage {
  return remember ? localStorage : sessionStorage;
}

/** 可用 storage 列表（SSR / 测试环境 sessionStorage 可能不存在，防御性过滤） */
function availableStorages(): Storage[] {
  const list: Storage[] = [];
  if (typeof localStorage !== "undefined") list.push(localStorage);
  if (typeof sessionStorage !== "undefined") list.push(sessionStorage);
  return list;
}

function readSession(): Session | null {
  for (const storage of availableStorages()) {
    try {
      const raw = storage.getItem(SESSION_KEY);
      if (!raw) continue;
      const session = JSON.parse(raw) as Session;
      if (session.expiresAt > 0 && session.expiresAt < Date.now()) {
        storage.removeItem(SESSION_KEY);
        continue;
      }
      return session;
    } catch {
      continue;
    }
  }
  return null;
}

function writeSession(session: Session, remember: boolean): void {
  (remember ? sessionStorage : localStorage).removeItem(SESSION_KEY);
  getStorage(remember).setItem(SESSION_KEY, JSON.stringify(session));
}

/** 读取原始 session（含已过期），用于登录时判断是否发生账号切换。 */
function readSessionRaw(): Session | null {
  for (const storage of availableStorages()) {
    try {
      const raw = storage.getItem(SESSION_KEY);
      if (!raw) continue;
      return JSON.parse(raw) as Session;
    } catch {
      continue;
    }
  }
  return null;
}

/**
 * 本地缓存归属标记：记录最近一次登录的 userId。
 * 不随 session 过期被删除——过期场景下 session 已被 readSession 静默清除，
 * 只有它能告诉下一次登录"浏览器里的缓存属于谁"。
 */
const CACHE_OWNER_KEY = "edushield:cache-owner";

function readCacheOwner(): string | null {
  try {
    return localStorage.getItem(CACHE_OWNER_KEY) ?? readSessionRaw()?.userId ?? null;
  } catch {
    return readSessionRaw()?.userId ?? null;
  }
}

function clearSession(): void {
  for (const storage of availableStorages()) {
    try {
      storage.removeItem(SESSION_KEY);
    } catch {
      // 静默忽略
    }
  }
}

// ─── 校验工具（本地预校验，服务端校验仍具最终决定权）───────────────────────
const USERNAME_RE = /^[a-zA-Z0-9_]{3,20}$/;
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

export function validateUsername(username: string): AuthError | null {
  return USERNAME_RE.test(username) ? null : "INVALID_USERNAME";
}

export function validateEmail(email: string): AuthError | null {
  return EMAIL_RE.test(email) ? null : "INVALID_EMAIL";
}

export function validatePassword(password: string): AuthError | null {
  return password.length >= 6 ? null : "WEAK_PASSWORD";
}

// ─── 错误处理 ──────────────────────────────────────────────────────────
export class AuthException extends Error {
  code: AuthError;
  constructor(code: AuthError, serverMessage?: string) {
    super(serverMessage || AUTH_ERROR_MESSAGES[code]);
    this.code = code;
    this.name = "AuthException";
  }
}

/** 按 HTTP 状态兜底映射错误码（服务端未返回 code 时）。 */
function fallbackErrorByStatus(status: number): AuthError {
  if (status === 401) return "INVALID_CREDENTIALS";
  if (status === 403) return "ACCOUNT_SUSPENDED";
  if (status === 409) return "USERNAME_TAKEN"; // 仅注册路径会 409，契约上即用户名/邮箱冲突
  if (status >= 500) return "SERVER_ERROR";
  return "UNKNOWN";
}

/**
 * 解析后端错误响应。兼容两种错误体形态：
 *  - `{ "code": "...", "message": "..." }`（大脑契约）
 *  - `{ "error": { "code": "...", "message": "..." } }`（网关风格）
 */
function normalizeAuthError(status: number, body: unknown): AuthException {
  const obj = (body && typeof body === "object" ? body : {}) as Record<string, unknown>;
  const inner = (obj.error && typeof obj.error === "object" ? obj.error : {}) as Record<string, unknown>;
  const rawCode = typeof obj.code === "string" ? obj.code : typeof inner.code === "string" ? inner.code : "";
  const rawMessage =
    typeof obj.message === "string" ? obj.message : typeof inner.message === "string" ? inner.message : undefined;
  const known = KNOWN_ERROR_CODES.has(rawCode);
  const code = known ? (rawCode as AuthError) : fallbackErrorByStatus(status);
  return new AuthException(code, known ? undefined : rawMessage);
}

// ─── HTTP 帮助函数 ────────────────────────────────────────────────────────
interface AuthResponseData {
  user?: unknown;
  token?: unknown;
  expiresAt?: unknown;
  [key: string]: unknown;
}

async function authPost(path: string, body: unknown): Promise<AuthResponseData> {
  let res: Response;
  try {
    res = await fetch(`${AUTH_API_BASE}${path}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
  } catch {
    // fetch 网络层异常（后端未启动 / 断网等）
    throw new AuthException("NETWORK_ERROR");
  }
  let parsed: unknown = null;
  try {
    const text = await res.text();
    if (text) parsed = JSON.parse(text);
  } catch {
    parsed = null;
  }
  if (!res.ok) throw normalizeAuthError(res.status, parsed);
  return (parsed && typeof parsed === "object" ? parsed : {}) as AuthResponseData;
}

/** 宽容解析后端 user 对象（容忍 snake_case 的 created_at）。 */
function normalizeUser(raw: unknown): PublicUser {
  const u = (raw && typeof raw === "object" ? raw : {}) as Record<string, unknown>;
  const createdAt =
    typeof u.createdAt === "string"
      ? u.createdAt
      : typeof u.created_at === "string"
        ? u.created_at
        : new Date().toISOString();
  return {
    id: String(u.id ?? ""),
    username: String(u.username ?? ""),
    email: String(u.email ?? ""),
    createdAt,
  };
}

/** 把 token 同步给 aisocApi 单例，使后续所有大脑 /api/* 请求携带 Bearer 头。 */
function syncTokenToAdapters(token: string | null): void {
  if (token) aisocApi.setAuthToken(token);
  else aisocApi.clearAuthToken();
}

// 18 号方案起：用户域缓存键已迁移到 userScopedStorage 的 userId 命名空间
// （各账号数据共存，logout/换账号不再清除）；base 键名唯一事实源见
// userScopedStorage.USER_SCOPED_BASE_KEYS。

// ─── authApi：后端 HTTP 实现（对外契约与原 localStorage 版一致）─────────────
export const authApi = {
  async register(
    username: string,
    email: string,
    password: string,
    confirmPassword: string,
  ): Promise<{ user: PublicUser; token: string }> {
    // 本地预校验：即时反馈，省一次往返；服务端校验错误以后端返回为准
    const usernameErr = validateUsername(username);
    if (usernameErr) throw new AuthException(usernameErr);
    const emailErr = validateEmail(email);
    if (emailErr) throw new AuthException(emailErr);
    const pwdErr = validatePassword(password);
    if (pwdErr) throw new AuthException(pwdErr);
    if (password !== confirmPassword) throw new AuthException("PASSWORD_MISMATCH");

    const data = await authPost("/register", { username, email, password, confirmPassword });
    return { user: normalizeUser(data.user), token: String(data.token ?? "") };
  },

  async login(
    identifier: string,
    password: string,
    remember: boolean,
  ): Promise<{ user: PublicUser; token: string; switchedAccount: boolean }> {
    const data = await authPost("/login", { identifier, password, remember });
    const user = normalizeUser(data.user);
    const token = String(data.token ?? "");
    if (!token) throw new AuthException("SERVER_ERROR");

    // 换账号登录（含上一会话已过期被静默清除的场景）：
    // 18 号方案起各账号缓存按 userId 命名空间共存，不再清除——
    // 仅上报 switchedAccount，由调用方做 anon 并入 + reload 重挂载。
    const prevOwner = readCacheOwner();
    const switchedAccount = prevOwner != null && prevOwner !== user.id;
    try {
      localStorage.setItem(CACHE_OWNER_KEY, user.id);
    } catch {
      // localStorage 不可用时静默忽略
    }

    const expiresAt =
      typeof data.expiresAt === "number" && data.expiresAt >= 0
        ? data.expiresAt
        : remember
          ? 0
          : Date.now() + 7 * 24 * 60 * 60 * 1000;
    const session: Session = { userId: user.id, token, issuedAt: Date.now(), expiresAt, user };
    writeSession(session, remember);
    syncTokenToAdapters(token);

    return { user, token, switchedAccount };
  },

  logout(): void {
    // 尽力通知后端吊销会话；无论成败本地会话都清除。
    // keepalive：紧随其后的页面 reload 不会中断该请求（18 号方案 F3）。
    const session = readSession();
    if (session?.token) {
      void fetch(`${AUTH_API_BASE}/logout`, {
        method: "POST",
        headers: { "Content-Type": "application/json", Authorization: `Bearer ${session.token}` },
        keepalive: true,
      }).catch(() => {});
    }
    clearSession();
    syncTokenToAdapters(null);
    // 18 号方案起：不再清除用户域缓存与 cache-owner——
    // 各账号数据按 userId 命名空间驻留，cache-owner 由下次 login 覆盖。
  },

  getCurrentUser(): PublicUser | null {
    const session = readSession();
    if (!session) return null;
    if (!session.user) return null; // 旧版 localStorage 会话无后端用户信息，视为未登录
    syncTokenToAdapters(session.token); // 页面刷新后重新注入 Bearer 头
    return session.user;
  },

  getCurrentSession(): Session | null {
    return readSession();
  },
};

// ─── 按用户命名空间的本地存储访问器 ────────────────────────────────────────
export function userStorage(userId: string) {
  const prefix = `${USER_DATA_PREFIX}${userId}:`;
  return {
    get<T>(subKey: string, fallback: T): T {
      try {
        const raw = localStorage.getItem(prefix + subKey);
        if (raw === null) return fallback;
        return JSON.parse(raw) as T;
      } catch {
        return fallback;
      }
    },
    set(subKey: string, value: unknown): void {
      try {
        localStorage.setItem(prefix + subKey, JSON.stringify(value));
      } catch {
        /* quota exceeded */
      }
    },
    remove(subKey: string): void {
      localStorage.removeItem(prefix + subKey);
    },
    keys(): string[] {
      const result: string[] = [];
      for (let i = 0; i < localStorage.length; i++) {
        const k = localStorage.key(i);
        if (k && k.startsWith(prefix)) result.push(k.slice(prefix.length));
      }
      return result;
    },
    clear(): void {
      const toRemove: string[] = [];
      for (let i = 0; i < localStorage.length; i++) {
        const k = localStorage.key(i);
        if (k && k.startsWith(prefix)) toRemove.push(k);
      }
      toRemove.forEach((k) => localStorage.removeItem(k));
    },
  };
}

// ─── 用户历史对话数据结构 ─────────────────────────────────────────────────
export interface ConversationMeta {
  conversationId: string;
  title: string;
  summary?: string;
  domain?: string;
  pinned: boolean;
  createdAt: string;
  updatedAt: string;
}

const HISTORY_SUBKEY = "conversation:history";

export function getUserConversationHistory(userId: string): ConversationMeta[] {
  return userStorage(userId).get<ConversationMeta[]>(HISTORY_SUBKEY, []);
}

export function saveUserConversation(userId: string, meta: ConversationMeta): void {
  const list = getUserConversationHistory(userId);
  const idx = list.findIndex((c) => c.conversationId === meta.conversationId);
  if (idx >= 0) list[idx] = { ...list[idx], ...meta };
  else list.unshift(meta);
  userStorage(userId).set(HISTORY_SUBKEY, list.slice(0, 200));
}

export function removeUserConversation(userId: string, conversationId: string): void {
  const list = getUserConversationHistory(userId).filter(
    (c) => c.conversationId !== conversationId,
  );
  userStorage(userId).set(HISTORY_SUBKEY, list);
}
