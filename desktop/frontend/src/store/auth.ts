/**
 * 认证状态 store（zustand）
 *
 * 职责：
 *  - 持有当前登录用户（PublicUser | null）
 *  - 暴露 login / register / logout / restoreSession action
 *  - 维护 loading / error 状态供 UI 层消费
 *  - 与 lib/auth.ts 的 authApi 解耦：store 只调 API，不直接碰 localStorage
 */

import { create } from "zustand";
import { authApi, AuthException, type PublicUser } from "../lib/auth";
import { adoptAnonIfFirstLogin } from "../lib/userScopedStorage";

export interface AuthState {
  user: PublicUser | null;
  loading: boolean;
  error: string | null;
  initialized: boolean; // 是否已完成启动时的会话恢复

  login: (identifier: string, password: string, remember: boolean) => Promise<boolean>;
  register: (
    username: string,
    email: string,
    password: string,
    confirmPassword: string,
  ) => Promise<boolean>;
  logout: () => void;
  restoreSession: () => void;
  clearError: () => void;
}

export const useAuthStore = create<AuthState>((set) => ({
  user: null,
  loading: false,
  error: null,
  initialized: false,

  login: async (identifier, password, remember) => {
    set({ loading: true, error: null });
    try {
      const { user, switchedAccount } = await authApi.login(identifier, password, remember);
      set({ user, loading: false, error: null });
      if (typeof window !== "undefined") {
        // anon 并入仅限"非换账号"（首次登录/同人重登）：换账号时 anon 数据归属
        // 无法确认（可能是上一用户过期残留），并入会导致新账号看到别人的本地会话。
        if (!switchedAccount) adoptAnonIfFirstLogin(user.id);
        // 无论是否换账号都 reload：webApiProxy / webProjects 单例只在构造时读
        // localStorage，首次登录（switchedAccount=false）不 reload 会停留在 anon
        // 命名空间的内存态，写入却走 userId 命名空间，刷新后数据"丢失"。
        window.location.reload();
      }
      return true;
    } catch (err) {
      const message =
        err instanceof AuthException ? err.message : "登录失败，请稍后重试";
      set({ loading: false, error: message });
      return false;
    }
  },

  register: async (username, email, password, confirmPassword) => {
    set({ loading: true, error: null });
    try {
      const { user } = await authApi.register(username, email, password, confirmPassword);
      // 注册成功后自动登录（写会话）
      const { switchedAccount } = await authApi.login(username, password, true);
      set({ user, loading: false, error: null });
      if (typeof window !== "undefined") {
        // 同 login：换账号不并 anon；reload 无条件执行以重挂载用户域单例。
        if (!switchedAccount) adoptAnonIfFirstLogin(user.id);
        window.location.reload();
      }
      return true;
    } catch (err) {
      const message =
        err instanceof AuthException ? err.message : "注册失败，请稍后重试";
      set({ loading: false, error: message });
      return false;
    }
  },

  logout: () => {
    authApi.logout();
    set({ user: null, error: null });
    // webApiProxy / webProjects 等单例只在构造时读一次 localStorage，
    // 不刷新页面内存中仍是上一账号的会话/项目数据；reload 后 AuthGate 自动弹登录页。
    if (typeof window !== "undefined") window.location.reload();
  },

  restoreSession: () => {
    const user = authApi.getCurrentUser();
    set({ user, initialized: true });
  },

  clearError: () => set({ error: null }),
}));
