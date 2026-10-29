/**
 * 用户域本地缓存的命名空间存储（18 号方案 F1）。
 *
 * 9 个用户域 localStorage 键统一收口为 `reasonix:web:{name}:{ns}` 形态：
 *   - 已登录：ns = 当前用户 id（各账号数据共存，换账号互不污染）
 *   - 未登录：ns = 'anon'
 *
 * 本文件是 9 个 base 键名的唯一事实源；webApiProxy / webProjects 的
 * 读写必须经 readNs/writeNs，禁止再直接拼字面值键。
 *
 * 依赖方向：userScopedStorage → lib/auth（auth 不反向依赖，无环）。
 */

import { authApi } from './auth';

/** 用户域 base 键名（不带命名空间后缀）。新增用户域键必须先在此登记。 */
export const USER_SCOPED_BASE_KEYS = [
  'reasonix:web:histories',
  'reasonix:web:tabs',
  'reasonix:web:tab:active',
  'reasonix:web:conversations',
  'reasonix:web:memory',
  'reasonix:web:projects:v1',
  'reasonix:web:projects:active',
  'reasonix:web:projects:migrated',
  'reasonix:web:projects:aliases',
] as const;

/** 旧版（命名空间化之前）全局键 → 当前命名空间的一次性迁移标记 */
const NS_MIGRATED_KEY = 'reasonix:web:ns-migrated';

/** 当前命名空间：已登录 → userId；未登录 → 'anon' */
export function currentNs(): string {
  return authApi.getCurrentSession()?.userId ?? 'anon';
}

export function nsKey(base: string, ns?: string): string {
  return `${base}:${ns ?? currentNs()}`;
}

export function readNs<T>(base: string, fallback: T, ns?: string): T {
  if (typeof localStorage === 'undefined') return fallback;
  try {
    const raw = localStorage.getItem(nsKey(base, ns));
    if (raw == null) return fallback;
    return JSON.parse(raw) as T;
  } catch {
    return fallback;
  }
}

export function writeNs(base: string, value: unknown, ns?: string): void {
  if (typeof localStorage === 'undefined') return;
  try {
    localStorage.setItem(nsKey(base, ns), JSON.stringify(value));
  } catch {
    // 存储满 / 隐私模式：静默忽略，行为与旧版一致
  }
}

export function removeNs(base: string, ns?: string): void {
  if (typeof localStorage === 'undefined') return;
  try {
    localStorage.removeItem(nsKey(base, ns));
  } catch {
    // 静默忽略
  }
}

/** 删除当前命名空间的全部用户域键（设置页"清除本账号本地缓存"用）。 */
export function clearCurrentNs(): void {
  const ns = currentNs();
  for (const base of USER_SCOPED_BASE_KEYS) removeNs(base, ns);
}

/**
 * 旧全局键（无命名空间后缀）→ 当前命名空间的一次性迁移。
 * 幂等：全局标记置位后直接返回；webApiProxy 构造时调用。
 */
export function migrateLegacyKeys(): void {
  if (typeof localStorage === 'undefined') return;
  try {
    if (localStorage.getItem(NS_MIGRATED_KEY)) return;
    for (const base of USER_SCOPED_BASE_KEYS) {
      const legacy = localStorage.getItem(base);
      if (legacy == null) continue;
      // 目标命名空间已有数据时丢弃旧值，避免旧全局数据覆盖新数据
      if (localStorage.getItem(nsKey(base)) == null) {
        // 旧版 active 键是裸字符串（非 JSON），统一 JSON 化后写入
        let value: unknown = legacy;
        try {
          value = JSON.parse(legacy);
        } catch {
          /* 裸字符串原样作为值 */
        }
        localStorage.setItem(nsKey(base), JSON.stringify(value));
      }
      localStorage.removeItem(base);
    }
    localStorage.setItem(NS_MIGRATED_KEY, '1');
  } catch {
    // 静默忽略
  }
}

/**
 * 首次登录并入：anon 命名空间有数据且目标用户命名空间为空时，
 * 把 anon 数据整体搬给该用户（保持"未登录先用、登录后数据还在"的体验）。
 * 目标用户已有数据时不并入——防共享电脑上 anon 数据吞并已有账号数据。
 * login 成功且检测到换账号时调用。
 */
export function adoptAnonIfFirstLogin(userId: string): void {
  if (typeof localStorage === 'undefined') return;
  try {
    const hasUserData = USER_SCOPED_BASE_KEYS.some(
      (base) => localStorage.getItem(nsKey(base, userId)) != null,
    );
    if (hasUserData) return;
    for (const base of USER_SCOPED_BASE_KEYS) {
      const anonKey = nsKey(base, 'anon');
      const raw = localStorage.getItem(anonKey);
      if (raw == null) continue;
      localStorage.setItem(nsKey(base, userId), raw);
      localStorage.removeItem(anonKey);
    }
  } catch {
    // 静默忽略
  }
}
