/**
 * 设置持久化统一适配器（L1 闭环基础）
 *
 * 所有 Web 模式下需要持久化的设置字段，统一走本模块读写：
 * - 键前缀 `reasonix-settings:`，避免与既有偏好 key（如 reasonix-display-mode）冲突；
 * - 值统一 JSON 序列化；
 * - localStorage 不可用或解析失败时静默回退 fallback，不抛异常。
 */
const PREFIX = "reasonix-settings:";

export const settingsStorage = {
  get<T>(key: string, fallback: T): T {
    try {
      const raw = localStorage.getItem(PREFIX + key);
      return raw == null ? fallback : (JSON.parse(raw) as T);
    } catch {
      return fallback;
    }
  },
  set(key: string, value: unknown) {
    try {
      localStorage.setItem(PREFIX + key, JSON.stringify(value));
    } catch {
      /* ignore storage failures */
    }
  },
  remove(key: string) {
    try {
      localStorage.removeItem(PREFIX + key);
    } catch {
      /* ignore storage failures */
    }
  },
};