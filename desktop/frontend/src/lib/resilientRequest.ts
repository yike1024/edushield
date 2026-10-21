/**
 * resilientRequest — 新接口统一降级 helper（校园运营场景对齐改进计划书 T1-9）
 *
 * 语义（固定）：把「新接口各自 try/catch 降级」收敛为一处。
 *   - 401 / 404 / 5xx / 超时 / 网络不可达 → 静默返回 fallback（默认 null），不抛异常；
 *   - 成功路径行为完全不变（原样返回 run 的结果）。
 *
 * 约定：
 *   - 超时由本 helper 统一控制，默认 8000ms，沿用项目既有 8s 约定（T0-3 规则快速路
 *     LLM timeout 8s）。超时经 Promise.race 强制生效，**不依赖 run 是否把 signal 透传给
 *     fetch**（`() => aisocApi.xxx()` 这类忽略 signal 的调用点同样能降级）；run 若把 signal
 *     透传给 fetch，还能额外受益于 AbortController 真正中断底层请求。
 *   - 401 不在此处触发登出：沿用 aisoc-api 既有「3s 防抖确认 → edushield:unauthorized
 *     全局事件」机制，由 AuthGate 统一处理登出，避免每个新接口重复实现。
 */

const DEFAULT_TIMEOUT_MS = 8000;

export interface ResilientRequestOptions {
  /** AbortController 超时毫秒数；默认 8000（沿用项目 8s 约定） */
  timeoutMs?: number;
}

/** 判定错误是否属于「可静默降级」：401 / 404 / 5xx / 超时 / 网络不可达。 */
export function isDegradableError(err: unknown): boolean {
  if (err == null) return false;
  const name = (err as { name?: unknown }).name;
  if (name === 'AbortError' || name === 'TimeoutError') return true;
  // fetch 在网络层失败（DNS/连接被拒/CORS）抛出 TypeError，等价于「服务不可达」
  if (err instanceof TypeError) return true;
  const status = (err as { status?: unknown }).status;
  if (typeof status === 'number') {
    return status === 0 || status === 401 || status === 404 || status >= 500;
  }
  if ((err as { isUnreachable?: unknown }).isUnreachable === true) return true;
  return false;
}

/** 携带调用方指定 fallback：失败时返回 fallback（类型保持 T）。 */
export function resilientRequest<T>(
  run: (signal: AbortSignal) => Promise<T>,
  fallback: T,
  options?: ResilientRequestOptions,
): Promise<T>;
/** 未指定 fallback：失败时返回 null。 */
export function resilientRequest<T>(
  run: (signal: AbortSignal) => Promise<T>,
  fallback?: null,
  options?: ResilientRequestOptions,
): Promise<T | null>;
export async function resilientRequest<T>(
  run: (signal: AbortSignal) => Promise<T>,
  fallback: T | null = null,
  options: ResilientRequestOptions = {},
): Promise<T | null> {
  const controller = new AbortController();
  const timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  let timer: ReturnType<typeof setTimeout> | undefined;
  // 超时不依赖 run 是否透传 signal：定时器到点即 abort 并 reject 一个 TimeoutError，
  // 与 run 的 Promise 竞速 —— 因此 `() => aisocApi.xxx()` 这类忽略 signal 的调用点也能降级。
  const timeout = new Promise<never>((_resolve, reject) => {
    timer = setTimeout(() => {
      controller.abort();
      const err = new Error(`request timeout after ${timeoutMs}ms`);
      err.name = 'TimeoutError';
      reject(err);
    }, timeoutMs);
  });
  try {
    return await Promise.race([run(controller.signal), timeout]);
  } catch (err) {
    if (isDegradableError(err)) return fallback;
    throw err;
  } finally {
    clearTimeout(timer);
  }
}
