/**
 * resilientRequest 统一降级冒烟测试（校园运营场景对齐改进计划书 T1-9）
 * 覆盖 401 / 404 / 超时 / 5xx 四种失败：均静默返回 fallback、不抛异常；
 * 并验证成功路径不受影响、非可降级错误（403）仍会抛出。
 * 运行：npx tsx src/__tests__/resilient-request.test.ts
 */

export {};

declare const process: { exit(code: number): void };

import { resilientRequest, isDegradableError } from '../lib/resilientRequest';

let pass = 0, fail = 0;
function ok(cond: boolean, name: string) {
  if (cond) { pass++; console.log('  ✓', name); }
  else { fail++; console.error('  ✗', name); }
}

/** 带 HTTP 状态码的接口错误（等价 aisoc-api 的 AisocApiError） */
class HttpError extends Error {
  status: number;
  constructor(status: number) { super(`HTTP ${status}`); this.status = status; }
}

async function main() {
  // ── 1. 成功路径行为完全不变 ──
  console.log('1) 成功路径不变');
  const okVal = await resilientRequest(async () => 'payload', null);
  ok(okVal === 'payload', '成功时返回原值');
  const okArr = await resilientRequest(async () => [1, 2, 3], [] as number[]);
  ok(okArr?.length === 3, '成功时返回原数组（带 fallback 亦不影响）');

  // ── 2. 401 ──
  console.log('2) 401 → 静默降级');
  const r401 = await resilientRequest(async () => { throw new HttpError(401); }, null);
  ok(r401 === null, '401 返回 null');
  let threw401 = false;
  try { await resilientRequest(async () => { throw new HttpError(401); }, null); } catch { threw401 = true; }
  ok(!threw401, '401 不抛异常');

  // ── 3. 404（含调用方指定 fallback） ──
  console.log('3) 404 → 静默降级');
  const fb = { tasks: [] as string[] };
  const r404 = await resilientRequest(async () => { throw new HttpError(404); }, fb);
  ok(r404 === fb, '404 返回调用方指定 fallback');
  ok(r404.tasks.length === 0, 'fallback 内容原样返回');

  // ── 4. 5xx ──
  console.log('4) 5xx → 静默降级');
  const r500 = await resilientRequest(async () => { throw new HttpError(500); }, null);
  ok(r500 === null, '500 返回 null');
  const r502 = await resilientRequest(async () => { throw new HttpError(502); }, null);
  ok(r502 === null, '502 返回 null');
  ok(isDegradableError({ status: 503 }), '503 判定为可降级');
  ok(isDegradableError({ isUnreachable: true }), 'AisocApiError.isUnreachable 判定为可降级');

  // ── 5. 超时（AbortController；默认 8s，测试用极小超时） ──
  console.log('5) 超时 → 静默降级');
  const rTimeout = await resilientRequest<string>(
    (signal) => new Promise((_res, rej) => {
      signal.addEventListener('abort', () => rej(new DOMException('Aborted', 'AbortError')));
    }),
    'timeout-fallback',
    { timeoutMs: 20 },
  );
  ok(rTimeout === 'timeout-fallback', '超时返回 fallback');
  ok(isDegradableError(new DOMException('x', 'TimeoutError')), 'TimeoutError 判定为可降级');
  ok(isDegradableError(new DOMException('x', 'AbortError')), 'AbortError 判定为可降级');

  // ── 5b. 超时不依赖 run 透传 signal（对齐 webApiProxy 真实调用点写法） ──
  // webApiProxy 的 5 个调用点均为 `resilientRequest(() => aisocApi.xxx(...), null)`，
  // 箭头函数忽略 signal；此类调用点也必须能超时降级，否则生产路径 8s 约定形同虚设。
  console.log('5b) run 忽略 signal 仍超时降级');
  const t0 = Date.now();
  const rIgnoreSignal = await resilientRequest<string>(
    async () => new Promise<string>(() => { /* 永不 resolve，且完全忽略 signal */ }),
    'ignore-signal-fallback',
    { timeoutMs: 30 },
  );
  ok(rIgnoreSignal === 'ignore-signal-fallback', 'run 忽略 signal 时超时返回 fallback');
  ok(Date.now() - t0 < 1000, '超时在约定时间内触发（未挂死）');

  // ── 6. 真实 fetch 集成：run 透传 signal，404 静默、200 透传 ──
  console.log('6) fetch 集成');
  (globalThis as any).fetch = async (_url: string, init?: any) => {
    ok(init?.signal instanceof AbortSignal, 'run 收到并可透传 AbortSignal');
    return new Response('not found', { status: 404 });
  };
  const rFetch404 = await resilientRequest(async (signal) => {
    const resp = await fetch('/api/tir/alerts', { signal });
    if (!resp.ok) throw new HttpError(resp.status);
    return [] as string[];
  }, [] as string[]);
  ok(rFetch404.length === 0, 'fetch 404 → 返回空 fallback，不抛异常');

  (globalThis as any).fetch = async () => new Response(JSON.stringify({ ok: 1 }), { status: 200 });
  const rFetch200 = await resilientRequest(async (signal) => {
    const resp = await fetch('/api/tir/playbooks', { signal });
    return (await resp.json()) as { ok: number };
  }, null);
  ok(rFetch200?.ok === 1, 'fetch 200 → 原样解析返回');

  // ── 7. 网络不可达 / 非可降级错误 ──
  console.log('7) 网络不可达 / 其它错误');
  let netThrew = false;
  try { await resilientRequest(async () => { throw new TypeError('Failed to fetch'); }, null); } catch { netThrew = true; }
  ok(!netThrew, 'fetch 网络层 TypeError → 静默返回 null');
  let otherThrew = false;
  try { await resilientRequest(async () => { throw new HttpError(403); }, 'fb'); } catch { otherThrew = true; }
  ok(otherThrew, '非 401/404/5xx（403）仍抛出，不放行错误');

  console.log(`\n通过 ${pass}，失败 ${fail}`);
  process.exit(fail > 0 ? 1 : 0);
}

main().catch((e) => { console.error(e); process.exit(1); });
