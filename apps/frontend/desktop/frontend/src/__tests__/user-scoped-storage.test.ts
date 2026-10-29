/**
 * userScopedStorage 单元测试（18 号方案 F1）
 * 覆盖：命名空间隔离 / anon 并入 / 不覆盖已有账号 / 旧全局键迁移 / clearCurrentNs
 * 运行：npx tsx src/__tests__/user-scoped-storage.test.ts
 */

export {};

declare const process: { exit(code: number): void };

// ─── 浏览器环境 polyfill（必须先于被测模块 import）───
class MemStorage implements Storage {
  private m = new Map<string, string>();
  get length() { return this.m.size; }
  clear() { this.m.clear(); }
  getItem(k: string) { return this.m.has(k) ? this.m.get(k)! : null; }
  key(i: number) { return [...this.m.keys()][i] ?? null; }
  removeItem(k: string) { this.m.delete(k); }
  setItem(k: string, v: string) { this.m.set(k, String(v)); }
}
const _ls = new MemStorage();
const _ss = new MemStorage();
Object.defineProperty(globalThis, 'localStorage', { value: _ls, configurable: true });
Object.defineProperty(globalThis, 'sessionStorage', { value: _ss, configurable: true });

const USER_A = { id: 'uid-a', username: 'alice', email: 'a@x.com', createdAt: '2026-01-01' };
const USER_B = { id: 'uid-b', username: 'bob', email: 'b@x.com', createdAt: '2026-01-01' };
(globalThis as any).fetch = async (url: string, init?: any) => {
  if (String(url).includes('/api/auth/login')) {
    const body = JSON.parse(init.body);
    const user = body.identifier === 'alice' ? USER_A : USER_B;
    return new Response(JSON.stringify({ user, token: 'tok-' + user.id, expiresAt: 0 }), { status: 200 });
  }
  return new Response('{}', { status: 200 });
};

const { authApi } = await import('../lib/auth');
const store = await import('../lib/userScopedStorage');

let pass = 0, fail = 0;
function ok(cond: boolean, name: string) {
  if (cond) { pass++; console.log('  ✓', name); }
  else { fail++; console.error('  ✗', name); }
}

function seedAll(nsLabel: string, ns?: string) {
  for (const base of store.USER_SCOPED_BASE_KEYS) {
    store.writeNs(base, `${nsLabel}-${base}`, ns);
  }
}
function readAll(ns?: string): (string | null)[] {
  return store.USER_SCOPED_BASE_KEYS.map((b) => store.readNs<string | null>(b, null, ns));
}

async function main() {
  console.log('场景1: 命名空间隔离（A 写 → B 读空 → A 原样在）');
  await authApi.login('alice', 'pw', true);
  ok(store.currentNs() === 'uid-a', '登录 A 后 currentNs=uid-a');
  seedAll('A');
  // 模拟切到 B（直接写 session 等价于 login B）
  await authApi.login('bob', 'pw', true);
  ok(store.currentNs() === 'uid-b', '登录 B 后 currentNs=uid-b');
  ok(readAll().every((v) => v === null), 'B 命名空间读不到 A 的数据');
  ok(readAll('uid-a').every((v) => v !== null && v.startsWith('A-')), 'A 命名空间数据原样保留');

  console.log('场景2: 未登录 anon 命名空间');
  authApi.logout();
  ok(store.currentNs() === 'anon', 'logout 后 currentNs=anon');
  ok(readAll().every((v) => v === null), 'anon 命名空间为空（与任何账号隔离）');

  console.log('场景3: anon → 首次登录并入');
  seedAll('anon');
  store.adoptAnonIfFirstLogin('uid-b');
  ok(readAll('uid-b').every((v) => v !== null && v.startsWith('anon-')), 'anon 数据并入 uid-b');
  ok(readAll('anon').every((v) => v === null), 'anon 命名空间已清空');

  console.log('场景4: 目标账号已有数据时 anon 不并入');
  store.writeNs('reasonix:web:tabs', 'B-own-tabs', 'uid-b');
  seedAll('anon2', 'anon');
  store.adoptAnonIfFirstLogin('uid-b');
  ok(store.readNs('reasonix:web:tabs', null, 'uid-b') === 'B-own-tabs', 'B 已有数据不被 anon 覆盖');
  ok(
    store.readNs('reasonix:web:histories', null, 'uid-b') === 'anon-reasonix:web:histories',
    'B 既有数据（场景3并入）未被 anon2 触碰',
  );
  ok(store.readNs('reasonix:web:tabs', null, 'anon') === 'anon2-reasonix:web:tabs', 'anon 数据保留');

  console.log('场景5: 旧全局键一次性迁移');
  _ls.clear(); _ss.clear();
  _ls.setItem('reasonix:web:histories', JSON.stringify([['t1', [{ role: 'user', text: 'hi' }]]]));
  _ls.setItem('reasonix:web:tab:active', 'web-tab-1'); // 旧版裸字符串
  _ls.setItem('reasonix:web:projects:v1', JSON.stringify([{ id: 'p1' }]));
  store.migrateLegacyKeys();
  ok(_ls.getItem('reasonix:web:histories') === null, '旧全局 histories 键已删除');
  ok(_ls.getItem('reasonix:web:ns-migrated') === '1', '迁移标记置位');
  const h = store.readNs('reasonix:web:histories', null);
  ok(Array.isArray(h) && (h as any)[0][0] === 't1', 'histories 迁入当前(anon)命名空间且可解析');
  ok(store.readNs('reasonix:web:tab:active', null) === 'web-tab-1', '裸字符串 active 键 JSON 化后可读');
  ok(Array.isArray(store.readNs('reasonix:web:projects:v1', null)), 'projects 迁移可解析');
  // 幂等：再放旧键不应被迁移
  _ls.setItem('reasonix:web:histories', JSON.stringify([['t2', []]]));
  store.migrateLegacyKeys();
  ok((store.readNs('reasonix:web:histories', null) as any)[0][0] === 't1', '二次迁移不生效（幂等）');

  console.log('场景6: clearCurrentNs 只清当前命名空间');
  _ls.clear(); _ss.clear();
  await authApi.login('alice', 'pw', true);
  seedAll('A');
  seedAll('B', 'uid-b');
  store.clearCurrentNs();
  ok(readAll().every((v) => v === null), 'A（当前）命名空间已清');
  ok(readAll('uid-b').every((v) => v !== null), 'B 命名空间不受影响');

  console.log(`\n结果: ${pass} passed, ${fail} failed`);
  if (fail > 0) process.exit(1);
  console.log('PASS');
}

await main();
