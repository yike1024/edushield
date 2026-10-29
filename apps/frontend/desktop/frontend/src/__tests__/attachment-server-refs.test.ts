/**
 * 21 号方案（会话级附件目录）前端链路单元测试
 * 覆盖：
 *   1) mirrorAttachmentToServer 请求体带 conversation_id；响应存 uploadId/conversationBound
 *   2) bindPendingAttachments 提交 upload_ids 并回写新 serverPath（404 静默）
 *   3) collectServerAttachmentRefs 只收集已镜像附件、按 serverPath 去重
 *   4) expandFileReferences：conversationBound 附件改路径引用不内联；未绑定附件保持内联
 *   5) aisoc-api chatStream 请求体 attachments 字段
 *   6) AttachmentServerInfo 返回落盘信息 / null
 * 运行：npx tsx src/__tests__/attachment-server-refs.test.ts
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
Object.defineProperty(globalThis, 'localStorage', { value: new MemStorage(), configurable: true });
Object.defineProperty(globalThis, 'sessionStorage', { value: new MemStorage(), configurable: true });

// fetch 捕获器：按 URL 分发响应，记录请求体
type CapturedCall = { url: string; body: any };
const calls: CapturedCall[] = [];
let saveAttachmentBehavior: 'bound' | 'pending' | 'notfound' = 'bound';
let bindStatus = 200;
(globalThis as any).fetch = async (url: string, init?: any) => {
  const u = String(url);
  const body = init?.body ? JSON.parse(init.body) : undefined;
  calls.push({ url: u, body });
  if (u.includes('/api/auth/login')) {
    return new Response(JSON.stringify({
      user: { id: 'uid-t', username: 'tester', email: 't@x.com', createdAt: '2026-01-01' },
      token: 'tok-t', expiresAt: 0,
    }), { status: 200 });
  }
  if (u.includes('/api/save-attachment')) {
    if (saveAttachmentBehavior === 'notfound') return new Response('not found', { status: 404 });
    if (saveAttachmentBehavior === 'pending') {
      return new Response(JSON.stringify({
        path: 'uid-t/_pending/up-1_test.log', upload_id: 'up-1', size: 12, conversation_bound: false,
      }), { status: 200 });
    }
    return new Response(JSON.stringify({
      path: 'uid-t/conv-123/test.log', size: 12, conversation_bound: true,
    }), { status: 200 });
  }
  if (u.includes('/api/attachments/bind')) {
    if (bindStatus !== 200) return new Response('not found', { status: bindStatus });
    return new Response(JSON.stringify({ bound: ['uid-t/conv-123/test.log'] }), { status: 200 });
  }
  if (u.includes('/api/chat/stream')) {
    return new Response(new TextEncoder().encode('data: [DONE]\n\n'), { status: 200 });
  }
  return new Response('{}', { status: 200 });
};

const { authApi } = await import('../lib/auth');
const { WebApiProxy } = await import('../lib/webApiProxy');
const { AisocApi } = await import('../lib/aisoc-api');

let pass = 0, fail = 0;
function ok(cond: boolean, name: string) {
  if (cond) { pass++; console.log('  ✓', name); }
  else { fail++; console.error('  ✗', name); }
}

const DATA_URL = 'data:text/plain;base64,' + Buffer.from('hello server copy').toString('base64');

async function main() {
  await authApi.login('tester', 'pw', true);

  // ── 1. mirror：已有会话 → conversation_id 带上，conversation_bound=true 落标记 ──
  console.log('1) mirrorAttachmentToServer（已绑定会话）');
  const proxy = new WebApiProxy();
  (proxy as any)._conversationIdByTab.set((proxy as any).activeTabId, 'conv-123');
  saveAttachmentBehavior = 'bound';
  calls.length = 0;
  const p1 = await proxy.SavePastedFile('test.log', DATA_URL);
  await (proxy as any).mirrorAttachmentToServer(p1, 'test.log', DATA_URL);
  const saveCall = calls.find((c) => c.url.includes('/api/save-attachment'));
  ok(saveCall?.body?.conversation_id === 'conv-123', '请求体带当前会话 conversation_id');
  ok(saveCall?.body?.name === 'test.log' && typeof saveCall?.body?.dataUrl === 'string', 'name/dataUrl 字段保持');
  let att = (proxy as any).attachments.get(p1);
  ok(att?.serverPath === 'uid-t/conv-123/test.log', 'serverPath 回写');
  ok(att?.conversationBound === true, 'conversationBound 标记为 true');
  ok(att?.uploadId === undefined, '直绑会话时无 uploadId');

  // ── 2. mirror：无会话 → conversation_id=null，存 uploadId（pending）──
  console.log('2) mirrorAttachmentToServer（新会话 pending）');
  const proxy2 = new WebApiProxy();
  saveAttachmentBehavior = 'pending';
  calls.length = 0;
  const p2 = await proxy2.SavePastedFile('test.log', DATA_URL);
  await (proxy2 as any).mirrorAttachmentToServer(p2, 'test.log', DATA_URL);
  const saveCall2 = calls.find((c) => c.url.includes('/api/save-attachment'));
  ok(saveCall2?.body?.conversation_id === null, '无会话时 conversation_id=null（走 _pending）');
  att = (proxy2 as any).attachments.get(p2);
  ok(att?.uploadId === 'up-1', 'uploadId 落存');
  ok(att?.conversationBound !== true, 'pending 状态未标记 conversationBound');

  // ── 3. bind：会话建立后 pending 附件绑定进会话目录 ──
  console.log('3) bindPendingAttachments');
  bindStatus = 200;
  calls.length = 0;
  await (proxy2 as any).bindPendingAttachments('conv-123');
  const bindCall = calls.find((c) => c.url.includes('/api/attachments/bind'));
  ok(bindCall?.body?.conversation_id === 'conv-123', 'bind 带 conversation_id');
  ok(Array.isArray(bindCall?.body?.upload_ids) && bindCall.body.upload_ids.includes('up-1'), 'bind 带 upload_ids');
  att = (proxy2 as any).attachments.get(p2);
  ok(att?.conversationBound === true && att?.serverPath === 'uid-t/conv-123/test.log', 'bind 成功后回写新 serverPath + conversationBound');

  // 3b. bind 404 静默（端点未上线不炸）
  console.log('3b) bind 404 静默降级');
  const proxy2b = new WebApiProxy();
  saveAttachmentBehavior = 'pending';
  const p2b = await proxy2b.SavePastedFile('test.log', DATA_URL);
  await (proxy2b as any).mirrorAttachmentToServer(p2b, 'test.log', DATA_URL);
  bindStatus = 404;
  let threw = false;
  try { await (proxy2b as any).bindPendingAttachments('conv-123'); } catch { threw = true; }
  bindStatus = 200;
  ok(!threw, 'bind 404 不抛异常');
  ok((proxy2b as any).attachments.get(p2b)?.conversationBound !== true, 'bind 404 不误标 conversationBound');

  // ── 4. collectServerAttachmentRefs：只收集已镜像附件、去重 ──
  console.log('4) collectServerAttachmentRefs');
  const refs = (proxy as any).collectServerAttachmentRefs(`看这个 @[test.log](${p1}) 和 @[test2](${p1})`);
  ok(refs.length === 1 && refs[0].name === 'test.log' && refs[0].path === 'uid-t/conv-123/test.log', '收集 name+path 且按 serverPath 去重');
  saveAttachmentBehavior = 'notfound'; // 端点未上线：fire-and-forget mirror 404，serverPath 保持未设置
  const proxy3 = new WebApiProxy(); // 未镜像附件
  const p3 = await proxy3.SavePastedFile('local.log', DATA_URL);
  await new Promise((r) => setTimeout(r, 20)); // 等 fire-and-forget mirror 落定（404 无回写）
  ok((proxy3 as any).collectServerAttachmentRefs(`@[local.log](${p3})`).length === 0, '未镜像附件不收集');

  // ── 5. expandFileReferences：conversationBound 改路径引用；未绑定保持内联 ──
  console.log('5) expandFileReferences');
  const expanded = await (proxy as any).expandFileReferences(`审计 @[test.log](${p1})`);
  ok(expanded.includes('[附件] test.log → uid-t/conv-123/test.log'), 'conversationBound 附件输出路径引用');
  ok(!expanded.includes('hello server copy'), 'conversationBound 附件不内联全文');
  const expandedLocal = await (proxy3 as any).expandFileReferences(`看 @[local.log](${p3})`);
  ok(expandedLocal.includes('hello server copy'), '未绑定附件保持内存内联（19 号链路不回归）');

  // ── 6. aisoc-api chatStream 请求体 attachments 字段 ──
  console.log('6) chatStream attachments 字段');
  calls.length = 0;
  const api = new AisocApi('/api');
  await api.chatStream('hi', { attachments: [{ name: 'test.log', path: 'uid-t/conv-123/test.log' }] });
  const chatCall = calls.find((c) => c.url.includes('/api/chat/stream'));
  ok(Array.isArray(chatCall?.body?.attachments) && chatCall.body.attachments[0]?.path === 'uid-t/conv-123/test.log', '带 attachments 时请求体包含该字段');
  calls.length = 0;
  await api.chatStream('hi', {});
  const chatCall2 = calls.find((c) => c.url.includes('/api/chat/stream'));
  ok(chatCall2?.body?.attachments === undefined, '不带时不出现 attachments 字段');

  // ── 7. AttachmentServerInfo ──
  console.log('7) AttachmentServerInfo');
  const info = await proxy.AttachmentServerInfo(p1);
  ok(info?.serverPath === 'uid-t/conv-123/test.log' && typeof info?.size === 'number', '已镜像附件返回 serverPath+size');
  ok((await proxy3.AttachmentServerInfo(p3)) === null, '未镜像附件返回 null');

  console.log(`\n通过 ${pass}，失败 ${fail}`);
  process.exit(fail > 0 ? 1 : 0);
}

main().catch((e) => { console.error(e); process.exit(1); });
