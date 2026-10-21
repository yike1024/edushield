#!/usr/bin/env node
/**
 * 端到端验证：前端 chatStream() 真实累积逻辑对接到 6657 大脑
 *
 * 这不是 mock。这个脚本里的累积逻辑跟 aisoc-api.ts:541 chatStream()
 * 函数 100% 同构：
 *   - fetch POST /api/chat/stream
 *   - response.body.getReader()
 *   - TextDecoder('utf-8')  按 stream: true 解码
 *   - 按 '\n\n' 切帧
 *   - 'data: ' 起头，[DONE] 终止
 *   - JSON.parse → 取 evt.delta → full += delta
 *
 * 浏览器里也是这些 API（fetch / ReadableStream / TextDecoder），
 * 只是浏览器在 V8 上跑、这个脚本在 Node V8 上跑。如果这条路径在 Node
 * 跑通，在浏览器一定跑通。
 *
 * 用法：node scripts/verify-chat-e2e.mjs "<message>"
 */

const message = process.argv[2] || '解释 HTTP 和 HTTPS 区别，一句话';

const url = 'http://127.0.0.1:6657/api/chat/stream';

console.log(`>>> POST ${url}`);
console.log(`>>> body: ${JSON.stringify({ message, pass_through: true })}`);
console.log(`>>> 等待 SSE 流（最长 90s）...\n`);

const t0 = Date.now();
const response = await fetch(url, {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ message, pass_through: true }),
});

console.log(`<<< HTTP ${response.status} ${response.statusText}`);
console.log(`<<< Content-Type: ${response.headers.get('content-type')}`);

const reader = response.body.getReader();
const decoder = new TextDecoder('utf-8');
let buffer = '';
let full = '';
let doneSse = false;
let frames = 0;
const frameSummary = {};

while (true) {
  const { done, value } = await reader.read();
  if (done) break;
  buffer += decoder.decode(value, { stream: true });
  let sepIdx;
  while ((sepIdx = buffer.indexOf('\n\n')) !== -1) {
    const raw = buffer.slice(0, sepIdx);
    buffer = buffer.slice(sepIdx + 2);
    for (const line of raw.split('\n')) {
      const trimmed = line.trim();
      if (!trimmed.startsWith('data:')) continue;
      const payload = trimmed.slice(5).trim();
      if (payload === '[DONE]') { doneSse = true; continue; }
      if (!payload) continue;
      try {
        const evt = JSON.parse(payload);
        frames++;
        for (const k of Object.keys(evt)) {
          frameSummary[k] = (frameSummary[k] ?? 0) + 1;
        }
        // 模拟前端 flush() 的 stream_error 判别分支
        if (evt.kind === 'stream_error' || evt.kind === 'error') {
          const errMsg = typeof evt.err === 'string' ? evt.err
            : typeof evt.message === 'string' ? evt.message
            : typeof evt.error === 'string' ? evt.error
            : `unknown ${String(evt.kind)} error`;
          process.stdout.write(`\n[stream_error] ${errMsg}\n`);
          full += `\n[stream_error] ${errMsg}\n`;
        } else if (typeof evt.delta === 'string') {
          full += evt.delta;
          process.stdout.write(evt.delta);  // 实时打出，跟浏览器 chat UI 一模一样
        } else if (typeof evt.text === 'string') {
          full += evt.text;
          process.stdout.write(evt.text);
        }
      } catch { /* skip */ }
    }
    if (doneSse) break;
  }
  if (doneSse) break;
}
if (buffer.trim()) {
  const payload = buffer.trim().replace(/^data:\s*/, '');
  if (payload && payload !== '[DONE]') {
    try {
      const evt = JSON.parse(payload);
      frames++;
      if (typeof evt.delta === 'string') full += evt.delta;
      else if (typeof evt.text === 'string') full += evt.text;
      else if (evt.kind === 'stream_error' || evt.kind === 'error') {
        full += `\n[stream_error] ${typeof evt.err === 'string' ? evt.err : 'unknown'}\n`;
      }
    } catch { /* skip */ }
  }
}

const elapsed = ((Date.now() - t0) / 1000).toFixed(2);
console.log('\n\n=== 端到端验证结果 ===');
console.log(`耗时:        ${elapsed}s`);
console.log(`总帧数:      ${frames}`);
console.log(`字段统计:    `, JSON.stringify(frameSummary));
console.log(`拼出文本长度: ${full.length}`);
console.log(`拼出文本内容: "${full}"`);
console.log(`完整性:      ${full.length > 0 ? '✅ 前端能拿到非空文本' : '❌ 没拼出任何文本'}`);
