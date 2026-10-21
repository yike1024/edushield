#!/usr/bin/env node
/**
 * 一致性对照：raw SSE 后端输出 vs 前端 chatStream flush + webApiProxy onFrame switch 全链路模拟
 *
 * 流程：
 *   1. 读 raw SSE 文件（curl 抓的 /api/chat/stream 输出）
 *   2. 逐帧解析，按前端 aisoc-api.ts:601 flush() 的判别逻辑识别 ChatStreamFrame.kind
 *   3. 再按前端 webApiProxy.ts:744 onFrame switch 的逻辑映射到 reducer event
 *   4. 列出三列对照：idx / 后端原始字段 / 前端识别 / 前端 emit 事件
 *   5. 不一致统计：前端识别到 kind 但 switch 无 case（数据丢）、前端识别但 emit 缺失
 *
 * 用法：node scripts/verify-parity.mjs <raw-sse-file>
 * 例：  node scripts/verify-parity.mjs /tmp/sse-passthrough.raw
 */

import { readFileSync } from 'node:fs';

const file = process.argv[2];
if (!file) {
  console.error('用法：node scripts/verify-parity.mjs <raw-sse-file>');
  process.exit(1);
}

const raw = readFileSync(file, 'utf8');

// ============================================================
// 模拟 aisoc-api.ts:601 flush() 判别（同构代码，逐行镜像）
// ============================================================
function isObject(v) {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}

function classifyFrame(evt) {
  // === 10 协议透传模式独有顶层字段（reasonix 原样事件）===
  if (evt.turn_started !== undefined) {
    return { kind: 'turn_started', task_id: typeof evt.task_id === 'string' ? evt.task_id : undefined };
  }
  if (evt.turn_done !== undefined) {
    return { kind: 'turn_done', task_id: typeof evt.task_id === 'string' ? evt.task_id : undefined };
  }
  if (isObject(evt.memory_compiler_stats)) {
    const mcs = evt.memory_compiler_stats;
    const mcsBody = isObject(mcs.memoryCompiler) ? mcs.memoryCompiler : mcs;
    return { kind: 'memory_compiler_stats', memoryCompiler: mcsBody, task_id: typeof evt.task_id === 'string' ? evt.task_id : undefined };
  }
  if (isObject(evt.usage)) {
    return { kind: 'usage', usage: evt.usage, task_id: typeof evt.task_id === 'string' ? evt.task_id : undefined };
  }
  if (typeof evt.delta === 'string') {
    return { kind: 'delta', delta: evt.delta, task_id: typeof evt.task_id === 'string' ? evt.task_id : undefined };
  }
  if (typeof evt.text === 'string') {
    return { kind: 'text', text: evt.text, task_id: typeof evt.task_id === 'string' ? evt.task_id : undefined };
  }
  if (typeof evt.thinking === 'string') {
    return { kind: 'thinking', thinking: evt.thinking, task_id: typeof evt.task_id === 'string' ? evt.task_id : undefined };
  }
  if (typeof evt.reasoning === 'string') {
    return { kind: 'reasoning', text: evt.reasoning, task_id: typeof evt.task_id === 'string' ? evt.task_id : undefined };
  }
  if (isObject(evt.tool_call)) {
    const tc = evt.tool_call;
    let toolName = '';
    if (typeof tc.tool === 'string') toolName = tc.tool;
    else if (isObject(tc.tool)) {
      const tObj = tc.tool;
      toolName = typeof tObj.name === 'string' ? tObj.name : '';
      if (!toolName && typeof tObj.id === 'string') toolName = tObj.id;
    }
    if (!toolName) toolName = 'unknown';
    return { kind: 'tool_call', tool: toolName, args: tc.args ?? {}, task_id: typeof evt.task_id === 'string' ? evt.task_id : undefined };
  }
  if (isObject(evt.tool_dispatch)) {
    const td = evt.tool_dispatch;
    const tdTool = isObject(td.tool) ? td.tool : td;
    return { kind: 'tool_dispatch', tool: tdTool, task_id: typeof evt.task_id === 'string' ? evt.task_id : undefined };
  }
  if (isObject(evt.tool_result)) {
    const tr = evt.tool_result;
    let trToolName = '';
    if (typeof tr.tool === 'string') trToolName = tr.tool;
    else if (isObject(tr.tool)) {
      const tObj = tr.tool;
      trToolName = typeof tObj.name === 'string' ? tObj.name : '';
      if (!trToolName && typeof tObj.id === 'string') trToolName = tObj.id;
    }
    if (!trToolName) trToolName = 'unknown';
    return { kind: 'tool_result', tool: trToolName, output: typeof tr.output === 'string' ? tr.output : '', exit_code: typeof tr.exit_code === 'number' ? tr.exit_code : undefined, partial: tr.partial === true, task_id: typeof evt.task_id === 'string' ? evt.task_id : undefined };
  }
  if (isObject(evt.tool_progress)) {
    const tp = evt.tool_progress;
    const tpTool = isObject(tp.tool) ? tp.tool : {};
    const tpOutput = typeof tpTool.output === 'string' ? tpTool.output : (typeof tp.output === 'string' ? tp.output : '');
    return { kind: 'tool_progress', tool: tpTool, output: tpOutput, partial: true, task_id: typeof evt.task_id === 'string' ? evt.task_id : undefined };
  }
  if (typeof evt.stage_start === 'string') {
    return { kind: 'stage_start', stage: evt.stage_start, task_id: typeof evt.task_id === 'string' ? evt.task_id : undefined };
  }
  if (isObject(evt.stage_finished) && typeof evt.stage_finished.stage === 'string') {
    const sf = evt.stage_finished;
    return { kind: 'stage_finished', stage: sf.stage, ok: sf.ok !== false, task_id: typeof evt.task_id === 'string' ? evt.task_id : undefined };
  }
  if (typeof evt.task_id === 'string' && typeof evt.domain === 'string' && evt.delta === undefined) {
    return { kind: 'task_created', task_id: evt.task_id, domain: evt.domain };
  }
  if (isObject(evt.answer) && typeof evt.answer.text === 'string') {
    return { kind: 'answer', text: evt.answer.text, task_id: typeof evt.task_id === 'string' ? evt.task_id : undefined };
  }
  if (isObject(evt.message) && typeof evt.message.text === 'string') {
    const m = evt.message;
    return { kind: 'message', text: m.text, reasoning: typeof m.reasoning === 'string' ? m.reasoning : undefined, task_id: typeof evt.task_id === 'string' ? evt.task_id : undefined };
  }
  // 07 协议嵌套 report_ready
  if (isObject(evt.report_ready)) {
    const rr = evt.report_ready;
    const rrTaskId = typeof rr.task_id === 'string' ? rr.task_id : taskId;
    const rrUrl = typeof rr.report_url === 'string' ? rr.report_url : '';
    return { kind: 'report_ready', task_id: rrTaskId, report_url: rrUrl };
  }
  if (typeof evt.task_id === 'string' && typeof evt.report_url === 'string') {
    return { kind: 'report_ready', task_id: evt.task_id, report_url: evt.report_url };
  }
  // 07 协议嵌套结构：{error: {code, message, ...}, task_id}
  if (isObject(evt.error)) {
    const errObj = evt.error;
    let errMsg = '';
    if (typeof errObj.message === 'string') errMsg = errObj.message;
    else if (typeof errObj.error === 'string') errMsg = errObj.error;
    else if (typeof errObj.err === 'string') errMsg = errObj.err;
    else if (typeof errObj.code === 'string') errMsg = errObj.code;
    else errMsg = JSON.stringify(errObj).slice(0, 200);
    const errTaskId = typeof evt.task_id === 'string' ? evt.task_id : undefined;
    return { kind: 'stream_error', err: errMsg, task_id: errTaskId };
  }
  if (evt.kind === 'stream_error' || evt.kind === 'error') {
    let errMsg = '';
    if (typeof evt.err === 'string') errMsg = evt.err;
    else if (typeof evt.message === 'string') errMsg = evt.message;
    else if (typeof evt.error === 'string') errMsg = evt.error;
    else errMsg = `unknown ${String(evt.kind)} error`;
    return { kind: 'stream_error', err: errMsg, task_id: typeof evt.task_id === 'string' ? evt.task_id : undefined };
  }
  return { kind: 'UNKNOWN', raw: JSON.stringify(evt).slice(0, 80) };
}

// ============================================================
// 模拟 webApiProxy.ts:744 onFrame switch（逐 case 镜像）
// 列出 reducer event kind（前端实际 emit 给 reducer 的事件）
// ============================================================
function emitReducerEvent(frame) {
  switch (frame.kind) {
    case 'delta':
      // delta 已在 onDelta 里走 typewriter，不再重复 emit
      return null;
    case 'thinking':
      return [{ kind: 'reasoning', reasoning: frame.thinking }];
    case 'tool_call': {
      // 简化版（不计 toolCallCounter 细节）：emit tool_dispatch
      return [{ kind: 'tool_dispatch', tool: { name: frame.tool, args: frame.args } }];
    }
    case 'tool_result':
      return [{ kind: 'tool_result', tool: { name: frame.tool, output: frame.output } }];
    case 'stage_start':
      return [{ kind: 'phase', text: `[stage] ${frame.stage} 开始` }];
    case 'stage_finished':
      return [{ kind: 'phase', text: `[stage] ${frame.stage} ${frame.ok ? '完成' : '失败'}` }];
    case 'task_created':
      return [{ kind: 'notice', level: 'info', text: `任务 ${frame.task_id} 已下发到 ${frame.domain}` }];
    case 'answer':
      return frame.text ? [{ kind: 'message', text: frame.text }] : [];
    case 'report_ready':
      return [{ kind: 'notice', level: 'info', text: `报告已生成 /api/tasks/${frame.task_id}/export` }];
    case 'reasoning':
      return frame.text ? [{ kind: 'reasoning', reasoning: frame.text }] : [];
    case 'tool_dispatch': {
      const tdTool = isObject(frame.tool) ? frame.tool : {};
      const tdName = typeof tdTool.name === 'string' && tdTool.name ? tdTool.name : 'unknown';
      return [{ kind: 'tool_dispatch', tool: { name: tdName, args: tdTool.args } }];
    }
    case 'tool_progress': {
      const tpTool = isObject(frame.tool) ? frame.tool : {};
      const tpName = typeof tpTool.name === 'string' && tpTool.name ? tpTool.name : 'unknown';
      return [{ kind: 'tool_result', tool: { name: tpName, output: frame.output ?? '', partial: true } }];
    }
    case 'message': {
      const evts = [];
      if (frame.text) evts.push({ kind: 'message', text: frame.text });
      if (frame.reasoning) evts.push({ kind: 'reasoning', reasoning: frame.reasoning });
      return evts;
    }
    case 'usage': {
      const u = isObject(frame.usage) ? frame.usage : {};
      const prompt = typeof u.prompt_tokens === 'number' ? u.prompt_tokens : 0;
      const completion = typeof u.completion_tokens === 'number' ? u.completion_tokens : 0;
      const total = typeof u.total_tokens === 'number' ? u.total_tokens : (prompt + completion);
      const details = u.completion_tokens_details;
      const rTokens = isObject(details) && typeof details.reasoning_tokens === 'number' ? details.reasoning_tokens : 0;
      const tokenText = rTokens > 0
        ? `token 用量：prompt ${prompt} / completion ${completion} (含推理 ${rTokens}) / 总计 ${total}`
        : `token 用量：prompt ${prompt} / completion ${completion} / 总计 ${total}`;
      return [{ kind: 'notice', level: 'info', text: tokenText }];
    }
    case 'memory_compiler_stats':
      return [{ kind: 'notice', level: 'info', text: `记忆编译器统计：${JSON.stringify(frame.memoryCompiler)}` }];
    case 'stream_error':
      return [{ kind: 'text', text: `[stream_error] ${frame.err}`, level: 'warn' }];
    case 'text':
      // 走 onDelta typewriter（flush() 内部已调 onDelta?.(evt.text)）—— 不是 switch 走
      return null;
    case 'turn_started':
      return null;  // webApiProxy:613 主动 emit，不靠 onFrame
    case 'turn_done':
      return null;  // emitTurnDoneSafe 兜底，不靠 onFrame
    case 'UNKNOWN':
      return [];  // 数据丢失
    default:
      return [];
  }
}

// ============================================================
// 解析 raw SSE → 帧列表
// ============================================================
const frames = [];
const events = [];
let buffer = '';

for (const line of raw.split('\n')) {
  const trimmed = line.trim();
  if (trimmed.startsWith('data:')) {
    buffer += trimmed.slice(5).trim() + '\n';
    if (buffer.trim().endsWith('}') || buffer.trim() === '[DONE]') {
      const payload = buffer.trim();
      buffer = '';
      if (payload === '[DONE]') {
        events.push({ kind: '[DONE]' });
        continue;
      }
      try {
        const evt = JSON.parse(payload);
        const frame = classifyFrame(evt);
        const reducerEvents = emitReducerEvent(frame);
        frames.push({ evt, frame, reducerEvents });
      } catch { /* skip */ }
    }
  }
}

// ============================================================
// 对照输出
// ============================================================
console.log(`\n=== 一致性对照：raw SSE vs 前端全链路（${frames.length} 帧）===\n`);

let unknownCount = 0;
let droppedCount = 0;
const counts = { backend: {}, frontend_kind: {}, reducer_event: {} };

for (let i = 0; i < frames.length; i++) {
  const { evt, frame, reducerEvents } = frames[i];
  // 后端发出什么 kind
  const backendKeys = Object.keys(evt).filter(k => k !== 'task_id');
  const backendSummary = backendKeys.map(k => {
    const v = evt[k];
    if (typeof v === 'string') return `${k}="${v.length > 30 ? v.slice(0, 30) + '…' : v}"`;
    if (typeof v === 'object' && v !== null) return `${k}={…}`;
    return `${k}=${v}`;
  }).join(', ');
  // 前端识别 + reducer 事件
  const feSummary = reducerEvents === null
    ? '(onDelta 走 typewriter)'
    : reducerEvents.length === 0
      ? (frame.kind === 'UNKNOWN' ? '❌ UNKNOWN — 数据丢失' : '⚠️ 识别了但 switch 无 case')
      : reducerEvents.map(e => {
        if (e.kind === 'reasoning') return `reasoning(reasoning="${(e.reasoning ?? '').slice(0, 20)}…")`;
        if (e.kind === 'tool_dispatch') return `tool_dispatch(name=${e.tool.name})`;
        if (e.kind === 'tool_result') return `tool_result(name=${e.tool.name}${e.tool.partial ? ',partial=true' : ''})`;
        if (e.kind === 'phase') return `phase(text="${e.text}")`;
        if (e.kind === 'notice') return `notice(text="${e.text.slice(0, 30)}…")`;
        if (e.kind === 'message') return `message(text="${(e.text ?? '').slice(0, 20)}…")`;
        if (e.kind === 'text') return `text(text="${e.text}",level=${e.level})`;
        return e.kind;
      }).join(' + ');

  counts.backend[Object.keys(evt).filter(k => k !== 'task_id')[0]] = (counts.backend[Object.keys(evt).filter(k => k !== 'task_id')[0]] ?? 0) + 1;
  counts.frontend_kind[frame.kind] = (counts.frontend_kind[frame.kind] ?? 0) + 1;
  for (const e of (reducerEvents ?? [])) {
    counts.reducer_event[e.kind] = (counts.reducer_event[e.kind] ?? 0) + 1;
  }

  if (frame.kind === 'UNKNOWN') unknownCount++;
  if (frame.kind !== 'UNKNOWN' && reducerEvents !== null && reducerEvents.length === 0) droppedCount++;

  console.log(`[#${String(i + 1).padStart(4, '0')}] 后端:[${backendSummary}]`);
  console.log(`        识别:kind=${frame.kind}`);
  console.log(`        前端:${feSummary}\n`);
}

console.log(`\n=== 一致性统计 ===`);
console.log(`总帧数:               ${frames.length}`);
console.log(`UNKNOWN 帧数:         ${unknownCount}  ${unknownCount === 0 ? '✅' : '❌ 前端未识'}`);
console.log(`数据丢失帧数:         ${droppedCount}  ${droppedCount === 0 ? '✅' : '❌ 识别了但 switch 无 case'}`);
console.log(`[DONE] 终止帧:        ${events.filter(e => e.kind === '[DONE]').length}`);
console.log(`\n后端顶层字段统计:`);
console.log('  ', JSON.stringify(counts.backend));
console.log(`前端 ChatStreamFrame.kind 统计:`);
console.log('  ', JSON.stringify(counts.frontend_kind));
console.log(`前端 reducer event 统计:`);
console.log('  ', JSON.stringify(counts.reducer_event));

// === 兑底交叉检查：后端总帧数 = 前端总触达事件 ===
// - onFrame switch 各 case 返回的 reducer event
// - delta / text 走 onDelta typewriter（未走 switch）
// - turn_started/turn_done webApiProxy 主动 emit（未走 switch）
let frontendReachedCount = 0;
let typewriterCount = 0;
let proactiveEmitCount = 0;
for (const { frame, reducerEvents } of frames) {
  if (reducerEvents === null) {
    if (frame.kind === 'delta' || frame.kind === 'text') typewriterCount++;
    else if (frame.kind === 'turn_started' || frame.kind === 'turn_done') proactiveEmitCount++;
  } else {
    frontendReachedCount += reducerEvents.length;
  }
}
console.log(`\n兑底交叉检查（后端1帧 = 前端 ≥1个触达事件）:`);
console.log(`  后端总帧数:           ${frames.length}`);
console.log(`  前端触达事件总数:      ${frontendReachedCount + typewriterCount + proactiveEmitCount}`);
console.log(`    - reducer event:    ${frontendReachedCount}`);
console.log(`    - typewriter (delta/text): ${typewriterCount}`);
console.log(`    - 主动 emit (turn_started/turn_done): ${proactiveEmitCount}`);
const consistent = frames.length === (frontendReachedCount + typewriterCount + proactiveEmitCount);
console.log(`  一致性:               ${consistent ? '✅ 后端帧数 = 前端触达事件总数（完全一致）' : '❌ 不一致'}`);