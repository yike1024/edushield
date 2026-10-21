// Run: tsx src/__tests__/aisoc-chat-stream-kind-frames.test.ts
// 针对 aisocApi.chatStream 帧解析器（src/lib/aisoc-api.ts flush）的回归测试。
//
// 背景（2026-09-28 抓流实证）：
// 任务意图消息经大脑 /api/chat/stream 接力到部件（pentest 等）后，部件（reasonix serve）
// 原生 SSE 是 {"kind": "...", ...} 包装格式，大脑原样转发。此前解析器只认裸键帧
// （{tool_result: ...} / {reasoning: ...}），导致：
//   1) tool_dispatch / tool_progress / tool_result 全部静默丢弃 → bash 卡片无输出；
//   2) {"kind":"reasoning","text":"..."} 被裸键 evt.text 检查误判成 text 帧 → 思考链混入正文；
//   3) {"kind":"notice","text":"Decision recorded..."} 同样误判成 text 污染回答。
// 本测试用真实抓包帧（缩短）锁定 kind 包装分支行为，同时覆盖裸键 07/10 协议不回归。

import { AisocApi } from "../lib/aisoc-api";
import { applyStreamEvent } from "../lib/aisocStreamItems";

let passed = 0;
let failed = 0;
function ok(cond: boolean, label: string) {
  if (cond) { passed++; console.log(`  ✅ ${label}`); }
  else { failed++; console.error(`  ❌ ${label}`); }
}

// 真实抓包帧（2026-09-28 pentest 任务流，字段结构原样保留、输出内容缩短）
const REAL_SSE = [
  'data: {"kind": "turn_started", "task_id": "T-TEST"}',
  // 16 号方案 B3（2026-10-09 实测，登录用户对话，首条 delta 前下发）
  'data: {"kind": "conversation", "id": "7ec4b602-3f1a-4c5d-9e8b-1a2b3c4d5e6f"}',
  'data: {"kind": "conversation_bound", "conversationId": "7ec4b602-3f1a-4c5d-9e8b-1a2b3c4d5e6f", "task_id": "T-TEST"}',
  'data: {"kind": "memory_retrieved", "entries": [{"id": "mem-001", "content": "测试服务器在 10.20.1.5，渗透任务优先打这里", "type": "fact", "importance": 90, "matchedBy": "keyword"}], "injected": true, "task_id": "T-TEST"}',
  'data: {"kind": "reasoning", "text": "用户", "task_id": "T-TEST"}',
  'data: {"kind": "text", "text": "我先按任务要求做信息收集", "task_id": "T-TEST"}',
  'data: {"kind": "tool_dispatch", "tool": {"id": "call_00_abc", "name": "bash", "args": "{\\"command\\": \\"whoami\\"}", "readOnly": false}, "task_id": "T-TEST"}',
  'data: {"kind": "tool_progress", "tool": {"id": "call_00_abc", "name": "", "output": "wangwei\\n", "readOnly": false}, "task_id": "T-TEST"}',
  'data: {"kind": "tool_result", "tool": {"id": "call_00_abc", "name": "bash", "args": "{\\"command\\": \\"whoami\\"}", "resolvedName": "bash", "output": "wangwei\\nLinux css-Server"}, "task_id": "T-TEST"}',
  'data: {"kind": "usage", "usage": {"promptTokens": 9512, "completionTokens": 474}, "task_id": "T-TEST"}',
  'data: {"kind": "notice", "text": "Decision recorded: allow_session", "code": "decision_receipt", "task_id": "T-TEST"}',
  'data: {"kind": "turn_phase", "text": "working", "phase": "working", "task_id": "T-TEST"}',
  'data: {"kind": "message", "text": "信息收集完成。", "reasoning": "用户要求收集信息。", "task_id": "T-TEST"}',
  'data: {"kind": "turn_done", "task_id": "T-TEST"}',
  // 裸键协议不回归：10 协议裸键 reasoning（大脑直聊路径）+ 07 协议 tool_call/answer
  'data: {"reasoning": "裸键思考", "task_id": "T-TEST"}',
  'data: {"tool_call": {"tool": "bash", "args": {"command": "ls"}}, "task_id": "T-TEST"}',
  'data: {"answer": {"text": "07 最终回答"}, "task_id": "T-TEST"}',
  'data: [DONE]',
].join("\n\n") + "\n\n";

async function main() {
  const encoder = new TextEncoder();
  (globalThis as { fetch?: unknown }).fetch = async () =>
    new Response(encoder.encode(REAL_SSE), { status: 200 });

  const api = new AisocApi("/api");
  const frames: Array<Record<string, unknown>> = [];
  let full = "";
  await api.chatStream("test", {
    passThrough: true,
    onDelta: (d) => { full += d; },
    onFrame: (f) => frames.push(f as unknown as Record<string, unknown>),
  });

  const countKind = (k: string) => frames.filter((f) => f.kind === k).length;
  const findKind = (k: string) => frames.find((f) => f.kind === k) as Record<string, unknown> | undefined;

  console.log("kind 包装帧解析（部件接力流）:");
  ok(countKind("tool_dispatch") === 1, "tool_dispatch 帧不再被丢弃");
  const td = findKind("tool_dispatch") as { tool?: Record<string, unknown> } | undefined;
  ok(td?.tool?.["name"] === "bash" && td?.tool?.["id"] === "call_00_abc", "tool_dispatch 保留完整 tool dict");
  ok(countKind("tool_progress") === 1, "tool_progress 帧不再被丢弃");
  ok(countKind("tool_result") === 1, "tool_result 帧不再被丢弃");
  const tr = findKind("tool_result") as { tool?: string; output?: string } | undefined;
  ok(tr?.tool === "bash" && (tr?.output ?? "").includes("wangwei"), "tool_result 归一化为 name + output");
  ok(countKind("turn_done") === 1, "kind 包装 turn_done 被识别");

  console.log("文本/推理分类不串线:");
  ok(countKind("reasoning") === 2, "kind 包装 reasoning + 裸键 reasoning 各归其位");
  const texts = frames.filter((f) => f.kind === "text").map((f) => String((f as { text?: string }).text ?? ""));
  ok(texts.length === 1 && texts[0] === "我先按任务要求做信息收集", "notice/turn_phase 的 text 不再泄漏成正文帧");
  ok(!full.includes("Decision recorded") && !full.includes("working"), "元数据帧不污染最终回答全文");
  ok(full.includes("我先按任务要求做信息收集") && full.includes("信息收集完成。"), "text + message 均计入全文");

  console.log("07 协议（pass_through=false）不回归:");
  ok(countKind("tool_call") === 1 && countKind("answer") === 1, "裸键 07 tool_call / answer 正常解析");

  console.log("16 号方案 B3 帧（登录用户对话，首条 delta 前）:");
  ok(countKind("conversation_bound") === 2, "conversation / conversation_bound 双帧归一为 conversation_bound");
  const cbFrames = frames.filter((f) => f.kind === "conversation_bound") as Array<{ conversationId?: string }>;
  ok(cbFrames.every((f) => f.conversationId === "7ec4b602-3f1a-4c5d-9e8b-1a2b3c4d5e6f"),
    "conversationId 提取正确（裸 conversation 帧用 id 字段兜底）");
  ok(countKind("memory_retrieved") === 1, "memory_retrieved 帧被解析");
  const mr = findKind("memory_retrieved") as { entries?: Array<Record<string, unknown>>; injected?: boolean } | undefined;
  ok(Array.isArray(mr?.entries) && mr.entries.length === 1, "entries 归一保留 1 条");
  const e0 = (mr?.entries?.[0] ?? {}) as Record<string, unknown>;
  ok(String(e0["content"]).includes("10.20.1.5") && e0["matchedBy"] === "keyword"
    && e0["importance"] === 90 && e0["type"] === "fact",
    "条目字段（content/matchedBy/importance/type）完整保留");
  ok(mr?.injected === true, "injected === true");
  ok(!full.includes("10.20.1.5"), "记忆帧不污染回答正文全文");

  // === reducer 层（aisocStreamItems.applyStreamEvent）：复现 bash 卡片 "{}" / 无输出 / 重复卡 ===
  console.log("reducer 卡片合并（透传真实帧序 partial → full → progress → result）:");
  let rItems: unknown[] = [];
  const feed = (ev: Record<string, unknown>) => {
    const next = applyStreamEvent([...rItems] as never[], ev as never, "T-TEST");
    if (next) rItems = next;
  };
  // 1) partial dispatch（仅 name，无 args）
  feed({ kind: "tool_dispatch", tool: { id: "call_x", name: "bash", partial: true, readOnly: false } });
  // 2) 同 id 完整 dispatch（带 args）
  feed({ kind: "tool_dispatch", tool: { id: "call_x", name: "bash", args: '{"command": "whoami"}', readOnly: false } });
  const toolItems = () => rItems.filter((i) => (i as { kind?: string }).kind === "tool") as Array<Record<string, unknown>>;
  let cards = toolItems();
  ok(cards.length === 1, "partial + full dispatch 合并为一张卡（不重复 push）");
  ok(cards[0]?.["args"] === '{"command": "whoami"}' && cards[0]?.["status"] === "running", "完整帧补入 args 且保持 running");
  // 3) 增量 output
  feed({ kind: "tool_result", tool: { id: "call_x", name: "bash", output: "wangwei\n", partial: true, readOnly: false } });
  cards = toolItems();
  ok(cards[0]?.["output"] === "wangwei\n" && cards[0]?.["status"] === "running", "progress 增量输出刷新卡片且保持 running");
  // 4) 最终 result
  feed({ kind: "tool_result", tool: { id: "call_x", name: "bash", args: '{"command": "whoami"}', output: "wangwei\n", readOnly: false } });
  cards = toolItems();
  ok(cards.length === 1 && cards[0]?.["status"] === "done" && cards[0]?.["output"] === "wangwei\n", "最终 result 置 done，仍是同一张卡");
  ok(cards[0]?.["args"] !== "{}" && cards[0]?.["args"] !== "", "卡片 args 不是 {} 也不是空");

  // 无 dispatch 的调用：progress 兜底建卡 → result 携带 args 补齐
  console.log("reducer 无 dispatch 调用（progress 兜底 + result 补 args）:");
  let r2: unknown[] = [];
  const feed2 = (ev: Record<string, unknown>) => {
    const next = applyStreamEvent([...r2] as never[], ev as never, "T-TEST");
    if (next) r2 = next;
  };
  feed2({ kind: "tool_result", tool: { id: "call_y", name: "bash", output: "partial-out", partial: true, readOnly: false } });
  feed2({ kind: "tool_result", tool: { id: "call_y", name: "bash", args: '{"command": "uname -a"}', output: "Linux host 6.8.0", readOnly: false } });
  const c2 = r2.filter((i) => (i as { kind?: string }).kind === "tool") as Array<Record<string, unknown>>;
  ok(c2.length === 1 && c2[0]?.["args"] === '{"command": "uname -a"}', "result 帧携带的 args 补齐到卡片");
  ok(c2[0]?.["output"] === "Linux host 6.8.0" && c2[0]?.["status"] === "done", "最终输出与 done 状态正确");

  console.log(`\n结果: ${passed} passed, ${failed} failed`);
  if (failed > 0) process.exit(1);
}

main().catch((e) => { console.error(e); process.exit(2); });
