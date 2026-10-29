// Run: tsx src/__tests__/aisoc-stream-items.test.ts
// 针对 AisocDashboard 流式 items reducer（src/lib/aisocStreamItems.ts）的回归测试。
//
// 背景（见 aisoc-docs/12-修复报告-20260903.md + fetch 抓流）：
// reasonix 输出一段文字会"先发 N 个增量 answer 帧、再发 1 帧全量 answer 帧"（全量 = N 帧拼接），
// webApiProxy 把 answer 帧转成 { kind:'message', text } 事件喂给本 reducer。
// 曾尝试在 webApiProxy 用"上一帧 text 完全相同则跳过"去重，抓流证实增量帧与全量帧必然不同
// （全量 = 增量拼接），该条件永不触发，属死代码已移除 —— 真正防重复靠本 reducer：
//   1) case 'message' 是覆盖式：只更新最后一条 assistant 的 text，文本不会累积；
//   2) tool_result.output 与 assistant.text 相同内容时双向倒查清理（tool 卡独享）。

import { applyStreamEvent } from "../lib/aisocStreamItems";
import type { Item } from "../lib/useController";
import type { WireEvent } from "../lib/types";

let passed = 0;
let failed = 0;

function ok(cond: boolean, label: string) {
  if (cond) {
    process.stdout.write(`  PASS  ${label}\n`);
    passed += 1;
  } else {
    process.stdout.write(`  FAIL  ${label}\n`);
    failed += 1;
  }
}

// ---- 事件构造 helper（kind 与 webApiProxy.emitEvent 对齐）----
const msg = (text: string): WireEvent => ({ kind: "message", text, tabId: "T1" });
const txt = (text: string): WireEvent => ({ kind: "text", text, tabId: "T1" });
const toolDispatch = (id: string): WireEvent => ({
  kind: "tool_dispatch",
  tool: { id, name: "bash", readOnly: false },
  tabId: "T1",
});
const toolResult = (id: string, output: string): WireEvent => ({
  kind: "tool_result",
  tool: { id, name: "bash", output, readOnly: false },
  tabId: "T1",
});

/** 按帧顺序喂给 reducer（每帧传拷贝，与 AisocDashboard.applyWireEvent 一致） */
function reduce(seq: WireEvent[], taskId = "T1"): Item[] {
  let items: Item[] = [];
  for (const ev of seq) {
    const r = applyStreamEvent([...items], ev, taskId);
    if (r !== null) items = r;
  }
  return items;
}

const assistantTexts = (items: Item[]) =>
  items.filter((i) => i.kind === "assistant").map((i) => (i.kind === "assistant" ? i.text : ""));
const toolOutputs = (items: Item[]) =>
  items.filter((i) => i.kind === "tool").map((i) => (i.kind === "tool" ? i.output ?? "" : ""));

console.log("\naisoc stream items — answer 增量+全量 / tool 同文本去重");

// ---- 场景 1：fetch #16-24 的增量+全量 answer 帧（覆盖式 → 最终只一条 assistant，无重复文本）----
{
  const FULL = "字典爆破失败。尝试其它途径:/proc/self/fd 枚举与 /app 下无扩展名文件:";
  const items = reduce([
    msg("字典"),
    msg("爆破"),
    msg("失败。尝试其它"),
    msg("途径:/"),
    msg("proc"),
    msg("/self/fd 枚举与 /app 下"),
    msg("无扩展名文件"),
    msg(":"),
    msg(FULL), // 全量帧 = 上面 8 段增量拼接
  ]);
  const ats = assistantTexts(items);
  ok(ats.length === 1, `增量+全量后 assistant 只有 1 条（实际 ${ats.length}）`);
  ok(ats[0] === FULL, `assistant.text 保留全量帧（实际 ${JSON.stringify(ats[0])}）`);
  ok(new Set(ats).size === ats.length, "assistant 文本互不重复");
}

// ---- 场景 2：text 打字机增量 + message 全量（先 text 流式、再 answer 全量覆盖）----
{
  const items = reduce([txt("HELLO"), txt(" world"), msg("HELLO world")]);
  const ats = assistantTexts(items);
  const a = items.find((i) => i.kind === "assistant");
  ok(ats.length === 1 && ats[0] === "HELLO world", "text 增量后 message 全量只保留一条完整文本");
  ok(a?.kind === "assistant" && a.streaming === false, "message 覆盖后 streaming 关闭");
}

// ---- 场景 3：实测顺序 answer 全量(assistant) → tool_result 同文本 → assistant 被删（tool 独享）----
{
  const OUT = "SAME CONTENT 既在 assistant 又进 tool output";
  const items = reduce([msg(OUT), toolDispatch("t1"), toolResult("t1", OUT)]);
  const ats = assistantTexts(items);
  const tos = toolOutputs(items);
  ok(ats.length === 0, `同文本 tool_result 落地后 assistant 被删（实际 ${ats.length} 条）`);
  ok(tos.length === 1 && tos[0] === OUT, "该文本只由 tool 卡持有");
  const occurrences = items.reduce(
    (n, i) =>
      n + (i.kind === "assistant" && i.text === OUT ? 1 : 0) + (i.kind === "tool" && i.output === OUT ? 1 : 0),
    0,
  );
  ok(occurrences === 1, `整个 items 中该文本只出现一次（实际 ${occurrences} 次）`);
}

// ---- 场景 4：message 到达时最近 tool.output 相同 → message 被跳过（v1 语义仍生效）----
{
  const OUT = "yyy";
  const items = reduce([toolDispatch("t1"), toolResult("t1", OUT), msg(OUT)]);
  const ats = assistantTexts(items);
  ok(ats.length === 0, `与最近 tool.output 相同的 message 被跳过（实际 assistant ${ats.length} 条）`);
  ok(toolOutputs(items).length === 1, "文本仍在 tool 卡");
}

// ---- 场景 5：v1 失效回归 —— message 先到(tool 未建)建立 assistant，tool_result 同文本兜底删除 ----
{
  const OUT = "xxx";
  const items = reduce([msg(OUT), toolDispatch("t1"), toolResult("t1", OUT)]);
  const ats = assistantTexts(items);
  ok(ats.length === 0, `v2 兜底：tool_result 倒查删掉同文本 assistant（实际 ${ats.length} 条）`);
  const occurrences = items.reduce(
    (n, i) =>
      n + (i.kind === "assistant" && i.text === OUT ? 1 : 0) + (i.kind === "tool" && i.output === OUT ? 1 : 0),
    0,
  );
  ok(occurrences === 1, `文本全仓唯一（tool 卡）（实际 ${occurrences} 次）`);
}

// ---- 场景 6：未消费 kind → 返回 null，items 不变（组件侧保持原 state、不 bump）----
{
  const items: Item[] = [];
  const r = applyStreamEvent(items, { kind: "turn_started" }, "T1");
  ok(r === null, "turn_started 等未消费 kind 返回 null");
  ok(assistantTexts(items).length === 0, "items 未被污染");
}

console.log(`\n${passed} passed, ${failed} failed`);
if (failed > 0) process.exit(1);
