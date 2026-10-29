// Run: tsx src/__tests__/answer-aggregator.test.ts
// answerAggregator 段落聚合 + 端到端模拟（webApiProxy 帧映射 → 聚合 → AisocDashboard reducer）。
//
// 背景（aisoc-docs/12-修复报告-20260903.md + fetch 抓流实证）：
// reasonix 输出一段完整回答 = "增量 N 帧（相邻连续，拼接=完整段）+ 1 全量帧（=增量拼接）"，
// 且 tool_call 帧常插在增量与全量之间。若不聚合：
//   - 增量帧把 assistant.text 覆盖成残句（如 " cookie:"、":"），tool_call 插入后冻结；
//   - 全量帧因 items 末尾已是 tool 卡而 push 一条新 assistant → "残句 + 完整句"重复渲染。

import { answerAggOnAnswer, answerAggFlush, emptyAnswerAgg, type AnswerAggState } from "../lib/answerAggregator";
import { applyStreamEvent } from "../lib/aisocStreamItems";
import type { Item } from "../lib/useController";

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

// ---- fetch 实证数据 ----
const P1 = "SECRET_KEY 未在环境。手写 itsdangerous 签名验证,用候选密钥(含平台其它题用过的 you-will-never-guess)检验 cookie:";
const P1_CHUNKS = ["SEC", "RET_KEY 未", "在环境", "。", "手写", " its", "danger", "ous 签名验证,用候选密钥(含平台", "其它", "题用", "过的", " you-will-never-guess)", "检验", " cookie:"];
const P2 = "字典爆破失败。尝试其它途径:/proc/self/fd 枚举与 /app 下无扩展名文件:";
const P2_CHUNKS = ["字典", "爆破", "失败。尝试其它", "途径:/", "proc", "/self/fd 枚举与 /app 下", "无扩展名文件", ":"];

console.log("\nanswer aggregator — 段落聚合 + 去重");

// ---- 1. 纯聚合器：增量累积，终结帧 flush 一次完整段 ----
{
  let s = emptyAnswerAgg();
  const emits: string[] = [];
  for (const c of P1_CHUNKS) {
    const r = answerAggOnAnswer(s, c);
    s = r.state;
    if (r.emit) emits.push(r.emit);
  }
  // 终结帧（tool_call 等）→ flush
  const r = answerAggFlush(s);
  s = r.state;
  if (r.emit) emits.push(r.emit);
  ok(emits.length === 1 && emits[0] === P1, `增量 ${P1_CHUNKS.length} 帧 + 终结帧 → 只 emit 一次完整段（实际 ${emits.length} 次）`);
  ok(s.pending === "", "flush 后 pending 清空");
}

// ---- 2. 全量帧（==pending）兜底完成段落，不产生第二次 emit ----
{
  let s = emptyAnswerAgg();
  const emits: string[] = [];
  for (const c of P1_CHUNKS.slice(0, 3)) {
    const r = answerAggOnAnswer(s, c);
    s = r.state;
    if (r.emit) emits.push(r.emit);
  }
  const full = P1_CHUNKS.slice(0, 3).join("");
  const r = answerAggOnAnswer(s, full); // 全量帧 == pending
  s = r.state;
  if (r.emit) emits.push(r.emit);
  ok(r.emit === full && emits.length === 1, `全量帧命中 pending → emit 一次（实际 emits=${JSON.stringify(emits)}）`);
  ok(s.pending === "" && s.lastFlushed === full, "全量帧后 pending 清空、lastFlushed 记录");
}

// ---- 3. 孤立全量帧（上一段落刚 flush，无新增量）→ 丢弃 ----
{
  let s: AnswerAggState = { pending: "", lastFlushed: P1 };
  const r = answerAggOnAnswer(s, P1); // 与 lastFlushed 相同 → 全量重复帧
  ok(r.emit === null && r.state.pending === "", `孤立全量重复帧被丢弃（emit=${r.emit}）`);
}

// ---- 4. flush 空状态 → 不 emit ----
{
  const r = answerAggFlush(emptyAnswerAgg());
  ok(r.emit === null, "空状态 flush 不 emit");
}

// ---- 5. 端到端模拟 fetch：帧 → 聚合 → reducer，最终 items 无残句、无重复 ----
{
  // 按 webApiProxy 语义编排：终结帧（tool_call/tool_result）先 flush，再处理自身事件
  const frameSeq: Array<{ kind: "answer"; text: string } | { kind: "tool_call" } | { kind: "tool_result" }> = [
    ...P1_CHUNKS.map((text) => ({ kind: "answer" as const, text })),
    { kind: "tool_call" },
    { kind: "answer", text: P1 }, // 全量帧 1（应被丢弃）
    { kind: "tool_call" },
    { kind: "tool_result" },
    ...P2_CHUNKS.map((text) => ({ kind: "answer" as const, text })),
    { kind: "tool_call" },
    { kind: "answer", text: P2 }, // 全量帧 2（应被丢弃）
    { kind: "tool_call" },
  ];

  let agg = emptyAnswerAgg();
  let items: Item[] = [];
  let toolCounter = 0;
  const apply = (ev: Parameters<typeof applyStreamEvent>[1]) => {
    const r = applyStreamEvent([...items], ev, "T1");
    if (r !== null) items = r;
  };
  for (const f of frameSeq) {
    if (f.kind === "answer") {
      const r = answerAggOnAnswer(agg, f.text);
      agg = r.state;
      if (r.emit) apply({ kind: "message", text: r.emit, tabId: "T1" });
    } else {
      const r = answerAggFlush(agg); // webApiProxy.onFrame 入口对终结帧 flush
      agg = r.state;
      if (r.emit) apply({ kind: "message", text: r.emit, tabId: "T1" });
      if (f.kind === "tool_call") {
        toolCounter += 1;
        apply({ kind: "tool_dispatch", tool: { id: `t${toolCounter}`, name: "bash", readOnly: false }, tabId: "T1" });
      } else {
        apply({ kind: "tool_result", tool: { id: `t${toolCounter}`, name: "bash", output: "", readOnly: false }, tabId: "T1" });
      }
    }
  }
  // 流结束兜底 flush
  const r = answerAggFlush(agg);
  if (r.emit) apply({ kind: "message", text: r.emit, tabId: "T1" });

  const ats = items.filter((i) => i.kind === "assistant").map((i) => (i.kind === "assistant" ? i.text : ""));
  const fulls = ats.filter((t) => t === P1 || t === P2);
  ok(ats.length === 2, `最终只有 2 条 assistant（实际 ${ats.length}）`);
  ok(fulls.length === 2, `两段完整文本各出现一次（实际 ${fulls.length}）`);
  ok(!ats.some((t) => t !== P1 && t !== P2), `无残句 assistant（实际 ${JSON.stringify(ats.map((t) => t.slice(0, 20)))}）`);
  ok(new Set(ats).size === ats.length, "assistant 文本互不重复");
  const toolCount = items.filter((i) => i.kind === "tool").length;
  ok(toolCount === 4, `tool 卡保留 4 张（fetch 实证 4 次 tool_call）（实际 ${toolCount}）`);
}

console.log(`\n${passed} passed, ${failed} failed`);
if (failed > 0) process.exit(1);
