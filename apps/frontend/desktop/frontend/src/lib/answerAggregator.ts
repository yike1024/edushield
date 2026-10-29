/**
 * reasonix answer 帧段落聚合器（纯函数，便于单测）。
 *
 * 背景（aisoc-docs/12-修复报告 + fetch 抓流实证）：
 * reasonix 输出"一段完整回答"时发送的 answer 帧序列为：
 *   增量帧 × N（相邻连续，拼接 = 完整段落）→ [tool_call 等帧] → 全量帧 × 1（= 增量拼接结果）
 * 若把每帧直接当作独立 message 发给 reducer：
 *   - 增量帧会把 assistant.text 覆盖成最后一片残句（如 " cookie:"、":"）；
 *   - tool_call 插在增量与全量之间，导致 assistant 不再是 items 末尾，
 *     全量帧只能 push 一条新 assistant —— 界面上出现"残句 + 完整句"并存的重复。
 *
 * 本聚合器把 answer 帧先累积成"段落"，满足以下任一条件才 emit 一次完整段落：
 *   1. 收到全量帧（text === 已累积的 pending）——段落自然完成；
 *   2. flushAnswer()：遇到明确的段落终结帧（tool_call / tool_result / turn_done 等）或流结束。
 * 上一段落刚 flush 后紧跟的全量重复帧（text === lastFlushed）会被丢弃。
 *
 * 该聚合发生在 webApiProxy 的 onFrame 层；reducer 侧不需要感知增量/全量的区别。
 */

export interface AnswerAggState {
  /** 当前段落已累积（增量帧拼接）但尚未 emit 的文本 */
  pending: string;
  /** 上次作为完整段落 emit 的文本，用于识别紧随其后的全量重复帧 */
  lastFlushed: string;
}

export interface AnswerAggResult {
  /** 需要 emit 的完整段落文本；null = 无需发事件 */
  emit: string | null;
  state: AnswerAggState;
}

export function emptyAnswerAgg(): AnswerAggState {
  return { pending: "", lastFlushed: "" };
}

/** answer 帧到来：增量累积 / 全量帧(==pending)完成段落 / 孤立全量帧(==lastFlushed)丢弃 */
export function answerAggOnAnswer(state: AnswerAggState, text: string): AnswerAggResult {
  if (!text) return { emit: null, state };
  if (state.pending === "") {
    // 段落起点：若与刚 flush 过的段落完全相同 → 全量重复帧，丢弃
    if (text === state.lastFlushed) return { emit: null, state };
    return { emit: null, state: { pending: text, lastFlushed: state.lastFlushed } };
  }
  if (text === state.pending) {
    // 全量帧：段落已在增量帧里拼完整（正常会被更早的终结帧 flush，此处兜底）
    return { emit: state.pending, state: { pending: "", lastFlushed: state.pending } };
  }
  // 增量帧：继续拼接
  return { emit: null, state: { pending: state.pending + text, lastFlushed: state.lastFlushed } };
}

/** 段落终结（非 answer 的终结帧 / 流结束）：把未完成的增量段落一次性 emit */
export function answerAggFlush(state: AnswerAggState): AnswerAggResult {
  if (!state.pending) return { emit: null, state };
  return { emit: state.pending, state: { pending: "", lastFlushed: state.pending } };
}
