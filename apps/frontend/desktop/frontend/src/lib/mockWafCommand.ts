/**
 * T2-2 处置回注（模拟）—— 把 TIR 处置预案 steps 汇总为可下发的封禁指令 JSON。
 *
 * 定位：纯函数转换（预案 → 指令），不含任何网络 / 设备 / 审批逻辑。
 * 安全约定（改进计划书 §6-#4 例外条款 / §7-Q4）：
 *   - 产出恒带 `simulated: true`，配合 UI 的"模拟"标注，避免演示造假争议；
 *   - 本模块只生成指令文本；真正的下发由前端在人工点"批准"后调用 8788 的模拟适配路由。
 */

/** 单条封禁 / 处置动作 */
export interface MockWafAction {
  /** 动作类型：按目标形态与预案措辞推断 */
  kind: 'block_ip' | 'block_domain' | 'block_url' | 'account_action' | 'notify' | 'other';
  /** 动作对象（IP / 域名 / URL）；无法从预案文本识别时为 ''（UI 标注"待人工核对"） */
  target: string;
  /** 预案原文动作描述 */
  action: string;
  /** 预案参考命令（仅展示，禁止执行） */
  command?: string;
  /** 对应预案步骤序号 */
  step_seq: number;
}

/** 处置回注指令（模拟） */
export interface MockWafCommand {
  task_id: string;
  playbook_id: string;
  /** 显式声明：本条为模拟指令，禁止下发给真实设备 */
  simulated: true;
  /**
   * 8788 `/mock/waf/block` 要求的顶层目标字段（该路由只认顶层 target）。
   * 取 actions 中第一个可下发的目标；预案里没有目标时为空串。
   */
  target: string;
  actions: MockWafAction[];
  created_at: string;
}

/** 预案步骤中与本模块相关的最小字段集（避免耦合 aisoc-api 的完整类型） */
export interface MockableStep {
  seq?: number;
  action?: string;
  phase?: string;
  expected_command?: string;
}

// 去混淆写法（文档 / 邮件里常见 `xynu-edu[.]top`）需先还原，再做提取
const DEFANG_RE = /\[\.\]|\(\.\)|\{\.\}|\[dot\]|\{dot\}/gi;
const IPV4_RE = /(?:\d{1,3}\.){3}\d{1,3}/g;
const IPV4_EXACT_RE = /^(?:\d{1,3}\.){3}\d{1,3}$/;
const URL_RE = /https?:\/\/[^\s"'<>)\]）】]+/gi;
const DOMAIN_RE = /\b(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,}\b/gi;

/** 还原去混淆写法：`xynu-edu[.]top` → `xynu-edu.top` */
export function refang(text: string): string {
  return text.replace(DEFANG_RE, '.');
}

/** 从一段文本中提取目标（URL / IP / 域名），去重且保持出现顺序 */
export function extractTargets(text: string): string[] {
  if (!text) return [];
  const t = refang(text);
  const urls: string[] = t.match(URL_RE) ?? [];
  const ips: string[] = t.match(IPV4_RE) ?? [];
  const rawDomains: string[] = t.match(DOMAIN_RE) ?? [];
  const domains = rawDomains.filter(
    (d) => !ips.includes(d) && !urls.some((u) => u.toLowerCase().includes(d.toLowerCase())),
  );
  return Array.from(new Set([...urls, ...ips, ...domains]));
}

/** 依据预案措辞与目标形态推断动作类型 */
function inferKind(actionText: string, target: string): MockWafAction['kind'] {
  const a = refang(actionText).toLowerCase();
  if (/改密|冻结|禁用|密码|账号|凭据|credential|account/.test(a)) return 'account_action';
  if (/通知|预警|告知|通报|notify|alert/.test(a)) return 'notify';
  if (IPV4_EXACT_RE.test(target)) return 'block_ip';
  if (/^https?:\/\//i.test(target)) return 'block_url';
  if (target) return 'block_domain';
  return 'other';
}

/**
 * 把预案 steps 汇总为一条模拟回注指令。
 * 每个步骤：能从 action + expected_command 中识别目标，则按目标展开为独立动作；
 * 识别不到则整条记为 other（target=''），交由 UI 标注"待人工核对"，不猜测。
 */
export function buildMockWafCommand(
  taskId: string,
  playbookId: string,
  steps: ReadonlyArray<MockableStep> = [],
  now: Date = new Date(),
): MockWafCommand {
  const actions: MockWafAction[] = [];
  steps.forEach((s, i) => {
    const stepSeq = typeof s.seq === 'number' ? s.seq : i + 1;
    const action = String(s.action ?? '').trim();
    const command = s.expected_command;
    const targets = extractTargets(`${action} ${command ?? ''}`);
    if (targets.length === 0) {
      actions.push({ kind: inferKind(action, ''), target: '', action, command, step_seq: stepSeq });
      return;
    }
    for (const target of targets) {
      actions.push({ kind: inferKind(action, target), target, action, command, step_seq: stepSeq });
    }
  });
  // 8788 路由只读顶层 target；按 actions 顺序取第一个真实目标做兜底。
  const primaryTarget = actions.find((a) => a.target.trim() !== '')?.target ?? '';
  return {
    task_id: taskId,
    playbook_id: playbookId,
    simulated: true,
    target: primaryTarget,
    actions,
    created_at: now.toISOString(),
  };
}
