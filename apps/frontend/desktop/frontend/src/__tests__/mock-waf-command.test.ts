/**
 * T2-2 处置回注（模拟）指令构建器冒烟测试（改进计划书 §7-Q4）
 * 覆盖：去混淆还原、目标提取（URL / IP / 域名 / 去重）、动作类型推断、
 * 按目标展开、simulated 恒真、序号兜底、JSON 序列化形态。
 * 运行：npx tsx src/__tests__/mock-waf-command.test.ts
 */

export {};

declare const process: { exit(code: number): void };

import {
  buildMockWafCommand,
  extractTargets,
  refang,
  type MockableStep,
} from '../lib/mockWafCommand';

let pass = 0, fail = 0;
function ok(cond: boolean, name: string) {
  if (cond) { pass++; console.log('  ✓', name); }
  else { fail++; console.error('  ✗', name); }
}

async function main() {
  // ── 1. 去混淆还原 ──
  console.log('1) refang 还原');
  ok(refang('xynu-edu[.]top') === 'xynu-edu.top', '[.] → .');
  ok(refang('evil(.)com') === 'evil.com', '(.) → .');
  ok(refang('a[dot]b') === 'a.b', '[dot] → .');

  // ── 2. 目标提取 ──
  console.log('2) extractTargets');
  ok(extractTargets('拉黑域名 xynu-edu[.]top，另 https://evil.example/path').includes('xynu-edu.top'),
    '提取域名（含去混淆）');
  ok(extractTargets('封禁来源 IP 203.0.113.7').includes('203.0.113.7'), '提取 IPv4');
  ok(extractTargets('封禁 https://evil.example/path').some(t => t.startsWith('https://evil.example')),
    '提取 URL');
  ok(extractTargets('a.example a.example a.example').length === 1, '重复目标去重');
  ok(extractTargets('').length === 0, '空文本返回空数组');
  ok(extractTargets('无目标描述').length === 0, '无目标返回空数组');

  // ── 3. 从预案 steps 汇总指令 ──
  console.log('3) buildMockWafCommand');
  const steps: MockableStep[] = [
    { seq: 1, phase: 'containment', action: '拉黑钓鱼域名 xynu-edu[.]top', expected_command: 'waf block-domain xynu-edu.top' },
    { seq: 2, phase: 'containment', action: '封禁攻击源 IP', expected_command: 'waf block-ip 203.0.113.7' },
    { seq: 3, phase: 'recovery', action: '受害账号强制改密' },
    { seq: 4, phase: 'notify', action: '向辅导员预警通知' },
  ];
  const fixed = new Date('2026-10-18T09:30:00.000Z');
  const cmd = buildMockWafCommand('T20261018-1', 'PB-1', steps, fixed);

  ok(cmd.task_id === 'T20261018-1', 'task_id 透传');
  ok(cmd.playbook_id === 'PB-1', 'playbook_id 透传');
  ok(cmd.simulated === true, 'simulated 恒为 true（防误下真机）');
  ok(cmd.target === 'xynu-edu.top', '顶层 target 取首个可下发目标（8788 路由契约兜底）');
  ok(cmd.created_at === fixed.toISOString(), 'created_at 使用注入时间');

  const kd = cmd.actions.find(a => a.target === 'xynu-edu.top');
  ok(!!kd && kd.kind === 'block_domain', '域名 → block_domain');
  const ki = cmd.actions.find(a => a.target === '203.0.113.7');
  ok(!!ki && ki.kind === 'block_ip', 'IP → block_ip');
  ok(cmd.actions.some(a => a.kind === 'account_action'), '改密措辞 → account_action');
  ok(cmd.actions.some(a => a.kind === 'notify'), '预警措辞 → notify');
  ok(cmd.actions.every(a => typeof a.step_seq === 'number'), '每条动作都带 step_seq');

  const other = cmd.actions.find(a => a.step_seq === 3);
  ok(!!other && other.kind === 'account_action' && other.target === '',
    '无目标步骤 target 为空（不猜测）且按措辞推断类型');

  // URL → block_url
  const urlCmd = buildMockWafCommand('t', 'p', [
    { seq: 1, action: '封禁', expected_command: 'waf block-url https://evil.example/a' },
  ], fixed);
  ok(urlCmd.actions[0]?.kind === 'block_url', 'URL → block_url');

  // 序号缺失兜底
  const noSeq = buildMockWafCommand('t', 'p', [{ action: '拉黑 bad.example' }], fixed);
  ok(noSeq.actions[0]?.step_seq === 1, 'seq 缺失时按序兜底为 1');

  // 空 steps
  const emptyCmd = buildMockWafCommand('t', 'p', [], fixed);
  ok(emptyCmd.actions.length === 0 && emptyCmd.simulated === true, '空预案 steps → 空指令且仍带 simulated');
  ok(emptyCmd.target === '', '无目标预案的顶层 target 为空串');

  // ── 4. 序列化后仍带 simulated（UI "查看指令"渲染的就是这份 JSON） ──
  console.log('4) JSON 序列化');
  const parsed = JSON.parse(JSON.stringify(cmd)) as { simulated?: boolean; target?: string; actions?: unknown[] };
  ok(parsed.simulated === true, 'JSON 中 simulated 保持 true');
  ok(parsed.target === 'xynu-edu.top', 'JSON 中顶层 target 与首个动作目标一致');
  ok(Array.isArray(parsed.actions), 'JSON 中 actions 为数组');

  console.log(`\n通过 ${pass}，失败 ${fail}`);
  process.exit(fail > 0 ? 1 : 0);
}

main().catch((e) => { console.error(e); process.exit(1); });
