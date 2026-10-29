/**
 * 应急响应（TIR）前端对接单元测试（tir-frontend.md §4.1~4.4）
 * 覆盖：
 *   1) getTirAlerts / getTirPlaybooks / getTirReports 2xx 解包为数组、字段透传
 *   2) 空数组 / 缺字段 → 返回 [] 不抛错（空数组是正常态，非 real_threat 任务无 TIR 数据）
 *   3) 404 / 401 → 抛 AisocApiError 且 status 正确（request() 无非 2xx 静默降级，调用方须自行 catch）
 *   4) approveTool：status=responded（带 report_id/report_md）与 status=recorded（仅记账）两形态解包
 *   5) 502（8090 不可用）→ AisocApiError 且 isUnreachable
 * 运行：npx tsx src/__tests__/tir-api.test.ts
 */

export {};

declare const process: { exit(code: number): void };

type CapturedCall = { url: string; body: any; headers: any };
const calls: CapturedCall[] = [];

type ListMode = 'ok' | 'empty' | 'missing' | '404' | '401';
let listMode: ListMode = 'ok';
let approveMode: 'responded' | 'recorded' | '502' = 'responded';

const TASK = 'T20261015-001';

const ALERT = {
  alert_id: 'tir_alert_1a28b242',
  task_id: TASK,
  event_ref: 'tir_event_xxx',
  level: 'high',
  status: 'acknowledged',
  display_md: '### ⚠️ 威胁警报\n检测到 WebShell 上传',
  created_at: '2026-10-15T02:00:00Z',
  payload: {
    title: '检测到 WebShell 上传',
    attack_type: 'webshell',
    mitre_technique: 'T1505',
    confidence: 0.92,
    verdict: 'true_positive',
  },
};

const PLAYBOOK = {
  playbook_id: 'tir_playbook_xxx',
  alert_id: ALERT.alert_id,
  task_id: TASK,
  mode: 'suggestion',
  display_md: '### 🛡️ 应急处置预案\n遏制并清除 WebShell',
  created_at: '2026-10-15T02:00:02Z',
  payload: {
    objective: '遏制并清除 WebShell',
    steps: [
      {
        seq: 1,
        phase: '遏制(Containment)',
        action: '隔离受影响主机',
        expected_command: 'iptables -A INPUT -s 111.1.216.150 -j DROP',
        requires_approval: true,
        status: 'pending',
      },
    ],
  },
};

const REPORT = {
  report_id: 'tir_report_xxx',
  task_id: TASK,
  playbook_id: PLAYBOOK.playbook_id,
  alert_id: ALERT.alert_id,
  decision: 'approve',
  report_md: '==== 应急响应报告 ====\n处置完成',
  created_at: '2026-10-15T02:05:00Z',
};

(globalThis as any).fetch = async (url: string, init?: any) => {
  const u = String(url);
  const body = init?.body ? JSON.parse(init.body) : undefined;
  calls.push({ url: u, body, headers: init?.headers });

  if (u.includes('/tir/alerts')) {
    if (listMode === '404') return new Response('not found', { status: 404 });
    if (listMode === '401') {
      return new Response(JSON.stringify({ error: '未登录或 token 已失效', code: 'UNAUTHORIZED' }), { status: 401 });
    }
    if (listMode === 'empty') return new Response(JSON.stringify({ task_id: TASK, alerts: [] }), { status: 200 });
    if (listMode === 'missing') return new Response(JSON.stringify({ task_id: TASK }), { status: 200 });
    return new Response(JSON.stringify({ task_id: TASK, alerts: [ALERT] }), { status: 200 });
  }
  if (u.includes('/tir/playbooks')) {
    if (listMode === '404') return new Response('not found', { status: 404 });
    if (listMode === '401') {
      return new Response(JSON.stringify({ error: '未登录或 token 已失效', code: 'UNAUTHORIZED' }), { status: 401 });
    }
    if (listMode === 'empty') return new Response(JSON.stringify({ task_id: TASK, playbooks: [] }), { status: 200 });
    if (listMode === 'missing') return new Response(JSON.stringify({ task_id: TASK }), { status: 200 });
    return new Response(JSON.stringify({ task_id: TASK, playbooks: [PLAYBOOK] }), { status: 200 });
  }
  if (u.includes('/tir/reports')) {
    if (listMode === '404') return new Response('not found', { status: 404 });
    if (listMode === '401') {
      return new Response(JSON.stringify({ error: '未登录或 token 已失效', code: 'UNAUTHORIZED' }), { status: 401 });
    }
    if (listMode === 'empty') return new Response(JSON.stringify({ task_id: TASK, reports: [] }), { status: 200 });
    if (listMode === 'missing') return new Response(JSON.stringify({ task_id: TASK }), { status: 200 });
    return new Response(JSON.stringify({ task_id: TASK, reports: [REPORT] }), { status: 200 });
  }
  if (u.includes('/approve')) {
    if (approveMode === '502') {
      return new Response(JSON.stringify({ error: 'TIR 预案决策失败（8090 不可用或预案不存在）' }), { status: 502 });
    }
    if (approveMode === 'recorded') {
      return new Response(JSON.stringify({
        task_id: body?.task_id, action: body?.action, decision: body?.decision, status: 'recorded',
      }), { status: 200 });
    }
    return new Response(JSON.stringify({
      task_id: body?.task_id, action: body?.action, decision: body?.decision, status: 'responded',
      playbook_id: PLAYBOOK.playbook_id, report_id: REPORT.report_id, report_md: REPORT.report_md,
    }), { status: 200 });
  }
  return new Response('{}', { status: 200 });
};

const { AisocApi, AisocApiError } = await import('../lib/aisoc-api');

let pass = 0, fail = 0;
function ok(cond: boolean, name: string) {
  if (cond) { pass++; console.log('  ✓', name); }
  else { fail++; console.error('  ✗', name); }
}

async function main() {
  const api = new AisocApi('/api', 'tok-t');

  // ── 1. 三个 GET 2xx 解包为数组、字段透传 ──
  console.log('1) TIR 列表 2xx 解包');
  listMode = 'ok';
  calls.length = 0;
  const alerts = await api.getTirAlerts(TASK);
  ok(Array.isArray(alerts) && alerts.length === 1, 'alerts 解包为数组');
  ok(alerts[0].alert_id === ALERT.alert_id && alerts[0].task_id === TASK, 'alert_id/task_id 透传');
  ok(alerts[0].level === 'high' && alerts[0].status === 'acknowledged', 'level/status 透传');
  ok(alerts[0].display_md === ALERT.display_md, 'display_md 原样透传（供 Markdown 渲染）');
  ok(alerts[0].payload?.mitre_technique === 'T1505', 'payload 结构化字段透传');
  ok(calls[0].url.includes(`/tir/alerts?task_id=${TASK}`), 'task_id 拼进 query');

  calls.length = 0;
  const playbooks = await api.getTirPlaybooks(TASK);
  ok(Array.isArray(playbooks) && playbooks.length === 1, 'playbooks 解包为数组');
  ok(playbooks[0].playbook_id === PLAYBOOK.playbook_id && playbooks[0].mode === 'suggestion', 'playbook_id/mode 透传');
  ok(playbooks[0].payload?.steps?.[0]?.expected_command === PLAYBOOK.payload.steps[0].expected_command,
    'steps[].expected_command 透传（前端仅展示）');
  ok(playbooks[0].payload?.steps?.[0]?.requires_approval === true, 'steps[].requires_approval 透传');

  calls.length = 0;
  const reports = await api.getTirReports(TASK);
  ok(Array.isArray(reports) && reports.length === 1, 'reports 解包为数组');
  ok(reports[0].report_id === REPORT.report_id && reports[0].decision === 'approve', 'report_id/decision 透传');
  ok(calls[0].url.includes('/tir/reports'), 'reports 命中正确端点');

  ok(calls[0].headers?.Authorization === 'Bearer tok-t', '携带 Authorization: Bearer');

  // ── 2. 空数组 / 缺字段 → [] 不抛错 ──
  console.log('2) 空数组是正常态');
  listMode = 'empty';
  ok((await api.getTirAlerts(TASK)).length === 0, 'alerts: [] → []');
  ok((await api.getTirPlaybooks(TASK)).length === 0, 'playbooks: [] → []');
  ok((await api.getTirReports(TASK)).length === 0, 'reports: [] → []');
  listMode = 'missing';
  let threw = false;
  try { await api.getTirAlerts(TASK); } catch { threw = true; }
  ok(!threw, '缺 alerts 字段时不抛错（?? [] 兜底）');
  ok((await api.getTirAlerts(TASK)).length === 0, '缺字段返回空数组');

  // ── 3. 404 / 401 抛 AisocApiError 且 status 正确 ──
  console.log('3) 非 2xx 抛错（request 无静默降级）');
  listMode = '404';
  let e404: any = null;
  try { await api.getTirAlerts(TASK); } catch (e) { e404 = e; }
  ok(e404 instanceof AisocApiError, '404 抛 AisocApiError');
  ok(e404?.status === 404, '404 status 正确（他人任务 → 404 由调用方 catch 降级）');

  listMode = '401';
  let e401: any = null;
  try { await api.getTirPlaybooks(TASK); } catch (e) { e401 = e; }
  ok(e401 instanceof AisocApiError && e401?.status === 401, '401 抛 AisocApiError 且 status=401');
  listMode = 'ok';

  // ── 4. approveTool 两种形态 ──
  console.log('4) approveTool');
  approveMode = 'responded';
  calls.length = 0;
  const responded = await api.approveTool(TASK, PLAYBOOK.playbook_id, 'approved');
  ok(calls[0].url.includes('/approve') && calls[0].body?.task_id === TASK, 'POST /approve 带 task_id');
  ok(calls[0].body?.action === PLAYBOOK.playbook_id && calls[0].body?.decision === 'approved', 'action/decision 原样传（approved）');
  ok(responded.status === 'responded', 'status=responded');
  ok(responded.report_id === REPORT.report_id && responded.report_md === REPORT.report_md, '带 report_id/report_md 可直接渲染');

  approveMode = 'recorded';
  calls.length = 0;
  const recorded = await api.approveTool(TASK, PLAYBOOK.playbook_id, 'denied');
  ok(calls[0].body?.decision === 'denied', 'decision=denied 透传');
  ok(recorded.status === 'recorded', 'status=recorded（无预案仅记账）');
  ok(recorded.report_id === undefined && recorded.report_md === undefined, 'recorded 形态无报告字段');

  // ── 5. 502（8090 不可用）→ isUnreachable ──
  console.log('5) 502 上游不可用');
  approveMode = '502';
  let e502: any = null;
  try { await api.approveTool(TASK, PLAYBOOK.playbook_id, 'approved'); } catch (e) { e502 = e; }
  ok(e502 instanceof AisocApiError && e502?.status === 502, '502 抛 AisocApiError 且 status=502');
  ok(e502?.isUnreachable === true, '502 标记 isUnreachable（前端轻提示不阻断）');

  console.log(`\n通过 ${pass}，失败 ${fail}`);
  process.exit(fail > 0 ? 1 : 0);
}

main().catch((e) => { console.error(e); process.exit(1); });
