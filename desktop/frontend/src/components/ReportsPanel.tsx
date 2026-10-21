/**
 * ReportsPanel — 预案 & 报告中心（独立于 AiSOC 大脑面板）
 *
 * 数据源：
 *   - 任务列表：`GET /api/tasks`（筛 status=completed / failed / cancelled）
 *   - 报告：`GET /api/reports/{task_id}`（markdown 文本）
 *   - 预案：前端 `src/aisoc-playbooks/*.md`（静态）
 *
 * 视图：
 *   - 顶部 Tab：「报告」/「预案」/「跨任务关联告警」
 *   - 「报告」Tab 左侧是任务列表 + 过滤；右侧是当前任务报告 markdown 渲染
 *   - 「预案」Tab 展示全部预案，点击展开 Markdown
 *   - 「告警关联」Tab 列出每个告警涉及的预案推荐（按 threat_class / rule_id）
 */

import { useCallback, useEffect, useMemo, useState } from 'react';
import {
  Activity,
  AlertTriangle,
  Database,
  Download,
  FileText,
  Loader2,
  Radar,
  RefreshCw,
  Search,
  ShieldCheck,
  X,
} from 'lucide-react';
import ReactMarkdown from 'react-markdown';
import remarkGfm from 'remark-gfm';
import { aisocApi, DOMAIN_LABELS, TASK_STATUS_META, type TaskInfo } from '../lib/aisoc-api';
import { PLAYBOOKS, type Playbook, matchPlaybooks } from '../aisoc-playbooks';

type TabKey = 'reports' | 'playbooks' | 'correlate';
const TAB_DEFS: Array<{ key: TabKey; label: string; icon: React.ReactNode }> = [
  { key: 'reports',    label: '报告',     icon: <FileText className="w-3.5 h-3.5" /> },
  { key: 'playbooks',  label: '预案库',   icon: <ShieldCheck className="w-3.5 h-3.5" /> },
  { key: 'correlate',  label: '告警关联', icon: <Radar className="w-3.5 h-3.5" /> },
];

export default function ReportsPanel({ onExit, onOpenInBrain }: {
  onExit: () => void;
  onOpenInBrain?: (seed: { taskId: string }) => void;
}) {
  const [tab, setTab] = useState<TabKey>('reports');

  // Esc 退出面板
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        e.preventDefault();
        onExit();
      }
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [onExit]);

  return (
    <div className="aisoc-shell flex flex-col h-screen w-screen text-sm">
      {/* 顶栏 */}
      <header className="px-4 py-2.5 border-b border-zinc-200 bg-white flex items-center gap-3">
        <button
          type="button"
          onClick={onExit}
          className="flex items-center gap-1.5 px-3 py-1.5 rounded border border-zinc-300 bg-white text-zinc-700 hover:bg-zinc-100 hover:border-zinc-400 text-xs font-medium transition-colors"
          title="返回主界面（按 Esc 也可退出）"
        >
          <X className="w-3.5 h-3.5" />
          <span>返回主页</span>
          <kbd className="ml-1 hidden sm:inline-block text-[9px] font-mono text-zinc-500 bg-zinc-100 border border-zinc-200 rounded px-1 py-0.5">Esc</kbd>
        </button>
        <div className="flex items-center gap-2 font-semibold text-zinc-800">
          <ShieldCheck className="w-4 h-4 text-emerald-600" />
          预案 / 报告中心
          <span className="text-[10px] font-normal text-zinc-500">
            · 独立于 AiSOC 大脑 · 任务报告 + 预案模板 + 告警关联
          </span>
        </div>
        <div className="ml-auto flex items-center gap-1">
          {TAB_DEFS.map((t) => (
            <button
              key={t.key}
              type="button"
              onClick={() => setTab(t.key)}
              className={`px-2.5 py-1 rounded text-[11px] flex items-center gap-1.5 border transition-colors ${
                tab === t.key
                  ? 'bg-emerald-50 text-emerald-700 border-emerald-200'
                  : 'bg-white text-zinc-500 border-zinc-200 hover:bg-zinc-50'
              }`}
            >
              {t.icon}
              {t.label}
            </button>
          ))}
        </div>
      </header>

      <div className="flex-1 min-h-0">
        {tab === 'reports'   && <ReportList onExit={onExit} onOpenInBrain={onOpenInBrain} />}
        {tab === 'playbooks' && <PlaybookList />}
        {tab === 'correlate' && <CorrelateView />}
      </div>
    </div>
  );
}

// ------------------------------------------------------------------
// 「报告」视图：左侧任务列表，右侧报告详情
// ------------------------------------------------------------------

function ReportList({ onOpenInBrain }: { onExit: () => void; onOpenInBrain?: (seed: { taskId: string }) => void }) {
  const [tasks, setTasks] = useState<TaskInfo[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [filterStatus, setFilterStatus] = useState<'all' | 'completed' | 'failed' | 'cancelled'>('completed');
  const [searchQ, setSearchQ] = useState('');
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [refreshing, setRefreshing] = useState(false);

  const fetchTasks = useCallback(async (isManual = false) => {
    if (isManual) setRefreshing(true);
    try {
      const data = await aisocApi.listTasks(200);
      setTasks(data.tasks ?? []);
      setError(null);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  }, []);

  useEffect(() => { void fetchTasks(); }, [fetchTasks]);

  const filtered = useMemo(() => {
    const q = searchQ.trim().toLowerCase();
    return tasks.filter((t) => {
      if (filterStatus !== 'all' && t.status !== filterStatus) return false;
      if (q) {
        const h = [t.id, t.domain, t.target].join(' ').toLowerCase();
        if (!h.includes(q)) return false;
      }
      return true;
    });
  }, [tasks, filterStatus, searchQ]);

  useEffect(() => {
    if (!selectedId && filtered.length > 0) {
      setSelectedId(filtered[0]!.id);
    }
  }, [filtered, selectedId]);

  const selected = useMemo(
    () => tasks.find((t) => t.id === selectedId) ?? null,
    [tasks, selectedId],
  );

  const statusCounts = useMemo(() => {
    const out: Record<string, number> = { completed: 0, failed: 0, cancelled: 0, running: 0, pending: 0 };
    for (const t of tasks) out[t.status] = (out[t.status] ?? 0) + 1;
    return out;
  }, [tasks]);

  return (
    <div className="flex h-full">
      {/* 左：任务列表 */}
      <div className="w-[400px] border-r border-zinc-200 flex flex-col bg-white">
        <div className="p-2 border-b border-zinc-100 space-y-1.5">
          <div className="flex items-center gap-1">
            {(['completed', 'failed', 'cancelled', 'all'] as const).map((s) => {
              const label = s === 'all' ? '全部' : (TASK_STATUS_META[s]?.label ?? s);
              const count = s === 'all' ? tasks.length : (statusCounts[s] ?? 0);
              return (
                <button
                  key={s}
                  type="button"
                  onClick={() => setFilterStatus(s)}
                  className={`px-2 py-0.5 rounded text-[10px] border transition-colors ${
                    filterStatus === s
                      ? 'bg-zinc-700 text-white border-zinc-700'
                      : 'bg-white text-zinc-500 border-zinc-200 hover:bg-zinc-50'
                  }`}
                >
                  {label} ({count})
                </button>
              );
            })}
            <button
              type="button"
              onClick={() => void fetchTasks(true)}
              disabled={refreshing}
              className="ml-auto rounded p-1 hover:bg-zinc-100"
              title="刷新任务列表"
            >
              <RefreshCw className={`w-3 h-3 text-zinc-500 ${refreshing ? 'animate-spin' : ''}`} />
            </button>
          </div>
          <div className="relative">
            <Search className="w-3.5 h-3.5 absolute left-2 top-1/2 -translate-y-1/2 text-zinc-400" />
            <input
              type="text"
              value={searchQ}
              onChange={(e) => setSearchQ(e.target.value)}
              placeholder="搜索任务 ID / 目标 / 描述…"
              className="w-full pl-7 pr-2 py-1 text-xs rounded border border-zinc-200 bg-zinc-50/30 focus:outline-none focus:ring-1 focus:ring-emerald-200 focus:bg-white"
            />
          </div>
        </div>

        <div className="flex-1 overflow-y-auto">
          {loading ? (
            <div className="flex items-center justify-center h-full text-zinc-500 text-xs">
              <Loader2 className="w-4 h-4 animate-spin mr-2" />
              加载任务…
            </div>
          ) : error ? (
            <div className="p-3 text-xs text-red-700 bg-red-50 border-b border-red-200">
              <div className="font-semibold mb-1 flex items-center gap-1">
                <AlertTriangle className="w-3.5 h-3.5" /> 拉取失败
              </div>
              <div className="font-mono text-[10px] break-all">{error}</div>
            </div>
          ) : filtered.length === 0 ? (
            <div className="flex flex-col items-center justify-center h-full text-zinc-400 text-xs gap-2">
              <Database className="w-8 h-8 text-zinc-300" />
              没有命中条件的任务
            </div>
          ) : (
            filtered.map((t) => {
              const isSel = t.id === selectedId;
              const sm = TASK_STATUS_META[t.status];
              return (
                <button
                  type="button"
                  key={t.id}
                  onClick={() => setSelectedId(t.id)}
                  className={`w-full text-left p-2.5 border-b border-zinc-100 transition-colors ${
                    isSel ? 'bg-emerald-50/60 border-l-2 border-l-emerald-500' : 'hover:bg-zinc-50/60'
                  }`}
                >
                  <div className="flex items-center gap-1.5 mb-1">
                    <span className={`px-1.5 py-0.5 rounded text-[10px] ${sm?.cls ?? 'bg-zinc-100'}`}>
                      {sm?.label ?? t.status}
                    </span>
                    <span className="text-[10px] text-zinc-500 font-mono">
                      {DOMAIN_LABELS[t.domain] ?? t.domain}
                    </span>
                  </div>
                  <div className="text-xs font-medium text-zinc-800 truncate font-mono">
                    {t.id}
                  </div>
                  <div className="text-[10px] text-zinc-500 mt-0.5 truncate">
                    目标：{t.target || '—'}
                  </div>
                </button>
              );
            })
          )}
        </div>
      </div>

      {/* 右：报告详情 */}
      <div className="flex-1 min-w-0 overflow-y-auto bg-zinc-50/30">
        {selected ? <ReportDetail task={selected} onOpenInBrain={onOpenInBrain} /> : (
          <div className="flex flex-col items-center justify-center h-full text-zinc-400 text-sm gap-2">
            <FileText className="w-10 h-10 text-zinc-300" />
            选择左侧任务查看报告
          </div>
        )}
      </div>
    </div>
  );
}

function ReportDetail({ task, onOpenInBrain }: { task: TaskInfo; onOpenInBrain?: (seed: { taskId: string }) => void }) {
  const [report, setReport] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    setReport(null);
    setError(null);
    setLoading(true);
    aisocApi.getReport(task.id)
      .then((res) => {
        if (cancelled) return;
        // 后端返回可能是 { report: "..." } 或 { content: "..." } 或 { text: "..." }，兼容几种
        const text =
          (res as { report?: string }).report ??
          (res as { content?: string }).content ??
          (res as { text?: string }).text ??
          (typeof res === 'string' ? res : null);
        setReport(text);
      })
      .catch((e) => {
        if (cancelled) return;
        setError(e instanceof Error ? e.message : String(e));
      })
      .finally(() => { if (!cancelled) setLoading(false); });
    return () => { cancelled = true; };
  }, [task.id]);

  const sm = TASK_STATUS_META[task.status];

  // 导出报告为 .md 文件
  const exportMd = () => {
    if (!report) return;
    const blob = new Blob([
      `# 任务报告：${task.id}\n\n`,
      `> 目标：${task.target}  域：${task.domain}  状态：${task.status}\n\n`,
      report,
    ], { type: 'text/markdown;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `report-${task.id}.md`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  return (
    <div className="p-4 max-w-4xl">
      {/* 头部 */}
      <div className="mb-3 flex items-start gap-3">
        <div className="flex-1 min-w-0">
          <h1 className="text-base font-bold text-zinc-800 font-mono">{task.id}</h1>
          <div className="flex items-center gap-1.5 mt-1.5 flex-wrap">
            <span className={`px-2 py-0.5 rounded text-[11px] ${sm?.cls}`}>
              {sm?.label ?? task.status}
            </span>
            <span className="px-2 py-0.5 rounded text-[11px] border border-zinc-200 text-zinc-600">
              域：{DOMAIN_LABELS[task.domain] ?? task.domain}
            </span>
            {task.target && (
              <span className="px-2 py-0.5 rounded text-[11px] border border-zinc-200 text-zinc-600 font-mono">
                目标：{task.target}
              </span>
            )}
            {task.verdict && (
              <span className="px-2 py-0.5 rounded text-[11px] border border-zinc-200 text-zinc-600">
                判定：{task.verdict}
              </span>
            )}
          </div>
        </div>
        <div className="flex items-center gap-1.5">
          {onOpenInBrain && task.status === 'running' && (
            <button
              type="button"
              onClick={() => onOpenInBrain({ taskId: task.id })}
              className="rounded border border-fuchsia-200 bg-fuchsia-50 text-fuchsia-700 px-2 py-1 text-[11px] flex items-center gap-1 hover:bg-fuchsia-100"
            >
              <Activity className="w-3 h-3" /> 回到大脑
            </button>
          )}
          {report && (
            <button
              type="button"
              onClick={exportMd}
              className="rounded border border-emerald-200 bg-emerald-50 text-emerald-700 px-2 py-1 text-[11px] flex items-center gap-1 hover:bg-emerald-100"
            >
              <Download className="w-3 h-3" /> 导出 .md
            </button>
          )}
        </div>
      </div>

      {/* 报告内容 */}
      {loading ? (
        <div className="flex items-center justify-center h-40 text-zinc-500 text-xs">
          <Loader2 className="w-4 h-4 animate-spin mr-2" />
          拉取报告…
        </div>
      ) : error ? (
        <div className="rounded border border-amber-200 bg-amber-50/40 p-3 text-xs text-amber-800">
          <div className="font-semibold mb-1 flex items-center gap-1">
            <AlertTriangle className="w-3.5 h-3.5" /> 报告未就绪
          </div>
          <div className="font-mono text-[10px] break-all mb-2">{error}</div>
          <div className="text-[11px] text-amber-700">
            任务状态 = <code className="bg-amber-100 px-1 rounded">{task.status}</code>。
            仅 <code className="bg-amber-100 px-1 rounded">completed</code> 状态的报告会落地到 <code className="bg-amber-100 px-1 rounded">/api/reports/&#123;task_id&#125;</code>。
          </div>
        </div>
      ) : !report ? (
        <div className="rounded border border-zinc-200 bg-white p-4 text-xs text-zinc-500 text-center">
          此任务没有报告
        </div>
      ) : (
        <article className="rounded-lg border border-zinc-200 bg-white p-4">
          <div className="prose prose-sm max-w-none prose-headings:text-zinc-800 prose-headings:font-semibold prose-h1:text-base prose-h2:text-sm prose-h2:mt-4 prose-h2:mb-1 prose-h3:text-xs prose-h3:mt-3 prose-h3:mb-1 prose-li:my-0.5 prose-pre:bg-zinc-50 prose-pre:border prose-pre:border-zinc-200">
            <ReactMarkdown remarkPlugins={[remarkGfm]}>{report}</ReactMarkdown>
          </div>
        </article>
      )}
    </div>
  );
}

// ------------------------------------------------------------------
// 「预案库」视图：全部预案
// ------------------------------------------------------------------

function PlaybookList() {
  const [q, setQ] = useState('');
  const [openId, setOpenId] = useState<string | null>(PLAYBOOKS[0]?.meta.id ?? null);

  const filtered = useMemo(() => {
    const query = q.trim().toLowerCase();
    if (!query) return PLAYBOOKS;
    return PLAYBOOKS.filter((pb) => {
      const h = [
        pb.meta.id, pb.meta.name,
        ...(pb.meta.tags ?? []),
        pb.body,
      ].join(' ').toLowerCase();
      return h.includes(query);
    });
  }, [q]);

  return (
    <div className="flex h-full">
      {/* 左：预案列表 */}
      <div className="w-[360px] border-r border-zinc-200 flex flex-col bg-white">
        <div className="p-2 border-b border-zinc-100 space-y-1.5">
          <div className="text-xs font-semibold text-zinc-700 flex items-center gap-1.5">
            <ShieldCheck className="w-3.5 h-3.5 text-emerald-600" />
            全部预案（{PLAYBOOKS.length}）
          </div>
          <div className="relative">
            <Search className="w-3.5 h-3.5 absolute left-2 top-1/2 -translate-y-1/2 text-zinc-400" />
            <input
              type="text"
              value={q}
              onChange={(e) => setQ(e.target.value)}
              placeholder="搜索 ID / 名称 / 标签…"
              className="w-full pl-7 pr-2 py-1 text-xs rounded border border-zinc-200 bg-zinc-50/30 focus:outline-none focus:ring-1 focus:ring-emerald-200 focus:bg-white"
            />
          </div>
        </div>
        <div className="flex-1 overflow-y-auto">
          {filtered.map((pb) => {
            const isOpen = openId === pb.meta.id;
            return (
              <button
                type="button"
                key={pb.meta.id}
                onClick={() => setOpenId(pb.meta.id)}
                className={`w-full text-left p-2.5 border-b border-zinc-100 transition-colors ${
                  isOpen ? 'bg-emerald-50/60 border-l-2 border-l-emerald-500' : 'hover:bg-zinc-50/60'
                }`}
              >
                <div className="flex items-center gap-1.5 mb-1">
                  <span className="px-1.5 py-0.5 rounded text-[10px] bg-emerald-100 text-emerald-700 font-mono">
                    {pb.meta.id}
                  </span>
                  {pb.meta.severity && (
                    <span className={`px-1.5 py-0.5 rounded text-[10px] ${
                      pb.meta.severity === 'critical' ? 'bg-red-100 text-red-700' :
                      pb.meta.severity === 'high' ? 'bg-orange-100 text-orange-700' :
                      pb.meta.severity === 'medium' ? 'bg-amber-100 text-amber-700' :
                      'bg-zinc-100 text-zinc-600'
                    }`}>
                      {pb.meta.severity}
                    </span>
                  )}
                </div>
                <div className="text-xs font-medium text-zinc-800">{pb.meta.name}</div>
                {pb.meta.tags && (
                  <div className="text-[10px] text-zinc-500 mt-0.5">
                    {pb.meta.tags.map((t) => `#${t}`).join(' ')}
                  </div>
                )}
              </button>
            );
          })}
          {filtered.length === 0 && (
            <div className="p-3 text-xs text-zinc-500 text-center">没有命中条件的预案</div>
          )}
        </div>
      </div>

      {/* 右：选中预案详情 */}
      <div className="flex-1 overflow-y-auto bg-zinc-50/30 p-4">
        {openId ? <PlaybookDetail id={openId} /> : null}
      </div>
    </div>
  );
}

function PlaybookDetail({ id }: { id: string }) {
  const pb = useMemo(() => PLAYBOOKS.find((p) => p.meta.id === id), [id]);
  if (!pb) return <div className="text-xs text-zinc-500">预案不存在</div>;
  return (
    <article className="max-w-4xl">
      <div className="mb-3">
        <div className="flex items-center gap-1.5 mb-1.5">
          <span className="px-2 py-0.5 rounded text-xs bg-emerald-100 text-emerald-700 font-mono">{pb.meta.id}</span>
          {pb.meta.severity && (
            <span className={`px-2 py-0.5 rounded text-xs ${
              pb.meta.severity === 'critical' ? 'bg-red-100 text-red-700' :
              pb.meta.severity === 'high' ? 'bg-orange-100 text-orange-700' :
              'bg-amber-100 text-amber-700'
            }`}>{pb.meta.severity}</span>
          )}
          {pb.meta.estimated_minutes && (
            <span className="px-2 py-0.5 rounded text-xs border border-zinc-200 text-zinc-600">
              ⏱ 预计 {pb.meta.estimated_minutes} 分钟
            </span>
          )}
        </div>
        <h1 className="text-base font-bold text-zinc-800">{pb.meta.name}</h1>
        {pb.meta.tags && (
          <div className="text-[11px] text-zinc-500 mt-1">
            {pb.meta.tags.map((t) => `#${t}`).join(' ')}
          </div>
        )}
        <div className="mt-2 text-[11px] text-zinc-500 flex items-center gap-2">
          <span>匹配规则：</span>
          {pb.meta.threat_class !== undefined && (
            <span className="font-mono">threat_class = {Array.isArray(pb.meta.threat_class) ? pb.meta.threat_class.join('|') : pb.meta.threat_class}</span>
          )}
          {pb.meta.rule_ids && pb.meta.rule_ids.length > 0 && (
            <span className="font-mono">rule_id ∈ [{pb.meta.rule_ids.join(', ')}]</span>
          )}
        </div>
      </div>
      <article className="rounded-lg border border-zinc-200 bg-white p-4">
        <div className="prose prose-sm max-w-none prose-headings:text-zinc-800 prose-headings:font-semibold prose-h2:text-sm prose-h2:mt-4 prose-h2:mb-1 prose-h3:text-xs prose-li:my-0.5 prose-pre:bg-zinc-50 prose-pre:border prose-pre:border-zinc-200">
          <ReactMarkdown remarkPlugins={[remarkGfm]}>{pb.body}</ReactMarkdown>
        </div>
      </article>
    </article>
  );
}

// ------------------------------------------------------------------
// 「告警关联」视图：每个告警涉及的预案
// ------------------------------------------------------------------

function CorrelateView() {
  const [alarms, setAlarms] = useState<Array<{ id?: string; title?: string; threat_class?: number; rule_id?: string; severity: string }>>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let cancelled = false;
    aisocApi.getAlarms(200)
      .then((res) => {
        if (cancelled) return;
        setAlarms((res.alarms ?? []).map((a) => ({
          id: a.id,
          title: a.title,
          threat_class: a.threat_class,
          rule_id: a.rule_id,
          severity: a.severity,
        })));
      })
      .catch(() => { /* ignore */ })
      .finally(() => { if (!cancelled) setLoading(false); });
    return () => { cancelled = true; };
  }, []);

  const rows = useMemo(() => {
    const out: Array<{ alarm: typeof alarms[number]; pbs: Playbook[] }> = [];
    for (const a of alarms) {
      const pbs = matchPlaybooks({ threat_class: a.threat_class, rule_id: a.rule_id });
      if (pbs.length > 0) out.push({ alarm: a, pbs });
    }
    return out;
  }, [alarms]);

  if (loading) {
    return (
      <div className="flex items-center justify-center h-full text-zinc-500 text-xs">
        <Loader2 className="w-4 h-4 animate-spin mr-2" />
        拉取告警…
      </div>
    );
  }

  return (
    <div className="p-4 max-w-5xl">
      <div className="mb-3 flex items-center gap-2 text-zinc-700">
        <Radar className="w-4 h-4 text-fuchsia-600" />
        <h1 className="text-sm font-bold">告警 × 预案 关联</h1>
        <span className="text-[11px] text-zinc-500">
          · 共 {alarms.length} 条告警，{rows.length} 条有匹配预案
        </span>
      </div>
      {rows.length === 0 ? (
        <div className="rounded border border-zinc-200 bg-white p-4 text-xs text-zinc-500 text-center">
          {alarms.length === 0 ? '当前没有告警数据' : '所有告警都未匹配到预案模板（threat_class / rule_id 都不在预案库范围内）'}
        </div>
      ) : (
        <div className="space-y-2">
          {rows.map(({ alarm, pbs }) => (
            <div key={alarm.id ?? Math.random()} className="rounded border border-zinc-200 bg-white p-3">
              <div className="flex items-start gap-2 mb-2">
                <span className={`px-1.5 py-0.5 rounded text-[10px] ${
                  alarm.severity === 'critical' ? 'bg-red-100 text-red-700' :
                  alarm.severity === 'high' ? 'bg-orange-100 text-orange-700' :
                  alarm.severity === 'medium' ? 'bg-amber-100 text-amber-700' :
                  'bg-zinc-100 text-zinc-700'
                }`}>{alarm.severity}</span>
                <div className="flex-1 min-w-0">
                  <div className="text-xs font-medium text-zinc-800">{alarm.title || '（无标题）'}</div>
                  <div className="text-[10px] text-zinc-500 font-mono">
                    threat_class={alarm.threat_class ?? '—'} · rule_id={alarm.rule_id ?? '—'} · id={alarm.id?.slice(0, 8) ?? '?'}
                  </div>
                </div>
              </div>
              <div className="flex items-center gap-1.5 flex-wrap">
                <span className="text-[10px] text-zinc-500">匹配预案：</span>
                {pbs.map((pb) => (
                  <span key={pb.meta.id} className="px-1.5 py-0.5 rounded text-[10px] bg-emerald-50 text-emerald-700 border border-emerald-200 font-mono">
                    {pb.meta.id} · {pb.meta.name}
                  </span>
                ))}
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
