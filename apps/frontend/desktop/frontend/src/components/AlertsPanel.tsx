/**
 * AlertsPanel — 威胁应急告警面板（独立于 AiSOC 大脑面板）
 *
 * 数据源：大脑 `GET /api/data/alarms` + `/api/data/alarms/summary`
 * 行为：实时轮询（默认 5s）+ 严重度/状态筛选 + 详情抽屉 + 处置操作（标记 deal_status）
 *       + 推荐预案（按 threat_class / rule_id 匹配前端 aisoc-playbooks/ 库）
 *
 * 重要设计：
 *   1. 面板**不**走大脑编排，只读告警数据 + 触发"通过大脑创建取证任务"（与 Aisoc 联动）
 *   2. 处置状态是本地状态（后端没有 /api/alarms/{id}/deal 接口），刷新后会回退
 *      — 等后端补端点后可平滑接入
 */

import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import {
  Activity,
  AlertTriangle,
  CheckCircle2,
  ChevronRight,
  Clock,
  Copy,
  ExternalLink,
  Filter,
  Loader2,
  Network,
  Radar,
  RefreshCw,
  Search,
  ShieldAlert,
  ShieldCheck,
  X,
  Zap,
} from 'lucide-react';
import ReactMarkdown from 'react-markdown';
import remarkGfm from 'remark-gfm';
import {
  aisocApi,
  SEVERITY_META,
  VERDICT_META,
  type Alarm,
  type AlarmsSummary,
} from '../lib/aisoc-api';
import { matchPlaybooks, type Playbook } from '../aisoc-playbooks';

const REFRESH_INTERVAL_MS = 5000;
const DEFAULT_LIMIT = 200;

const SEVERITY_ORDER = ['critical', 'high', 'medium', 'low', 'info'] as const;
const VERDICT_OPTIONS = [
  { value: '',            label: '全部研判',  cls: 'bg-zinc-100 text-zinc-700' },
  { value: 'real_threat', label: '⚠️ 真实威胁', cls: 'bg-red-50 text-red-700' },
  { value: 'pending_review', label: '🗂️ 待复核', cls: 'bg-amber-50 text-amber-800' },
  { value: 'false_positive', label: '✅ 误报', cls: 'bg-emerald-50 text-emerald-700' },
] as const;

const DEAL_STATUS_META: Record<number, { label: string; cls: string }> = {
  0: { label: '未处置', cls: 'bg-zinc-100 text-zinc-700 border-zinc-200' },
  1: { label: '处置中', cls: 'bg-sky-50 text-sky-700 border-sky-200' },
  2: { label: '已处置', cls: 'bg-emerald-50 text-emerald-700 border-emerald-200' },
  3: { label: '已忽略', cls: 'bg-zinc-50 text-zinc-500 border-zinc-200' },
};

type DealStatusKey = 0 | 1 | 2 | 3;
type SeverityFilter = typeof SEVERITY_ORDER[number] | 'all';

function fmtUnixTime(ts?: number): string {
  if (!ts) return '—';
  const d = new Date(ts * 1000);
  if (isNaN(d.getTime())) return String(ts);
  return d.toLocaleString('zh-CN', { hour12: false });
}

function fmtTimeAgo(ts?: number): string {
  if (!ts) return '—';
  const diff = Math.max(0, Math.floor(Date.now() / 1000) - ts);
  if (diff < 60) return `${diff} 秒前`;
  if (diff < 3600) return `${Math.floor(diff / 60)} 分钟前`;
  if (diff < 86400) return `${Math.floor(diff / 3600)} 小时前`;
  return `${Math.floor(diff / 86400)} 天前`;
}

function safeArr<T>(v: unknown): T[] {
  return Array.isArray(v) ? (v as T[]) : [];
}

function firstOrDash<T>(arr: T[] | undefined, fmt: (x: T) => string = (x) => String(x)): string {
  if (!arr || arr.length === 0) return '—';
  return fmt(arr[0]!);
}

function joinOrDash<T>(arr: T[] | undefined, sep = ', '): string {
  if (!arr || arr.length === 0) return '—';
  return arr.map(String).join(sep);
}

export default function AlertsPanel({ onExit, onOpenInBrain }: {
  onExit: () => void;
  /** 通知父组件切换到 AiSOC 大脑面板（用于「通过大脑创建取证任务」按钮） */
  onOpenInBrain?: (seed: { domain: string; target: string; taskDesc: string }) => void;
}) {
  const [alarms, setAlarms] = useState<Alarm[]>([]);
  const [, setSummary] = useState<AlarmsSummary | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [refreshing, setRefreshing] = useState(false);
  const [lastRefreshAt, setLastRefreshAt] = useState<number>(Date.now());

  // 筛选
  const [severityFilter, setSeverityFilter] = useState<SeverityFilter>('all');
  const [verdictFilter, setVerdictFilter] = useState<string>('');
  const [searchQuery, setSearchQuery] = useState('');

  // 选中告警
  const [selectedId, setSelectedId] = useState<string | null>(null);

  // 本地处置状态（后端未提供 deal 接口，刷新后会重置）
  const [dealOverrides, setDealOverrides] = useState<Record<string, DealStatusKey>>({});

  const listRef = useRef<HTMLDivElement | null>(null);

  // Esc 退出面板（不依赖顶栏那个 ✕ 小图标）
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

  // ---------- 数据拉取 ----------
  const fetchAll = useCallback(async (isManual = false) => {
    if (isManual) setRefreshing(true);
    try {
      const [alarmsRes, summaryRes] = await Promise.all([
        aisocApi.getAlarms(DEFAULT_LIMIT).catch((e) => {
          throw new Error(`alarms: ${e instanceof Error ? e.message : String(e)}`);
        }),
        aisocApi.getAlarmsSummary().catch((e) => {
          throw new Error(`summary: ${e instanceof Error ? e.message : String(e)}`);
        }),
      ]);
      setAlarms(alarmsRes.alarms ?? []);
      setSummary(summaryRes);
      setError(null);
      setLastRefreshAt(Date.now());
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  }, []);

  useEffect(() => {
    void fetchAll();
    const timer = setInterval(() => void fetchAll(), REFRESH_INTERVAL_MS);
    return () => clearInterval(timer);
  }, [fetchAll]);

  // ---------- 派生数据 ----------
  const filtered = useMemo(() => {
    const q = searchQuery.trim().toLowerCase();
    return alarms.filter((a) => {
      if (severityFilter !== 'all' && a.severity !== severityFilter) return false;
      if (verdictFilter && (a.verdict_hint ?? '') !== verdictFilter) return false;
      if (q) {
        const haystack = [
          a.title, a.description, a.rule_id, a.host, a.url,
          ...safeArr<string>(a.source_ip), ...safeArr<string>(a.dest_ip),
        ].filter(Boolean).join(' ').toLowerCase();
        if (!haystack.includes(q)) return false;
      }
      return true;
    });
  }, [alarms, severityFilter, verdictFilter, searchQuery]);

  // 自动选中第一条（首次加载时）
  useEffect(() => {
    if (!selectedId && filtered.length > 0) {
      setSelectedId(filtered[0]!.id ?? null);
    }
  }, [filtered, selectedId]);

  const selected = useMemo(
    () => alarms.find((a) => (a.id ?? '') === (selectedId ?? '')) ?? null,
    [alarms, selectedId],
  );

  // 严重度分桶
  const severityBuckets = useMemo(() => {
    const buckets: Record<string, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    for (const a of alarms) {
      const k = a.severity ?? 'info';
      if (k in buckets) buckets[k] = (buckets[k] ?? 0) + 1;
      else buckets.info = (buckets.info ?? 0) + 1;
    }
    return buckets;
  }, [alarms]);

  // 匹配预案
  const matchedPlaybooks: Playbook[] = useMemo(
    () => (selected ? matchPlaybooks({ threat_class: selected.threat_class, rule_id: selected.rule_id }) : []),
    [selected],
  );

  // ---------- 处置操作 ----------
  const setDealStatus = (alarmId: string, status: DealStatusKey) => {
    setDealOverrides((m) => ({ ...m, [alarmId]: status }));
  };

  const effectiveDeal = (a: Alarm): DealStatusKey => {
    return (dealOverrides[a.id ?? ''] ?? a.deal_status ?? 0) as DealStatusKey;
  };

  // ---------- 复制 ----------
  const copyText = useCallback((text: string) => {
    void navigator.clipboard?.writeText(text).catch(() => {});
  }, []);

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
          <ShieldAlert className="w-4 h-4 text-red-600" />
          威胁应急告警中心
          <span className="text-[10px] font-normal text-zinc-500">
            · 独立于 AiSOC 大脑 · {alarms.length} 条
          </span>
          <span
            className="text-[10px] font-normal text-amber-700 bg-amber-50 border border-amber-200 rounded px-1.5 py-0.5"
            title="后端暂无 /api/alarms/{id}/deal 接口：处置状态仅保存在当前页面，刷新后会重置"
          >
            处置状态仅本地演示
          </span>
        </div>
        <div className="ml-auto flex items-center gap-2 text-[11px] text-zinc-500">
          <Clock className="w-3 h-3" />
          上次刷新：{fmtTimeAgo(Math.floor(lastRefreshAt / 1000))}
          <button
            type="button"
            onClick={() => void fetchAll(true)}
            disabled={refreshing}
            className="ml-2 flex items-center gap-1 rounded border border-zinc-200 px-2 py-1 hover:bg-fuchsia-50 hover:border-fuchsia-200 transition-colors disabled:opacity-50"
          >
            {refreshing ? <Loader2 className="w-3 h-3 animate-spin" /> : <RefreshCw className="w-3 h-3" />}
            刷新
          </button>
        </div>
      </header>

      {/* 严重度统计条 */}
      <div className="px-4 py-2 border-b border-zinc-100 bg-zinc-50/40 flex items-center gap-2 overflow-x-auto">
        <button
          type="button"
          onClick={() => setSeverityFilter('all')}
          className={`px-2 py-1 rounded text-[11px] border transition-colors ${
            severityFilter === 'all'
              ? 'bg-zinc-700 text-white border-zinc-700'
              : 'bg-white text-zinc-600 border-zinc-200 hover:bg-zinc-50'
          }`}
        >
          全部 ({alarms.length})
        </button>
        {SEVERITY_ORDER.map((s) => {
          const meta = SEVERITY_META[s];
          const count = severityBuckets[s] ?? 0;
          return (
            <button
              key={s}
              type="button"
              onClick={() => setSeverityFilter(s)}
              className={`px-2 py-1 rounded text-[11px] border transition-colors flex items-center gap-1 ${
                severityFilter === s
                  ? meta.cls + ' ring-1 ring-fuchsia-300'
                  : 'bg-white text-zinc-600 border-zinc-200 hover:bg-zinc-50'
              }`}
            >
              <span className={`w-1.5 h-1.5 rounded-full ${
                s === 'critical' ? 'bg-red-500' :
                s === 'high' ? 'bg-orange-500' :
                s === 'medium' ? 'bg-amber-500' :
                s === 'low' ? 'bg-sky-500' :
                'bg-zinc-400'
              }`} />
              {meta?.label ?? s} ({count})
            </button>
          );
        })}
        <div className="ml-auto flex items-center gap-1.5">
          {VERDICT_OPTIONS.map((opt) => (
            <button
              key={opt.value || 'all'}
              type="button"
              onClick={() => setVerdictFilter(opt.value)}
              className={`px-2 py-1 rounded text-[11px] border transition-colors ${
                verdictFilter === opt.value
                  ? opt.cls + ' ring-1 ring-fuchsia-300'
                  : 'bg-white text-zinc-500 border-zinc-200 hover:bg-zinc-50'
              }`}
            >
              {opt.label}
            </button>
          ))}
        </div>
      </div>

      {/* 主区：左列表 + 右详情 */}
      <div className="flex-1 min-h-0 flex">
        {/* 左：告警列表 */}
        <div className="w-[420px] border-r border-zinc-200 flex flex-col bg-white">
          {/* 搜索框 */}
          <div className="p-2 border-b border-zinc-100">
            <div className="relative">
              <Search className="w-3.5 h-3.5 absolute left-2 top-1/2 -translate-y-1/2 text-zinc-400" />
              <input
                type="text"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                placeholder="搜索 IP / URL / 规则 ID / 标题…"
                className="w-full pl-7 pr-2 py-1.5 text-xs rounded border border-zinc-200 bg-zinc-50/30 focus:outline-none focus:ring-1 focus:ring-fuchsia-200 focus:bg-white"
              />
            </div>
            <div className="mt-1.5 text-[10px] text-zinc-500 px-0.5 flex items-center gap-1">
              <Filter className="w-3 h-3" />
              命中 {filtered.length} / {alarms.length} 条
            </div>
          </div>

          {/* 列表 */}
          <div ref={listRef} className="flex-1 overflow-y-auto">
            {loading ? (
              <div className="flex items-center justify-center h-full text-zinc-500 text-xs">
                <Loader2 className="w-4 h-4 animate-spin mr-2" />
                加载告警…
              </div>
            ) : error ? (
              <div className="p-3 text-xs text-red-700 bg-red-50 border-b border-red-200">
                <div className="font-semibold mb-1 flex items-center gap-1">
                  <AlertTriangle className="w-3.5 h-3.5" /> 拉取失败
                </div>
                <div className="font-mono text-[10px] break-all">{error}</div>
                <button
                  type="button"
                  onClick={() => void fetchAll(true)}
                  className="mt-2 text-[10px] text-red-700 underline"
                >重试</button>
              </div>
            ) : filtered.length === 0 ? (
              <div className="flex flex-col items-center justify-center h-full text-zinc-400 text-xs gap-2">
                <CheckCircle2 className="w-8 h-8 text-emerald-400" />
                没有命中条件的告警
              </div>
            ) : (
              filtered.map((a) => {
                const isSelected = (a.id ?? '') === (selectedId ?? '');
                const sevMeta = SEVERITY_META[a.severity];
                const verdictMeta = a.verdict_hint ? VERDICT_META[a.verdict_hint] : undefined;
                const deal = effectiveDeal(a);
                const dealMeta = DEAL_STATUS_META[deal];
                return (
                  <button
                    type="button"
                    key={a.id ?? Math.random()}
                    onClick={() => setSelectedId(a.id ?? null)}
                    className={`w-full text-left p-2.5 border-b border-zinc-100 transition-colors flex gap-2 ${
                      isSelected ? 'bg-fuchsia-50/60 border-l-2 border-l-fuchsia-500' : 'hover:bg-zinc-50/60'
                    }`}
                  >
                    <span className={`w-1 self-stretch rounded-full shrink-0 ${
                      a.severity === 'critical' ? 'bg-red-500' :
                      a.severity === 'high' ? 'bg-orange-500' :
                      a.severity === 'medium' ? 'bg-amber-500' :
                      a.severity === 'low' ? 'bg-sky-500' : 'bg-zinc-400'
                    }`} />
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-1.5 mb-1">
                        <span className={`px-1.5 py-0.5 rounded text-[10px] border ${sevMeta?.cls ?? 'bg-zinc-100 text-zinc-700'}`}>
                          {sevMeta?.label ?? a.severity}
                        </span>
                        {verdictMeta && (
                          <span className={`px-1.5 py-0.5 rounded text-[10px] border ${verdictMeta.cls}`}>
                            {verdictMeta.icon} {verdictMeta.label}
                          </span>
                        )}
                        {deal > 0 && (
                          <span className={`px-1.5 py-0.5 rounded text-[10px] border ${dealMeta.cls}`}>
                            {dealMeta.label}
                          </span>
                        )}
                      </div>
                      <div className="text-xs font-medium text-zinc-800 truncate">
                        {a.title || a.description || '（无标题）'}
                      </div>
                      <div className="text-[10px] text-zinc-500 mt-0.5 flex items-center gap-1.5 font-mono">
                        <Network className="w-3 h-3" />
                        {joinOrDash(a.source_ip)} → {joinOrDash(a.dest_ip)}
                        <span className="text-zinc-300">|</span>
                        <Clock className="w-3 h-3" />
                        {fmtTimeAgo(a.first_time ?? a.occur_time)}
                      </div>
                    </div>
                    <ChevronRight className={`w-3.5 h-3.5 mt-1 ${isSelected ? 'text-fuchsia-500' : 'text-zinc-300'}`} />
                  </button>
                );
              })
            )}
          </div>
        </div>

        {/* 右：详情 */}
        <div className="flex-1 min-w-0 overflow-y-auto bg-zinc-50/30">
          {selected ? (
            <AlarmDetail
              alarm={selected}
              deal={effectiveDeal(selected)}
              onSetDeal={setDealStatus}
              playbooks={matchedPlaybooks}
              onCopy={copyText}
              onOpenInBrain={onOpenInBrain}
            />
          ) : (
            <div className="flex flex-col items-center justify-center h-full text-zinc-400 text-sm gap-2">
              <Activity className="w-10 h-10 text-zinc-300" />
              选择左侧告警查看详情
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

// ------------------------------------------------------------------
// 详情组件
// ------------------------------------------------------------------

function AlarmDetail({
  alarm,
  deal,
  onSetDeal,
  playbooks,
  onCopy,
  onOpenInBrain,
}: {
  alarm: Alarm;
  deal: DealStatusKey;
  onSetDeal: (id: string, status: DealStatusKey) => void;
  playbooks: Playbook[];
  onCopy: (text: string) => void;
  onOpenInBrain?: (seed: { domain: string; target: string; taskDesc: string }) => void;
}) {
  const sevMeta = SEVERITY_META[alarm.severity];
  const verdictMeta = alarm.verdict_hint ? VERDICT_META[alarm.verdict_hint] : undefined;
  const dealMeta = DEAL_STATUS_META[deal];

  // 解析 analysis 字段（可能是 JSON 字符串，里面有 think 字段）
  const analysisText = useMemo(() => {
    if (!alarm.analysis) return null;
    try {
      const obj = JSON.parse(alarm.analysis);
      // 取第一个 think 字段
      for (const k of Object.keys(obj)) {
        if (obj[k] && typeof obj[k] === 'object' && 'think' in obj[k]) {
          return String((obj[k] as { think: string }).think);
        }
      }
    } catch {
      // 不是 JSON，直接返回原文
      return alarm.analysis;
    }
    return null;
  }, [alarm.analysis]);

  // 构造「通过大脑创建取证任务」参数
  const seedTask = useMemo(() => {
    const target = firstOrDash(alarm.source_ip) !== '—'
      ? `${firstOrDash(alarm.source_ip)}（来源 IP）`
      : (alarm.host || '（未指定）');
    const desc = `对告警 [${alarm.id?.slice(0, 8) ?? '?'}] ${alarm.title ?? '（无标题）'} 做应急取证与影响面分析`;
    return { target, desc };
  }, [alarm]);

  return (
    <div className="p-4 max-w-4xl">
      {/* 标题 + 状态徽标 */}
      <div className="flex items-start gap-2 mb-3">
        <div className="flex-1 min-w-0">
          <h1 className="text-base font-bold text-zinc-800 leading-tight">
            {alarm.title || alarm.description || '（无标题告警）'}
          </h1>
          <div className="flex items-center gap-1.5 mt-1.5 flex-wrap">
            <span className={`px-2 py-0.5 rounded text-[11px] border ${sevMeta?.cls}`}>
              {sevMeta?.label ?? alarm.severity}
            </span>
            {verdictMeta && (
              <span className={`px-2 py-0.5 rounded text-[11px] border ${verdictMeta.cls}`}>
                {verdictMeta.icon} {verdictMeta.label}
              </span>
            )}
            <span className={`px-2 py-0.5 rounded text-[11px] border ${dealMeta.cls}`}>
              处置状态：{dealMeta.label}
            </span>
            {alarm.source && (
              <span className="px-2 py-0.5 rounded text-[11px] border border-zinc-200 text-zinc-600">
                来源 {alarm.source}
              </span>
            )}
            {alarm.severity_score !== undefined && (
              <span className="px-2 py-0.5 rounded text-[11px] border border-zinc-200 text-zinc-600 font-mono">
                score {alarm.severity_score}
              </span>
            )}
          </div>
        </div>
        <div className="flex items-center gap-1">
          {onOpenInBrain && (
            <button
              type="button"
              onClick={() => onOpenInBrain({
                domain: 'pentest',
                target: seedTask.target,
                taskDesc: seedTask.desc,
              })}
              className="rounded border border-fuchsia-200 bg-fuchsia-50 text-fuchsia-700 px-2 py-1 text-[11px] flex items-center gap-1 hover:bg-fuchsia-100"
              title="跳到 AiSOC 大脑面板，自动填充任务参数"
            >
              <ExternalLink className="w-3 h-3" /> 通过大脑取证
            </button>
          )}
        </div>
      </div>

      {/* 处置按钮 */}
      <div className="flex items-center gap-1.5 mb-3">
        <span className="text-[11px] text-zinc-500">处置：</span>
        {([0, 1, 2, 3] as DealStatusKey[]).map((s) => {
          const m = DEAL_STATUS_META[s];
          const active = deal === s;
          return (
            <button
              key={s}
              type="button"
              onClick={() => alarm.id && onSetDeal(alarm.id, s)}
              disabled={!alarm.id}
              className={`px-2 py-1 rounded text-[11px] border transition-colors ${
                active ? m.cls + ' ring-1 ring-fuchsia-300' : 'bg-white text-zinc-500 border-zinc-200 hover:bg-zinc-50'
              }`}
            >
              {m.label}
            </button>
          );
        })}
      </div>

      {/* 网络信息（突出显示） */}
      <section className="rounded-lg border border-zinc-200 bg-white p-3 mb-3">
        <h2 className="text-xs font-bold text-zinc-700 mb-2 flex items-center gap-1.5">
          <Network className="w-3.5 h-3.5 text-fuchsia-600" /> 网络信息
        </h2>
        <div className="grid grid-cols-2 gap-x-4 gap-y-2 text-xs">
          <Field label="攻击方 IP" value={
            <span className="font-mono flex items-center gap-1">
              {joinOrDash(alarm.source_ip)}
              {alarm.source_ip?.length ? <CopyBtn onClick={() => onCopy(alarm.source_ip!.join(','))} /> : null}
            </span>
          } />
          <Field label="受害方 IP" value={
            <span className="font-mono flex items-center gap-1">
              {joinOrDash(alarm.dest_ip)}
              {alarm.dest_ip?.length ? <CopyBtn onClick={() => onCopy(alarm.dest_ip!.join(','))} /> : null}
            </span>
          } />
          <Field label="源端口" value={
            <span className="font-mono">{joinOrDash(alarm.src_port)}</span>
          } />
          <Field label="目的端口" value={
            <span className="font-mono">{joinOrDash(alarm.dst_port)}</span>
          } />
          <Field label="协议" value={
            <span className="font-mono uppercase">{alarm.protocol ?? '—'}</span>
          } />
          <Field label="Host" value={
            <span className="font-mono">{alarm.host ?? '—'}</span>
          } />
          {alarm.url && (
            <Field label="URL" value={
              <span className="font-mono break-all">{alarm.url}</span>
            } fullWidth />
          )}
          {alarm.user_agent && (
            <Field label="User-Agent" value={
              <span className="font-mono text-[10px] break-all">{alarm.user_agent}</span>
            } fullWidth />
          )}
        </div>
      </section>

      {/* 威胁分类 */}
      <section className="rounded-lg border border-zinc-200 bg-white p-3 mb-3">
        <h2 className="text-xs font-bold text-zinc-700 mb-2 flex items-center gap-1.5">
          <Radar className="w-3.5 h-3.5 text-fuchsia-600" /> 威胁分类
        </h2>
        <div className="grid grid-cols-2 gap-x-4 gap-y-2 text-xs">
          <Field label="威胁大类" value={
            <span className="font-mono">{alarm.threat_class ?? '—'}</span>
          } />
          <Field label="威胁子类" value={
            <span className="font-mono">
              {alarm.threat_type ?? '—'}{alarm.threat_sub_type !== undefined ? ` / ${alarm.threat_sub_type}` : ''}
            </span>
          } />
          <Field label="XDR 规则" value={
            <span className="font-mono flex items-center gap-1">
              {alarm.rule_id ?? '—'}
              {alarm.rule_id ? <CopyBtn onClick={() => onCopy(alarm.rule_id!)} /> : null}
            </span>
          } />
          <Field label="触发引擎" value={
            <span>{joinOrDash(alarm.engine)}</span>
          } />
          <Field label="首次出现" value={
            <span className="font-mono text-[11px]">{fmtUnixTime(alarm.first_time)}</span>
          } />
          <Field label="最近出现" value={
            <span className="font-mono text-[11px]">{fmtUnixTime(alarm.last_time)}</span>
          } />
        </div>
      </section>

      {/* AI 研判 */}
      {analysisText && (
        <section className="rounded-lg border border-fuchsia-200 bg-fuchsia-50/30 p-3 mb-3">
          <h2 className="text-xs font-bold text-fuchsia-800 mb-2 flex items-center gap-1.5">
            <Zap className="w-3.5 h-3.5" /> AI 研判（大脑内联）
          </h2>
          <div className="text-xs leading-relaxed text-zinc-700 whitespace-pre-wrap">
            {analysisText}
          </div>
        </section>
      )}

      {/* 描述 */}
      {alarm.description && (
        <section className="rounded-lg border border-zinc-200 bg-white p-3 mb-3">
          <h2 className="text-xs font-bold text-zinc-700 mb-2">描述</h2>
          <div className="text-xs text-zinc-600 whitespace-pre-wrap">{alarm.description}</div>
        </section>
      )}

      {/* 推荐预案 */}
      <section className="rounded-lg border border-emerald-200 bg-emerald-50/30 p-3 mb-3">
        <h2 className="text-xs font-bold text-emerald-800 mb-2 flex items-center gap-1.5">
          <ShieldCheck className="w-3.5 h-3.5" /> 推荐预案
          {playbooks.length > 0 && <span className="text-[10px] font-normal">({playbooks.length} 个)</span>}
        </h2>
        {playbooks.length === 0 ? (
          <div className="text-xs text-zinc-500">
            当前告警无匹配的预案模板（threat_class={alarm.threat_class ?? '—'}, rule_id={alarm.rule_id ?? '—'}）。
            可前往「报告中心」→ 预案库 浏览全部。
          </div>
        ) : (
          <div className="space-y-2">
            {playbooks.map((pb) => (
              <details key={pb.meta.id} className="rounded border border-emerald-200 bg-white">
                <summary className="cursor-pointer px-2 py-1.5 text-xs font-medium text-emerald-800 flex items-center gap-1.5">
                  <span className="px-1.5 py-0.5 rounded bg-emerald-100 text-emerald-700 font-mono">{pb.meta.id}</span>
                  {pb.meta.name}
                  {pb.meta.estimated_minutes && (
                    <span className="ml-auto text-[10px] text-zinc-500">预计 {pb.meta.estimated_minutes} 分钟</span>
                  )}
                </summary>
                <div className="px-3 py-2 border-t border-emerald-100 text-xs">
                  <div className="prose prose-sm max-w-none prose-headings:text-sm prose-headings:font-semibold prose-h2:mt-3 prose-h2:mb-1 prose-h3:mt-2 prose-h3:mb-1 prose-li:my-0.5 prose-ul:my-1 prose-ol:my-1">
                    <ReactMarkdown remarkPlugins={[remarkGfm]}>{pb.body}</ReactMarkdown>
                  </div>
                </div>
              </details>
            ))}
          </div>
        )}
      </section>

      {/* 原始 payload（调试用） */}
      {alarm.raw && Object.keys(alarm.raw).length > 0 && (
        <details className="rounded-lg border border-zinc-200 bg-white p-2">
          <summary className="cursor-pointer text-xs text-zinc-500 flex items-center gap-1">
            <Activity className="w-3 h-3" /> 原始 payload（{Object.keys(alarm.raw).length} 字段）
          </summary>
          <pre className="mt-2 text-[10px] font-mono bg-zinc-50 p-2 rounded overflow-x-auto text-zinc-600">
            {JSON.stringify(alarm.raw, null, 2)}
          </pre>
        </details>
      )}
    </div>
  );
}

function Field({ label, value, fullWidth }: { label: string; value: React.ReactNode; fullWidth?: boolean }) {
  return (
    <div className={fullWidth ? 'col-span-2' : ''}>
      <div className="text-[10px] text-zinc-500 mb-0.5">{label}</div>
      <div className="text-zinc-800">{value}</div>
    </div>
  );
}

function CopyBtn({ onClick }: { onClick: () => void }) {
  return (
    <button
      type="button"
      onClick={onClick}
      className="rounded p-0.5 hover:bg-zinc-100 text-zinc-400 hover:text-zinc-600"
      title="复制"
    >
      <Copy className="w-3 h-3" />
    </button>
  );
}
