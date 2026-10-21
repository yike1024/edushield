/**
 * RagDemoPanel — AiSOC 安全知识库 RAG 检索 Demo 页面
 *
 * 设计目标：对外演示本地安全知识检索效果，**只读不调库、不消耗 LLM token**。
 * 直接 fetch 后端 `GET /api/rag/search?q=...&k=...`，返回 hits 列表 + score。
 *
 * 页面模式：
 *   - 「单问检索」：输入框 + 检索按钮 + 结果列表（默认）
 *   - 「三例对比」：一键并行发起 3 个示例问句，结果分 3 列并排展示，便于
 *     观众一眼看到不同 query 命中的差异（如 SQL 注入 ↔ Web 攻防；Log4j ↔ 漏洞）。
 *
 * 退出：顶栏左侧「返回主页」按钮，或键盘 Esc。
 */

import { useCallback, useEffect, useMemo, useState } from 'react';
import {
  Database,
  GitCompare,
  Loader2,
  Search,
  ShieldCheck,
  Sparkles,
  X,
} from 'lucide-react';

// ---- 类型 ----
interface RagHit {
  content: string;
  score: number;
}
interface RagResult {
  query: string;
  k: number;
  hits: RagHit[];
}

// 后端 RAG 检索端点（已就绪；CORS 已开 *）。
// 使用相对路径走前端代理（serve_frontend.py: /api/* → 127.0.0.1:6657/api/*），
// 避免 Wails 浏览器沙盒里跨端口直接 fetch 被 ERR_CONNECTION_REFUSED。
const RAG_ENDPOINT = '/api/rag/search';
const DEFAULT_K = 5;
const MAX_K = 20;

// 演示用示例问句（覆盖 5 大知识域：Web 攻击/攻防技战术/漏洞/等保合规/校园场景）
const SAMPLE_QUERIES: ReadonlyArray<{ label: string; q: string; tag: string }> = [
  { label: 'SQL 注入怎么防御', q: 'SQL注入怎么防御', tag: 'Web 攻击' },
  { label: 'Log4j 漏洞应该怎么处理', q: 'Log4j漏洞应该怎么处理', tag: '漏洞' },
  { label: '被拖库、学生信息泄露怎么办', q: '被拖库、学生信息泄露怎么办', tag: '校园场景' },
];

async function searchRag(q: string, k: number, signal?: AbortSignal): Promise<RagResult> {
  // 相对路径需要传 base，否则 URL 构造器会报 TypeError: Invalid URL。
  // 用 window.location.origin 保证和当前页面同源，走同源代理。
  const url = new URL(RAG_ENDPOINT, window.location.origin);
  url.searchParams.set('q', q);
  url.searchParams.set('k', String(k));
  const res = await fetch(url.toString(), { signal });
  if (!res.ok) {
    throw new Error(`HTTP ${res.status} ${res.statusText}`);
  }
  return (await res.json()) as RagResult;
}

export default function RagDemoPanel({ onExit }: { onExit: () => void }) {
  const [mode, setMode] = useState<'single' | 'compare'>('single');

  // 单问检索状态
  const [query, setQuery] = useState('');
  const [k, setK] = useState<number>(DEFAULT_K);
  const [singleResult, setSingleResult] = useState<RagResult | null>(null);
  const [singleLoading, setSingleLoading] = useState(false);
  const [singleError, setSingleError] = useState<string | null>(null);

  // 三例对比状态
  const [compareResults, setCompareResults] = useState<Array<{ sample: typeof SAMPLE_QUERIES[number]; result: RagResult | null; loading: boolean; error: string | null }>>([]);
  const [compareLoading, setCompareLoading] = useState(false);

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

  // 单问检索
  const runSingleSearch = useCallback(async (overrideQ?: string) => {
    const q = (overrideQ ?? query).trim();
    if (!q) {
      setSingleError('请输入问题');
      return;
    }
    setSingleLoading(true);
    setSingleError(null);
    try {
      const r = await searchRag(q, Math.min(Math.max(1, k), MAX_K));
      setSingleResult(r);
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      setSingleError(`检索失败：${msg}`);
      setSingleResult(null);
    } finally {
      setSingleLoading(false);
    }
  }, [query, k]);

  // 三例对比
  const runCompare = useCallback(async () => {
    setCompareLoading(true);
    // 先建好骨架，再并行 fetch
    const skeleton = SAMPLE_QUERIES.map((s) => ({
      sample: s,
      result: null,
      loading: true,
      error: null as string | null,
    }));
    setCompareResults(skeleton);
    await Promise.all(
      SAMPLE_QUERIES.map(async (s, idx) => {
        try {
          const r = await searchRag(s.q, DEFAULT_K);
          setCompareResults((prev) => {
            const next = [...prev];
            next[idx] = { sample: s, result: r, loading: false, error: null };
            return next;
          });
        } catch (e) {
          const msg = e instanceof Error ? e.message : String(e);
          setCompareResults((prev) => {
            const next = [...prev];
            next[idx] = { sample: s, result: null, loading: false, error: msg };
            return next;
          });
        }
      }),
    );
    setCompareLoading(false);
  }, []);

  // 顶部示例问句快捷填入（不立即检索，填到输入框）
  const fillSample = (q: string) => {
    setQuery(q);
    setMode('single');
  };

  return (
    <div className="aisoc-shell flex flex-col h-screen w-screen text-sm bg-zinc-50 text-zinc-800">
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
          <Database className="w-4 h-4 text-fuchsia-600" />
          AiSOC 安全知识库 RAG 检索
          <span className="text-[10px] font-normal text-zinc-500">
            · 独立 Demo · 只读 · 本地离线向量库
          </span>
        </div>
        <div className="ml-auto flex items-center gap-1">
          <button
            type="button"
            onClick={() => setMode('single')}
            className={`px-2.5 py-1 rounded text-[11px] flex items-center gap-1.5 border transition-colors ${
              mode === 'single'
                ? 'bg-fuchsia-50 text-fuchsia-700 border-fuchsia-200'
                : 'bg-white text-zinc-500 border-zinc-200 hover:bg-zinc-50'
            }`}
          >
            <Search className="w-3.5 h-3.5" />
            单问检索
          </button>
          <button
            type="button"
            onClick={() => setMode('compare')}
            className={`px-2.5 py-1 rounded text-[11px] flex items-center gap-1.5 border transition-colors ${
              mode === 'compare'
                ? 'bg-fuchsia-50 text-fuchsia-700 border-fuchsia-200'
                : 'bg-white text-zinc-500 border-zinc-200 hover:bg-zinc-50'
            }`}
          >
            <GitCompare className="w-3.5 h-3.5" />
            三例对比
          </button>
        </div>
      </header>

      {/* 说明条 */}
      <div className="px-4 py-2 border-b border-zinc-100 bg-zinc-50/60 text-[11px] text-zinc-600 leading-relaxed">
        针对威胁 / 漏洞 / 合规问题，系统可在本地安全知识库快速召回相关处置建议与依据。
        知识域：<span className="text-zinc-800 font-medium">Web 攻击</span> /{' '}
        <span className="text-zinc-800 font-medium">攻防技战术</span> /{' '}
        <span className="text-zinc-800 font-medium">漏洞</span> /{' '}
        <span className="text-zinc-800 font-medium">等保合规</span> /{' '}
        <span className="text-zinc-800 font-medium">校园场景</span>。
        本 Demo <span className="font-medium text-fuchsia-700">仅展示检索层能力</span>，完整能力还会把召回结果注入到智能体对话与威胁判定中作为参考依据。
      </div>

      {/* 主体 */}
      <div className="flex-1 min-h-0 overflow-y-auto">
        {mode === 'single' ? (
          <SingleMode
            query={query}
            setQuery={setQuery}
            k={k}
            setK={setK}
            loading={singleLoading}
            error={singleError}
            result={singleResult}
            onRun={runSingleSearch}
            onFillSample={fillSample}
          />
        ) : (
          <CompareMode
            results={compareResults}
            loading={compareLoading}
            onRun={runCompare}
          />
        )}
      </div>

      {/* 底部演示口径 */}
      <footer className="px-4 py-2 border-t border-zinc-200 bg-white text-[10px] text-zinc-500 leading-relaxed">
          <span className="font-medium text-zinc-700">演示口径：</span>
          检索是<span className="text-zinc-800 font-medium">本地离线向量库</span>，不给模型改 prompt、不调用模型，
          只返回相似知识召回 — 以体现「知识库端到端检索」已在后端可用。
          {' '}本接口只读、不写库、不消耗模型 token，可放心频繁演示。
      </footer>
    </div>
  );
}

// ===== 单问检索模式 =====
function SingleMode({
  query,
  setQuery,
  k,
  setK,
  loading,
  error,
  result,
  onRun,
  onFillSample,
}: {
  query: string;
  setQuery: (s: string) => void;
  k: number;
  setK: (n: number) => void;
  loading: boolean;
  error: string | null;
  result: RagResult | null;
  onRun: (overrideQ?: string) => Promise<void> | void;
  onFillSample: (q: string) => void;
}) {
  const maxScore = useMemo(() => {
    if (!result?.hits?.length) return 0;
    return Math.max(...result.hits.map((h) => h.score));
  }, [result]);

  return (
    <div className="px-4 py-3 max-w-4xl mx-auto w-full">
      {/* 输入区 */}
      <section className="rounded-lg border border-zinc-200 bg-white p-3 mb-3">
        <div className="flex items-center gap-2 mb-2">
          <label className="text-[11px] text-zinc-500 shrink-0">问句：</label>
          <input
            type="text"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === 'Enter' && !e.shiftKey) {
                e.preventDefault();
                void onRun();
              }
            }}
            placeholder="例：SQL 注入怎么防御（按 Enter 检索）"
            className="flex-1 px-3 py-2 rounded border border-zinc-300 text-sm focus:outline-none focus:border-fuchsia-400 focus:ring-1 focus:ring-fuchsia-200"
            disabled={loading}
          />
          <label className="text-[11px] text-zinc-500 shrink-0 flex items-center gap-1">
            k=
            <select
              value={k}
              onChange={(e) => setK(Number(e.target.value))}
              disabled={loading}
              className="px-1 py-1 rounded border border-zinc-300 text-xs bg-white"
            >
              {[3, 5, 8, 10, 15, 20].map((n) => (
                <option key={n} value={n}>{n}</option>
              ))}
            </select>
          </label>
          <button
            type="button"
            onClick={() => void onRun()}
            disabled={loading || !query.trim()}
            className="px-4 py-2 rounded bg-fuchsia-600 text-white text-xs font-medium flex items-center gap-1.5 hover:bg-fuchsia-700 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
          >
            {loading ? (
              <Loader2 className="w-3.5 h-3.5 animate-spin" />
            ) : (
              <Search className="w-3.5 h-3.5" />
            )}
            检索
          </button>
        </div>
        <div className="flex items-center gap-1.5 flex-wrap text-[11px]">
          <span className="text-zinc-500 shrink-0">示例问句：</span>
          {SAMPLE_QUERIES.map((s) => (
            <button
              key={s.q}
              type="button"
              onClick={() => onFillSample(s.q)}
              disabled={loading}
              className="px-2 py-1 rounded border border-zinc-200 bg-white text-zinc-700 hover:bg-zinc-50 hover:border-fuchsia-200 transition-colors flex items-center gap-1"
              title={`点击填入：${s.q}（${s.tag}）`}
            >
              <Sparkles className="w-3 h-3 text-fuchsia-500" />
              {s.label}
            </button>
          ))}
        </div>
      </section>

      {/* 错误提示 */}
      {error && (
        <div className="rounded-lg border border-red-200 bg-red-50 text-red-700 text-xs p-2.5 mb-3">
          {error}
        </div>
      )}

      {/* 结果区 */}
      {loading ? (
        <div className="rounded-lg border border-zinc-200 bg-white p-8 flex flex-col items-center justify-center text-zinc-500 text-xs gap-2">
          <Loader2 className="w-6 h-6 animate-spin text-fuchsia-500" />
          正在检索本地知识库…
        </div>
      ) : result ? (
        <ResultList result={result} maxScore={maxScore} />
      ) : (
        <EmptyState />
      )}
    </div>
  );
}

// ===== 三例对比模式 =====
function CompareMode({
  results,
  loading,
  onRun,
}: {
  results: Array<{ sample: typeof SAMPLE_QUERIES[number]; result: RagResult | null; loading: boolean; error: string | null }>;
  loading: boolean;
  onRun: () => void;
}) {
  return (
    <div className="px-4 py-3 max-w-7xl mx-auto w-full">
      <section className="rounded-lg border border-zinc-200 bg-white p-3 mb-3">
        <div className="flex items-center gap-3">
          <div className="flex-1 text-xs text-zinc-600">
            一键并行发起 3 个示例问句的检索（Web 攻击 / 漏洞 / 校园场景三个域），结果分列并排展示，便于观众一眼看到不同 query 命中的差异。
          </div>
          <button
            type="button"
            onClick={onRun}
            disabled={loading}
            className="px-4 py-2 rounded bg-fuchsia-600 text-white text-xs font-medium flex items-center gap-1.5 hover:bg-fuchsia-700 disabled:opacity-50 disabled:cursor-not-allowed transition-colors shrink-0"
          >
            {loading ? (
              <Loader2 className="w-3.5 h-3.5 animate-spin" />
            ) : (
              <GitCompare className="w-3.5 h-3.5" />
            )}
            {results.length > 0 ? '重新对比' : '开始对比'}
          </button>
        </div>
      </section>

      {results.length === 0 ? (
        <div className="rounded-lg border border-zinc-200 bg-white p-8 flex flex-col items-center justify-center text-zinc-400 text-xs gap-2">
          <GitCompare className="w-8 h-8 text-zinc-300" />
          点击「开始对比」发起并行检索
        </div>
      ) : (
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-3">
          {results.map((r, i) => (
            <CompareColumn key={i} {...r} />
          ))}
        </div>
      )}
    </div>
  );
}

function CompareColumn({
  sample,
  result,
  loading,
  error,
}: {
  sample: typeof SAMPLE_QUERIES[number];
  result: RagResult | null;
  loading: boolean;
  error: string | null;
}) {
  const maxScore = useMemo(() => {
    if (!result?.hits?.length) return 0;
    return Math.max(...result.hits.map((h) => h.score));
  }, [result]);

  return (
    <div className="rounded-lg border border-zinc-200 bg-white p-3 flex flex-col min-h-0">
      <div className="flex items-center gap-1.5 mb-2">
        <span className="px-1.5 py-0.5 rounded text-[9px] font-mono bg-fuchsia-100 text-fuchsia-700 border border-fuchsia-200">
          {sample.tag}
        </span>
        <h3 className="text-xs font-semibold text-zinc-800 flex-1 min-w-0 truncate" title={sample.q}>
          {sample.label}
        </h3>
        {result && (
          <span className="text-[10px] text-zinc-500 shrink-0">
            {result.hits.length} 条
          </span>
        )}
      </div>

      {loading ? (
        <div className="flex flex-col items-center justify-center py-8 text-zinc-400 text-xs gap-2">
          <Loader2 className="w-5 h-5 animate-spin text-fuchsia-500" />
          检索中…
        </div>
      ) : error ? (
        <div className="text-xs text-red-600 bg-red-50 border border-red-200 rounded p-2">
          {error}
        </div>
      ) : result ? (
        <div className="space-y-2 overflow-y-auto">
          {result.hits.length === 0 ? (
            <div className="text-xs text-zinc-500 italic">未命中</div>
          ) : (
            result.hits.map((h, i) => (
              <HitCard key={i} hit={h} maxScore={maxScore} compact />
            ))
          )}
        </div>
      ) : null}
    </div>
  );
}

// ===== 结果列表（单问检索用） =====
function ResultList({ result, maxScore }: { result: RagResult; maxScore: number }) {
  return (
    <section className="rounded-lg border border-zinc-200 bg-white p-3">
      <div className="flex items-center gap-2 mb-2.5">
        <ShieldCheck className="w-3.5 h-3.5 text-fuchsia-600" />
        <h2 className="text-xs font-bold text-zinc-700">检索结果</h2>
        <span className="text-[10px] text-zinc-500">
          · 命中 {result.hits.length} 条 · 最高相关度 {maxScore > 0 ? maxScore.toFixed(1) : '—'}
        </span>
      </div>
      {result.hits.length === 0 ? (
        <div className="text-xs text-zinc-500 italic py-4 text-center">
          未命中本地知识，可换一种问法
        </div>
      ) : (
        <div className="space-y-2">
          {result.hits.map((h, i) => (
            <HitCard key={i} hit={h} maxScore={maxScore} />
          ))}
        </div>
      )}
    </section>
  );
}

// ===== 单条命中卡片 =====
function HitCard({ hit, maxScore, compact = false }: { hit: RagHit; maxScore: number; compact?: boolean }) {
  const ratio = maxScore > 0 ? Math.min(100, Math.max(0, (hit.score / maxScore) * 100)) : 0;
  // 颜色梯度：高分绿、中分黄、低分灰
  const barColor =
    hit.score >= maxScore * 0.7 ? 'bg-emerald-500' :
    hit.score >= maxScore * 0.4 ? 'bg-amber-500' :
    'bg-zinc-400';

  return (
    <article
      className={`rounded-md border border-zinc-200 bg-white p-2.5 ${compact ? '' : 'hover:border-fuchsia-200 hover:bg-fuchsia-50/30'} transition-colors`}
    >
      <div className={`text-xs leading-relaxed text-zinc-800 whitespace-pre-wrap ${compact ? '' : 'mb-1.5'}`}>
        {hit.content}
      </div>
      <div className="flex items-center gap-2">
        <span className="text-[10px] text-zinc-500 shrink-0 font-mono">
          相关度 {hit.score.toFixed(1)}
        </span>
        <div className="flex-1 h-1.5 bg-zinc-100 rounded-full overflow-hidden">
          <div
            className={`h-full ${barColor} rounded-full transition-all`}
            style={{ width: `${ratio}%` }}
          />
        </div>
        <span className="text-[10px] text-zinc-400 shrink-0 font-mono">
          {ratio.toFixed(0)}%
        </span>
      </div>
    </article>
  );
}

// ===== 空状态 =====
function EmptyState() {
  return (
    <div className="rounded-lg border border-zinc-200 bg-white p-8 flex flex-col items-center justify-center text-zinc-400 text-xs gap-2">
      <Search className="w-8 h-8 text-zinc-300" />
      <div>在上方输入问题，或点击「示例问句」一键填入</div>
    </div>
  );
}