/**
 * AiSOC 大脑平台仪表板
 * 按 docs/frontend-api.md（大脑 FastAPI :6657）实现。
 *
 * 布局：
 *   ┌──────────────────────────────────────────────────────────────────────┐
 *   │ 顶栏：大脑健康灯 + 4 子部件连接灯 + 创建任务按钮                       │
 *   ├──────────────┬───────────────────────────────────────────────────────┤
 *   │ 左列（架构视图）:                                                    │
 *   │  · 大脑中心卡片 + 四部件节点（注册表数组驱动）                       │
 *   │  · 任务创建表单（任务描述 × domain × pipeline × target × tools）     │
 *   ├──────────────┼───────────────────────────────────────────────────────┤
 *   │ 右列（三 Tab 可切换）:                                               │
 *   │  Tab1 任务列表：所有任务 + 状态徽标 + 点击选中                        │
 *   │  Tab2 实时面板：RealtimePanel（agent 状态墙 + SSE 流式输出）         │
 *   │  Tab3 详情：Finding 证据表 + Verdict 判定卡 + Markdown 报告          │
 *   └──────────────┴───────────────────────────────────────────────────────┘
 */

import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import {
  ArrowLeft,
  Activity,
  AlertTriangle,
  CheckCircle2,
  ChevronRight,
  Cpu,
  Database,
  Download,
  FileSearch,
  FileText,
  Gavel,
  Layers,
  Loader2,
  MessageSquare,
  Minus,
  TerminalSquare,
  Network,
  Play,
  Plus,
  RefreshCw,
  Rocket,
  Radar,
  Send,
  ShieldAlert,
  ShieldCheck,
  Sparkles,
  X,
  Zap,
} from 'lucide-react';
import RealtimePanel from './RealtimePanel';
import ReactMarkdown from 'react-markdown';
import remarkGfm from 'remark-gfm';
import { getWebApi } from '../lib/webApiProxy';
import { applyStreamEvent } from '../lib/aisocStreamItems';
import { buildMockWafCommand, type MockWafCommand } from '../lib/mockWafCommand';
import { summarizeTirAvailability, type TirAvailability } from '../lib/tirAvailability';
import {
  aisocApi,
  AisocApiError,
  DOMAIN_COLORS,
  DOMAIN_DESCRIPTIONS,
  DOMAIN_LABELS,
  DOMAIN_PORTS,
  SEVERITY_META,
  TASK_STATUS_META,
  VERDICT_META,
  type CreateTaskInput,
  type Finding,
  type RegistryPart,
  type ReportDoc,
  type TaskDetail,
  type TaskInfo,
  type AgentsStatus,
  type WhitelistView,
  type TirAlert,
  type TirPlaybook,
  type TirReport,
  type MockWafBlockResponse,
} from '../lib/aisoc-api';

// ---------------------------------------------------------------------------
// 小工具
// ---------------------------------------------------------------------------

const ALL_DOMAINS: CreateTaskInput['domain'][] = ['pentest', 'logaudit', 'intel', 'incident'];

/** TIR 调用失败的归因状态码：已知 HTTP 状态原样返回，网络/未知错误按不可达(0)处理。 */
function tirFailureStatus(error: unknown): number {
  if (error instanceof AisocApiError) return error.status;
  return 0;
}

/** 阶段名 → 中文显示（文档 §4.2 stages 元素） */
const STAGE_LABELS: Record<string, string> = {
  logaudit: '日志审计',
  pentest: '渗透测试',
  verdict: '威胁判定',
  tir: '威胁情报',
  report: '报告',
};

function fmtTime(iso: string): string {
  if (!iso) return '—';
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  return d.toLocaleString('zh-CN', { hour12: false });
}

function fmtAgo(iso: string): string {
  if (!iso) return '—';
  const diff = Date.now() - new Date(iso).getTime();
  if (Number.isNaN(diff) || diff < 0) return '—';
  const s = Math.floor(diff / 1000);
  if (s < 60) return `${s} 秒前`;
  const m = Math.floor(s / 60);
  if (m < 60) return `${m} 分钟前`;
  const h = Math.floor(m / 60);
  if (h < 24) return `${h} 小时前`;
  const d = Math.floor(h / 24);
  return `${d} 天前`;
}

// ---------------------------------------------------------------------------
// 架构拓扑：大脑居中 → 星型连线 → 四部件节点
// ---------------------------------------------------------------------------

type ConnectState = 'ok' | 'warn' | 'off' | 'loading';

function stateFromHealth(ok: boolean | null, running: boolean): ConnectState {
  if (ok === null) return running ? 'loading' : 'off';
  return ok ? 'ok' : 'warn';
}

const CONNECT_STYLE: Record<ConnectState, { dot: string; label: string; line: string }> = {
  ok:      { dot: 'bg-emerald-500', label: '在线',  line: 'bg-emerald-300' },
  warn:    { dot: 'bg-amber-500',   label: '告警',  line: 'bg-amber-300' },
  off:     { dot: 'bg-zinc-400',    label: '离线',  line: 'bg-zinc-200' },
  loading: { dot: 'bg-sky-500 animate-pulse', label: '检测中', line: 'bg-sky-300' },
};

// ---------------------------------------------------------------------------
// 流程监控图（agent 介绍 → 大脑下发任务的动态拓扑）
//
// 作用：顶视图呈现“用户 → 大脑 → 4 Agent”的数据流。
// - 节点状态（在线/告警/离线/检测中）由大脑 + /api/registry + /api/agents/status 实时驱动。
// - 边状态（静态/有任务在跑）由 tasks 聚合驱动：
//   - domain='pentest'/'logaudit'/'intel'/'incident' 的 running 任务 → 对应 Agent 边高亮。
//   - domain='all' 的 pipeline 任务（data_leak）→ 按 current_stage 高亮对应 Agent 边。
// - 边动画：SVG <path stroke-dasharray> 实现流光，运载感从大脑→Agent 或 Agent→大脑。
// - 节点点击复用 DomainNode 行为：Agent 节点点击预填任务表单 domain / target；用户节点点击聚焦快聊输入框。
// ---------------------------------------------------------------------------

type FlowEdge = {
  from: 'user' | 'brain' | string;
  to: 'user' | 'brain' | string;
  d: string;            // SVG path d
  /** 当前在这条边上的任务数（0=静态，>0=高亮 + 动画） */
  load: number;
};

const SHORT_DOMAIN_LABELS: Record<string, string> = {
  pentest: '渗透',
  logaudit: '审计',
  intel: '情报',
  incident: '应急',
};

function ArchitectureFlow({
  brainState,
  domainStates,
  tasks,
  onSelectAgent,
  onFocusUserInput,
}: {
  brainState: ConnectState;
  domainStates: Record<string, ConnectState>;
  tasks: TaskInfo[];
  onSelectAgent?: (domain: string) => void;
  onFocusUserInput?: () => void;
}) {
  // 聚合每条 Agent 边的运行中任务数。
  // pipeline 任务（domain='all'）按 current_stage 路由：
  //   current_stage='logaudit'/'pentest' 时归入对应 Agent 边；
  //   verdict/tir/report 是大脑内部决策（不算 Agent），归到 brain 节点本身的高亮上。
  // 注意：TaskInfo.domain 是 TaskDomain（不含 'all'），但后端 pipeline 任务实际会返回 'all'，
  // 用 (t.domain as string) === 'all' 绕过类型检查（运行时安全）。
  const loadByDomain = useMemo(() => {
    const out: Record<string, number> = { pentest: 0, logaudit: 0, intel: 0, incident: 0 };
    for (const t of tasks) {
      if (t.status !== 'running' && t.status !== 'pending') continue;
      const d = (t.domain as string) === 'all'
        ? ((t.current_stage ?? '').toLowerCase())
        : (t.domain as string);
      if (out[d] !== undefined) {
        out[d] = (out[d] ?? 0) + 1;
      }
    }
    return out;
  }, [tasks]);

  const totalRunning = tasks.filter(t => t.status === 'running' || t.status === 'pending').length;

  // === 关键：所有节点与边都画在同一个 SVG 内，使用同一坐标系（viewBox）===
  // 这样无论容器宽度怎么变，节点和边永远精确对齐——
  // SVG 是一个坐标系，path d 和 rect/text x/y 都用 viewBox 数字，一起缩放。
  const W = 360;
  const H = 230;

  // 节点坐标（viewBox 单位 360×230）：
  //   用户  24,100   64×32  （左）
  //   大脑  148,100  64×32  （中）
  //   Agent 节点 254,  64×24  （右侧四个，竖排）
  const nodes = {
    user:    { x: 24,  y: 100, w: 64, h: 32 },
    brain:   { x: 148, y: 100, w: 64, h: 32 },
    pentest:  { x: 254, y: 14,  w: 90, h: 24 },
    logaudit: { x: 254, y: 60,  w: 90, h: 24 },
    intel:    { x: 254, y: 106, w: 90, h: 24 },
    incident: { x: 254, y: 152, w: 90, h: 24 },
  };
  const nodeMidY = (n: { y: number; h: number }) => n.y + n.h / 2;
  const nodeRightX = (n: { x: number; w: number }) => n.x + n.w;
  const nodeLeftX = (n: { x: number }) => n.x;

  // 边路径：用节点中心点 / 边缘点画贝塞尔曲线，永远精确对齐节点边缘。
  const edges: FlowEdge[] = [
    {
      from: 'user', to: 'brain',
      d: `M ${nodeRightX(nodes.user)} ${nodeMidY(nodes.user)} C ${nodeRightX(nodes.user) + 18} ${nodeMidY(nodes.user)}, ${nodeLeftX(nodes.brain) - 18} ${nodeMidY(nodes.brain)}, ${nodeLeftX(nodes.brain)} ${nodeMidY(nodes.brain)}`,
      load: totalRunning,
    },
    {
      from: 'brain', to: 'pentest',
      d: `M ${nodeRightX(nodes.brain)} ${nodeMidY(nodes.brain) - 3} C ${nodeRightX(nodes.brain) + 18} ${nodeMidY(nodes.brain) - 3}, ${nodeLeftX(nodes.pentest) - 12} ${nodeMidY(nodes.pentest)}, ${nodeLeftX(nodes.pentest)} ${nodeMidY(nodes.pentest)}`,
      load: loadByDomain.pentest,
    },
    {
      from: 'brain', to: 'logaudit',
      d: `M ${nodeRightX(nodes.brain)} ${nodeMidY(nodes.brain) - 1} C ${nodeRightX(nodes.brain) + 18} ${nodeMidY(nodes.brain) - 1}, ${nodeLeftX(nodes.logaudit) - 12} ${nodeMidY(nodes.logaudit)}, ${nodeLeftX(nodes.logaudit)} ${nodeMidY(nodes.logaudit)}`,
      load: loadByDomain.logaudit,
    },
    {
      from: 'brain', to: 'intel',
      d: `M ${nodeRightX(nodes.brain)} ${nodeMidY(nodes.brain) + 1} C ${nodeRightX(nodes.brain) + 18} ${nodeMidY(nodes.brain) + 1}, ${nodeLeftX(nodes.intel) - 12} ${nodeMidY(nodes.intel)}, ${nodeLeftX(nodes.intel)} ${nodeMidY(nodes.intel)}`,
      load: loadByDomain.intel,
    },
    {
      from: 'brain', to: 'incident',
      d: `M ${nodeRightX(nodes.brain)} ${nodeMidY(nodes.brain) + 3} C ${nodeRightX(nodes.brain) + 18} ${nodeMidY(nodes.brain) + 3}, ${nodeLeftX(nodes.incident) - 12} ${nodeMidY(nodes.incident)}, ${nodeLeftX(nodes.incident)} ${nodeMidY(nodes.incident)}`,
      load: loadByDomain.incident,
    },
  ];

  // 边状态颜色（实际十六进制，不依赖 CSS class）
  const edgeBaseColor = '#a1a1aa';      // zinc-400
  const edgeActiveColor = '#10b981';     // emerald-500
  const edgeActiveColorPipeline = '#d946ef'; // fuchsia-500
  const isBrainBusy = totalRunning > 0;

  // 节点状态灯颜色（CONNECT_STYLE 的 dot class → 实际色）
  const STATE_DOT_COLOR: Record<ConnectState, string> = {
    ok:      '#10b981',  // emerald-500
    warn:    '#f59e0b',  // amber-500
    off:     '#a1a1aa',  // zinc-400
    loading: '#0ea5e9',  // sky-500
  };

  // Agent 节点主色（DOMAIN_COLORS 的 dot → 实际色，用于边框 / load 徽章）
  const DOMAIN_DOT_COLOR: Record<string, string> = {
    pentest:  '#f43f5e',  // rose-500
    logaudit: '#0ea5e9',  // sky-500
    intel:    '#f59e0b',  // amber-500
    incident: '#10b981',  // emerald-500
  };

  const hasPipeline = tasks.some(t => (t.domain as string) === 'all' && (t.status === 'running' || t.status === 'pending'));

  return (
    <div className="rounded-xl border border-fuchsia-200 bg-gradient-to-br from-fuchsia-50/30 to-white p-2.5">
      <div className="flex items-center justify-between mb-1 gap-2">
        <div className="text-[11px] font-bold text-zinc-700 flex items-center gap-1 min-w-0">
          <Network className="w-3 h-3 text-fuchsia-600 shrink-0" />
          <span className="truncate">流程监控图</span>
        </div>
        <div className="text-[9px] text-zinc-500 flex items-center gap-1.5 shrink-0">
          <span className="flex items-center gap-0.5" title="空闲边">
            <span className="inline-block w-2.5 h-0.5 bg-zinc-400" />
            空闲
          </span>
          <span className="flex items-center gap-0.5" title="单域任务在跑">
            <span className="inline-block w-2.5 h-0.5 bg-emerald-500" />
            单域
          </span>
          <span className="flex items-center gap-0.5" title="Pipeline 任务在跑">
            <span className="inline-block w-2.5 h-0.5 bg-fuchsia-500" />
            管道
          </span>
        </div>
      </div>

      {/*
        * 整个流程图（节点 + 边）都在一个 SVG 内画，使用统一的 viewBox 坐标系。
        * 优点：无论容器宽度怎么变（卡片被左列挤压/拉宽），节点和边永远精确对齐——
        * 因为 rect / text / path 都用 viewBox 数字，SVG 是一个坐标系整体缩放。
        * 之前用 absolute + 百分比的方案，节点和 SVG path 走两套坐标系，缩放时可能错位。
        */}
      <svg
        width="100%"
        height={H}
        viewBox={`0 0 ${W} ${H}`}
        preserveAspectRatio="xMidYMid meet"
        style={{ display: 'block', overflow: 'visible' }}
      >
        <defs>
          <marker id="flow-arrow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="5" markerHeight="5" orient="auto-start-reverse">
            <path d="M 0 0 L 10 5 L 0 10 z" fill={edgeBaseColor} />
          </marker>
          <marker id="flow-arrow-active" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="5" markerHeight="5" orient="auto-start-reverse">
            <path d="M 0 0 L 10 5 L 0 10 z" fill={edgeActiveColor} />
          </marker>
          <marker id="flow-arrow-pipeline" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="5" markerHeight="5" orient="auto-start-reverse">
            <path d="M 0 0 L 10 5 L 0 10 z" fill={edgeActiveColorPipeline} />
          </marker>
        </defs>

        {/* 边 */}
        {edges.map((e, idx) => {
          const isActive = e.load > 0;
          const color = isActive ? (hasPipeline ? edgeActiveColorPipeline : edgeActiveColor) : edgeBaseColor;
          const marker = isActive ? (hasPipeline ? 'flow-arrow-pipeline' : 'flow-arrow-active') : 'flow-arrow';
          return (
            <g key={`edge-${idx}`}>
              {/* 底层灰线（始终显示，让路径位置固定） */}
              <path d={e.d} stroke={edgeBaseColor} strokeWidth={1.2} fill="none" opacity={isActive ? 0.3 : 1} markerEnd={`url(#${marker})`} />
              {/* 高亮流动线：stroke-dasharray + 动画 dashoffset */}
              {isActive && (
                <path
                  d={e.d}
                  stroke={color}
                  strokeWidth={1.6}
                  fill="none"
                  strokeDasharray="3 5"
                  style={{ animation: 'flow-dash 1.4s linear infinite' }}
                />
              )}
            </g>
          );
        })}

        {/* 用户节点：rect + 小图标圆点 + 文字 */}
        <g
          onClick={() => onFocusUserInput?.()}
          style={{ cursor: 'pointer' }}
          data-testid="flow-user-node"
          role="button"
          aria-label="用户节点：点击聚焦快聊输入框"
        >
          <rect
            x={nodes.user.x} y={nodes.user.y} width={nodes.user.w} height={nodes.user.h} rx={6}
            fill="#ffffff" stroke="#a1a1aa" strokeWidth={1.5}
          />
          {/* 用户图标：简笔画（圆头 + 半圆肩） */}
          <circle cx={nodes.user.x + 12} cy={nodes.user.y + 12} r={2.4} fill="#52525b" />
          <path d={`M ${nodes.user.x + 8} ${nodes.user.y + 21} a 4 3.5 0 0 1 8 0`} fill="#52525b" />
          <text
            x={nodes.user.x + 26} y={nodes.user.y + 21}
            fontSize={11} fontWeight={600} fill="#3f3f46"
          >用户</text>
        </g>

        {/* 大脑节点 */}
        <g
          data-testid="flow-brain-node"
          role="img"
          aria-label={`AiSOC 大脑 — ${CONNECT_STYLE[brainState].label} | 运行中 ${totalRunning} 个任务`}
        >
          <rect
            x={nodes.brain.x} y={nodes.brain.y} width={nodes.brain.w} height={nodes.brain.h} rx={6}
            fill="#ffffff"
            stroke={isBrainBusy ? '#d946ef' : '#e879f9'}
            strokeWidth={1.5}
          />
          {/* 中心图标：忙碌时画 loader 同心圆（旋转感用 stroke-dasharray 表达），空闲画一颗八角星 */}
          {isBrainBusy ? (
            <g transform={`translate(${nodes.brain.x + 11}, ${nodes.brain.y + 16})`}>
              <circle r={5} fill="none" stroke="#d946ef" strokeWidth={1.5} strokeDasharray="3 2">
                <animateTransform attributeName="transform" type="rotate" from="0" to="360" dur="1.2s" repeatCount="indefinite" />
              </circle>
            </g>
          ) : (
            <g transform={`translate(${nodes.brain.x + 11}, ${nodes.brain.y + 16})`}>
              {/* 八角星 */}
              <path
                d="M 0 -5 L 1.5 -1.5 L 5 0 L 1.5 1.5 L 0 5 L -1.5 1.5 L -5 0 L -1.5 -1.5 Z"
                fill="#d946ef"
              />
            </g>
          )}
          <text
            x={nodes.brain.x + 22} y={nodes.brain.y + 21}
            fontSize={11} fontWeight={700} fill="#a21caf"
          >大脑</text>
          {totalRunning > 0 && (
            <g>
              <circle
                cx={nodeRightX(nodes.brain) - 2}
                cy={nodes.brain.y - 2}
                r={7}
                fill="#d946ef"
                stroke="#ffffff"
                strokeWidth={1}
              />
              <text
                x={nodeRightX(nodes.brain) - 2}
                y={nodes.brain.y + 1.5}
                fontSize={9} fontWeight={700} fill="#ffffff"
                textAnchor="middle"
              >{totalRunning}</text>
            </g>
          )}
        </g>

        {/* 4 Agent 节点 */}
        {(['pentest', 'logaudit', 'intel', 'incident'] as const).map((d) => {
          const n = nodes[d];
          const state = domainStates[d] ?? 'off';
          const dotColor = STATE_DOT_COLOR[state];
          const load = loadByDomain[d] ?? 0;
          const active = load > 0;
          const mainColor = DOMAIN_DOT_COLOR[d] ?? '#71717a';
          return (
            <g
              key={d}
              onClick={() => onSelectAgent?.(d)}
              style={{ cursor: 'pointer' }}
              data-testid={`flow-agent-${d}`}
              role="button"
              aria-label={`${DOMAIN_LABELS[d] ?? d} — ${CONNECT_STYLE[state].label}${load > 0 ? `（${load} 个任务在跑）` : ''}`}
            >
              <rect
                x={n.x} y={n.y} width={n.w} height={n.h} rx={6}
                fill="#ffffff"
                stroke={active ? mainColor : '#e4e4e7'}
                strokeWidth={active ? 1.8 : 1.2}
              />
              {/* 状态灯圆点 */}
              <circle cx={n.x + 9} cy={n.y + n.h / 2} r={3.2} fill={dotColor}>
                {state === 'loading' && (
                  <animate attributeName="opacity" values="1;0.4;1" dur="1.4s" repeatCount="indefinite" />
                )}
              </circle>
              {/* 节点文字 */}
              <text
                x={n.x + 18} y={n.y + n.h / 2 + 3.5}
                fontSize={10.5} fontWeight={500} fill="#3f3f46"
              >{SHORT_DOMAIN_LABELS[d] ?? d}</text>
              {/* load 徽章 */}
              {active && (
                <g>
                  <circle
                    cx={nodeRightX(n) - 1}
                    cy={n.y - 1}
                    r={6.5}
                    fill={mainColor}
                    stroke="#ffffff"
                    strokeWidth={1}
                  />
                  <text
                    x={nodeRightX(n) - 1}
                    y={n.y + 2}
                    fontSize={8.5} fontWeight={700} fill="#ffffff"
                    textAnchor="middle"
                  >{load}</text>
                </g>
              )}
            </g>
          );
        })}
      </svg>

      <style>{`
        @keyframes flow-dash {
          from { stroke-dashoffset: 0; }
          to   { stroke-dashoffset: -16; }
        }
      `}</style>
    </div>
  );
}

function DomainNode({
  domain, registry, state, onClick, portOverride,
}: {
  domain: string;
  registry?: RegistryPart;
  state: ConnectState;
  onClick: () => void;
  /** 优先级：registry.port > portOverride > DOMAIN_PORTS 默认值 */
  portOverride?: number;
}) {
  const color = DOMAIN_COLORS[domain] ?? DOMAIN_COLORS.brain;
  const style = CONNECT_STYLE[state];
  const port = registry?.port ?? portOverride ?? DOMAIN_PORTS[domain];
  return (
    <button
      type="button"
      onClick={onClick}
      className={`group w-full text-left rounded-xl border ring-1 ${color.ring} ${color.bg} p-3 hover:shadow-md transition-all`}
    >
      <div className="flex items-center gap-2 mb-1">
        <span className={`w-2.5 h-2.5 rounded-full ${style.dot}`} />
        <span className="font-semibold text-sm text-zinc-800">{DOMAIN_LABELS[domain] ?? domain}</span>
      </div>
      <div className="text-xs text-zinc-500 font-mono mb-1">
        {registry ? `${registry.host}:${registry.port}` : `(默认) 127.0.0.1:${port}`}
      </div>
      <div className="text-xs text-zinc-600 leading-snug mb-2">{DOMAIN_DESCRIPTIONS[domain]}</div>
      <div className="flex items-center justify-between text-xs">
        <span className={`px-1.5 py-0.5 rounded text-xs font-medium text-white ${style.dot}`}>
          {style.label}
        </span>
        <span className="text-zinc-400 group-hover:text-zinc-600 transition-colors">详情 →</span>
      </div>
    </button>
  );
}

function BrainCenterCard({ brainState, registryLoaded, registryCount }: {
  brainState: ConnectState; registryLoaded: boolean; registryCount: number;
}) {
  const color = DOMAIN_COLORS.brain;
  const style = CONNECT_STYLE[brainState];
  return (
    <div className={`relative rounded-2xl ring-2 ${color.ring} ${color.bg} border px-5 py-4 flex items-center gap-4`}>
      <div className={`w-14 h-14 rounded-full ${color.dot} flex items-center justify-center shadow-lg shadow-fuchsia-200/60 shrink-0`}>
        <Network className="w-7 h-7 text-white" />
      </div>
      <div className="min-w-0">
        <div className="flex items-center gap-2">
          <h3 className="font-bold text-lg text-zinc-800">AiSOC 大脑</h3>
          <span className={`px-2 py-0.5 rounded-full text-xs font-medium ${style.dot} text-white`}>{style.label}</span>
        </div>
        <div className="text-sm text-zinc-600 mt-0.5">{DOMAIN_DESCRIPTIONS.brain}</div>
        <div className="text-xs text-zinc-500 mt-1 font-mono">
          FastAPI / 127.0.0.1:{DOMAIN_PORTS.brain} · {registryLoaded ? `已注册部件 ${registryCount} 个` : '注册表加载中...'}
        </div>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// 任务创建表单（frontend-api.md §5 推荐结构）
// ---------------------------------------------------------------------------

function TaskCreateForm({
  taskDesc, setTaskDesc, domain, setDomain, pipeline, setPipeline,
  target, setTarget, scopeTools, setScopeTools,
  submitting, onSubmit, brainOk,
}: {
  taskDesc: string;
  setTaskDesc: (v: string) => void;
  domain: CreateTaskInput['domain'];
  setDomain: (d: CreateTaskInput['domain']) => void;
  pipeline: string;
  setPipeline: (v: string) => void;
  target: string;
  setTarget: (v: string) => void;
  scopeTools: string;
  setScopeTools: (v: string) => void;
  submitting: boolean;
  onSubmit: () => Promise<void> | void;
  brainOk: boolean | null;
}) {
  const targetPlaceholder = domain === 'logaudit'
    ? '示例：10.0.0.0/24 或 /var/log/access.log 或 host:edu.cn'
    : '示例：https://target.edu.cn 或 192.168.1.0/24 或 app.example.com';

  return (
    <section className="rounded-xl border border-zinc-200 bg-white p-4">
      <div className="flex items-center justify-between mb-3">
        <h2 className="font-bold flex items-center gap-1.5">
          <Rocket className="w-4 h-4 text-fuchsia-600" />
          创建任务
        </h2>
        <span className={`text-xs px-2 py-0.5 rounded ${brainOk ? 'bg-emerald-50 text-emerald-700' : brainOk === false ? 'bg-red-50 text-red-700' : 'bg-zinc-100 text-zinc-600'}`}>
          大脑服务：{brainOk === null ? '检测中' : brainOk ? '可连通' : '未连通（可先配 target）'}
        </span>
      </div>

      <label className="block text-xs font-medium text-zinc-600 mb-1">1. 任务描述（自然语言，选填）</label>
      <textarea
        rows={2}
        className="w-full rounded border border-zinc-300 px-2 py-1.5 text-sm mb-3 focus:outline-none focus:ring-2 focus:ring-fuchsia-200 resize-none"
        value={taskDesc}
        onChange={(e) => setTaskDesc(e.target.value)}
        placeholder="例：对目标做基础侦察并输出发现 / 分析目标日志并输出发现"
      />

      <div className="grid grid-cols-2 gap-2 mb-3">
        <div>
          <label className="block text-xs font-medium text-zinc-600 mb-1">2. 域 domain</label>
          <select
            className="w-full rounded border border-zinc-300 bg-white px-2 py-1.5 text-sm focus:outline-none focus:ring-2 focus:ring-fuchsia-200"
            value={domain}
            onChange={(e) => setDomain(e.target.value as CreateTaskInput['domain'])}
          >
            <option value="logaudit">日志审计（logaudit）</option>
            <option value="pentest">渗透测试（pentest）</option>
          </select>
        </div>
        <div>
          <label className="block text-xs font-medium text-zinc-600 mb-1">3. 管道 pipeline</label>
          <select
            className="w-full rounded border border-zinc-300 bg-white px-2 py-1.5 text-sm focus:outline-none focus:ring-2 focus:ring-fuchsia-200"
            value={pipeline}
            onChange={(e) => setPipeline(e.target.value)}
          >
            <option value="">无（单域任务）</option>
            <option value="data_leak">data_leak（数据泄露调查：日志审计→渗透验证→判定→报告）</option>
          </select>
        </div>
      </div>

      <label className="block text-xs font-medium text-zinc-600 mb-1">4. 目标 target（IP/域名/URL — 必须在授权白名单内，否则 403）</label>
      <input
        className="w-full rounded border border-zinc-300 px-2 py-1.5 text-sm font-mono mb-3 focus:outline-none focus:ring-2 focus:ring-fuchsia-200"
        value={target}
        onChange={(e) => setTarget(e.target.value.trim())}
        placeholder={targetPlaceholder}
      />

      <div className="mb-3">
        <label className="block text-[11px] text-zinc-600 mb-0.5">工具白名单 tools（逗号分隔，留空=全部）</label>
        <input
          className="w-full rounded border border-zinc-300 px-2 py-1 text-xs font-mono focus:outline-none focus:ring-2 focus:ring-fuchsia-200"
          value={scopeTools}
          onChange={e => setScopeTools(e.target.value)}
          placeholder="port_scan,dns_enum"
        />
      </div>

      <button
        type="button"
        onClick={() => void onSubmit()}
        disabled={submitting || !target || !taskDesc}
        className="w-full rounded-lg bg-fuchsia-600 text-white px-3 py-2 text-sm font-medium hover:bg-fuchsia-700 active:bg-fuchsia-800 disabled:bg-zinc-300 disabled:cursor-not-allowed transition-colors flex items-center justify-center gap-2"
      >
        {submitting ? <Loader2 className="w-4 h-4 animate-spin" /> : <Play className="w-4 h-4" />}
        {submitting ? '正在通过大脑创建任务…' : '通过大脑下发任务'}
      </button>
    </section>
  );
}

// ---------------------------------------------------------------------------
// 任务列表 Tab
// ---------------------------------------------------------------------------

function TaskList({
  tasks, loading, selectedId, onSelect, onRefresh,
}: {
  tasks: TaskInfo[];
  loading: boolean;
  selectedId: string | null;
  onSelect: (t: TaskInfo) => void;
  onRefresh: () => void;
}) {
  return (
    <div className="flex flex-col h-full min-h-0">
      <div className="flex items-center justify-between px-4 py-2 border-b bg-white">
        <div className="flex items-center gap-2">
          <Database className="w-4 h-4 text-zinc-500" />
          <span className="text-sm font-semibold">任务列表（{tasks.length}）</span>
        </div>
        <button
          type="button"
          onClick={onRefresh}
          disabled={loading}
          className="text-xs px-2 py-1 rounded border border-zinc-200 hover:bg-zinc-50 disabled:opacity-50 inline-flex items-center gap-1"
        >
          <RefreshCw className={`w-3 h-3 ${loading ? 'animate-spin' : ''}`} /> 刷新
        </button>
      </div>
      <div className="flex-1 overflow-auto">
        {loading && tasks.length === 0 ? (
          <div className="flex items-center justify-center h-32 text-zinc-500 text-sm">加载任务中…</div>
        ) : tasks.length === 0 ? (
          <div className="flex flex-col items-center justify-center h-32 gap-2 text-zinc-500 text-sm">
            <FileSearch className="w-8 h-8 text-zinc-300" />
            还没有任何任务 — 从左侧创建一个
          </div>
        ) : (
          <table className="w-full text-xs">
            <thead className="bg-zinc-50 sticky top-0 z-10">
              <tr className="text-left text-zinc-600">
                <th className="px-3 py-2 font-medium">任务 ID</th>
                <th className="px-3 py-2 font-medium">域</th>
                <th className="px-3 py-2 font-medium">目标</th>
                <th className="px-3 py-2 font-medium">状态</th>
                <th className="px-3 py-2 font-medium">判定</th>
                <th className="px-3 py-2 font-medium">更新</th>
              </tr>
            </thead>
            <tbody>
              {tasks.map(t => {
                const stat = TASK_STATUS_META[t.status] ?? TASK_STATUS_META.pending;
                const v = t.verdict ? VERDICT_META[t.verdict] : null;
                const domainColor = DOMAIN_COLORS[t.domain] ?? DOMAIN_COLORS.brain;
                const active = selectedId === t.id;
                return (
                  <tr
                    key={t.id}
                    onClick={() => onSelect(t)}
                    className={`cursor-pointer border-b border-zinc-100 hover:bg-fuchsia-50/50 ${active ? 'bg-fuchsia-50' : ''}`}
                  >
                    <td className="px-3 py-2 font-mono text-[11px] text-zinc-700">{t.id}</td>
                    <td className="px-3 py-2">
                      <span className={`inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-[11px] ${domainColor.bg} ${domainColor.ring} ring-1`}>
                        <span className={`w-1.5 h-1.5 rounded-full ${domainColor.dot}`} />
                        {DOMAIN_LABELS[t.domain] ?? t.domain}
                      </span>
                    </td>
                    <td className="px-3 py-2 font-mono text-[11px] max-w-[200px] truncate" title={t.target}>{t.target}</td>
                    <td className="px-3 py-2">
                      <span className={`px-1.5 py-0.5 rounded text-[11px] ${stat.cls}`}>{stat.label}</span>
                    </td>
                    <td className="px-3 py-2">
                      {v ? (
                        <span className={`px-1.5 py-0.5 rounded border text-[11px] ${v.cls}`}>{v.icon} {v.label}</span>
                      ) : (
                        <span className="text-zinc-400 text-[11px]">待判定</span>
                      )}
                    </td>
                    <td className="px-3 py-2 text-zinc-500 text-[11px] whitespace-nowrap" title={fmtTime(t.updated_at)}>{fmtAgo(t.updated_at)}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// 快速聊天（指定 Agent）面板
// ---------------------------------------------------------------------------

/**
 * Agent 快速聊天面板 —— 让用户选完 Agent 就能直接输入任务描述发送，
 * 不必每次都填 TaskCreateForm 里的所有字段。点击 agent 按钮 → 自动预填
 * domain + 典型 target placeholder + 触发词前缀。提交流程跟 TaskCreateForm
 * 完全一致（复用 submitTaskViaStream 逻辑）。
 */
type QuickChatAgent = 'auto' | 'pentest' | 'logaudit' | 'intel';

interface QuickChatOption {
  id: QuickChatAgent;
  label: string;
  shortLabel: string;
  /** 加在用户输入前的触发词（大脑侧意图识别的强 token；详见 aisoc-docs/12 + 13） */
  prefix: (text: string) => string;
  icon: React.ReactNode;
  /** 预填的 domain（'auto' 表示不改 domain） */
  setDomain?: CreateTaskInput['domain'];
  /** 预填的 target placeholder */
  targetPlaceholder: string;
  colorClass: string; // 选中色
  description: string;
}

const QUICK_CHAT_OPTIONS: QuickChatOption[] = [
  {
    id: 'auto',
    label: '🤖 自动',
    shortLabel: '自动',
    prefix: (t) => t,
    icon: <Sparkles className="w-3.5 h-3.5" />,
    targetPlaceholder: '随附路径或 IP（可选）',
    colorClass: 'border-fuchsia-300 bg-fuchsia-50 text-fuchsia-700',
    description: '由大脑自动识别意图并路由',
  },
  {
    id: 'pentest',
    label: '🛡️ 渗透测试',
    shortLabel: '渗透测试',
    prefix: (t) => (t.trim() ? `渗透测试 ${t}` : '渗透测试'),
    icon: <TerminalSquare className="w-3.5 h-3.5" />,
    setDomain: 'pentest',
    targetPlaceholder: '例：https://target.edu.cn 或 192.168.1.0/24',
    colorClass: 'border-rose-300 bg-rose-50 text-rose-700',
    description: '路由到 pentest 部件（8786）',
  },
  {
    id: 'logaudit',
    label: '📋 日志审计',
    shortLabel: '日志审计',
    prefix: (t) => (t.trim() ? `日志审计 ${t}` : '日志审计'),
    icon: <FileSearch className="w-3.5 h-3.5" />,
    setDomain: 'logaudit',
    targetPlaceholder: '例：./logaudit-work/AntSword2.pcap 或 /var/log/access.log',
    colorClass: 'border-amber-300 bg-amber-50 text-amber-700',
    description: '路由到 logaudit 部件（8788）',
  },
  {
    id: 'intel',
    label: '🕵️ 情报收集',
    shortLabel: '情报收集',
    prefix: (t) => (t.trim() ? `情报收集 ${t}` : '情报收集'),
    icon: <Radar className="w-3.5 h-3.5" />,
    setDomain: 'intel',
    targetPlaceholder: '例：cve-2025-xxxx 或威胁组织 APT-XX',
    colorClass: 'border-sky-300 bg-sky-50 text-sky-700',
    description: '路由到 intel 部件（8789）',
  },
];

function QuickChatInput({
  chatAgent,
  setChatAgent,
  chatText,
  setChatText,
  submitting,
  onSend,
  disabled,
}: {
  chatAgent: QuickChatAgent;
  setChatAgent: (a: QuickChatAgent) => void;
  chatText: string;
  setChatText: (s: string) => void;
  submitting: boolean;
  onSend: () => void | Promise<void>;
  disabled?: boolean;
}) {
  const currentOption = QUICK_CHAT_OPTIONS.find(o => o.id === chatAgent) ?? QUICK_CHAT_OPTIONS[0];

  const handleKeyDown = (e: React.KeyboardEvent<HTMLTextAreaElement>) => {
    // Enter 发送，Shift+Enter 换行
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      if (chatText.trim() && !submitting && !disabled) {
        void onSend();
      }
    }
  };

  return (
    <section className="rounded-xl border border-fuchsia-200 bg-gradient-to-br from-fuchsia-50/40 to-white p-3 shadow-sm">
      <div className="flex items-center justify-between mb-2">
        <h2 className="font-bold flex items-center gap-1.5 text-sm">
          <MessageSquare className="w-4 h-4 text-fuchsia-600" />
          快速聊天
          <span className="text-[11px] font-normal text-zinc-500">· 指定 Agent 后直接发送</span>
        </h2>
        <span className="text-[11px] text-zinc-500">
          Enter 发送 · Shift+Enter 换行
        </span>
      </div>

      {/* Agent 选择按钮组（横排 4 选 1） */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-1.5 mb-2">
        {QUICK_CHAT_OPTIONS.map((opt) => {
          const isActive = opt.id === chatAgent;
          return (
            <button
              key={opt.id}
              type="button"
              onClick={() => setChatAgent(opt.id)}
              title={opt.description}
              className={`flex items-center justify-center gap-1 rounded-lg border px-2 py-1.5 text-xs font-medium transition-all ${
                isActive
                  ? `${opt.colorClass} shadow-sm ring-1 ring-current`
                  : 'border-zinc-200 bg-white text-zinc-600 hover:border-zinc-300 hover:bg-zinc-50'
              }`}
              data-testid={`quick-chat-agent-${opt.id}`}
            >
              {opt.icon}
              <span>{opt.shortLabel}</span>
            </button>
          );
        })}
      </div>

      {/* 选中 Agent 的描述 */}
      <div className="text-[11px] text-zinc-500 mb-2 px-0.5">
        {currentOption.description}
      </div>

      {/* 输入框 + 发送按钮 */}
      <div className="flex gap-1.5 items-end">
        <textarea
          rows={2}
          className="flex-1 rounded-lg border border-zinc-300 bg-white px-2.5 py-1.5 text-sm resize-none focus:outline-none focus:ring-2 focus:ring-fuchsia-200 placeholder:text-zinc-400 disabled:bg-zinc-50 disabled:text-zinc-400"
          value={chatText}
          onChange={(e) => setChatText(e.target.value)}
          onKeyDown={handleKeyDown}
          placeholder={currentOption.targetPlaceholder}
          disabled={disabled || submitting}
          data-testid="quick-chat-input"
        />
        <button
          type="button"
          onClick={() => void onSend()}
          disabled={!chatText.trim() || submitting || disabled}
          className="rounded-lg bg-fuchsia-600 hover:bg-fuchsia-700 disabled:bg-zinc-300 disabled:cursor-not-allowed text-white px-3 py-2 text-sm font-medium flex items-center gap-1.5 transition-colors shrink-0"
          data-testid="quick-chat-send"
        >
          {submitting ? (
            <Loader2 className="w-4 h-4 animate-spin" />
          ) : (
            <Send className="w-4 h-4" />
          )}
          <span>发送</span>
        </button>
      </div>
    </section>
  );
}

// ---------------------------------------------------------------------------
// Finding 证据表 Tab 内部分
// ---------------------------------------------------------------------------

function FindingsView({ findings, loading, task }: {
  findings: Finding[];
  loading: boolean;
  task: TaskInfo | null;
}) {
  return (
    <div className="flex flex-col h-full min-h-0">
      <div className="px-4 py-2 border-b bg-white flex items-center justify-between">
        <div className="flex items-center gap-2">
          <ShieldAlert className="w-4 h-4 text-zinc-500" />
          <span className="text-sm font-semibold">
            证据 Findings {task && <span className="text-xs text-zinc-500 font-normal"> · {task.id}</span>}
          </span>
          {findings.length > 0 && <span className="text-xs text-zinc-500">（{findings.length} 条）</span>}
        </div>
        {findings.length > 0 && (
          <div className="flex gap-1 text-[11px]">
            {(['critical','high','medium','low','info'] as const).map(s => {
              const count = findings.filter(f => f.severity === s).length;
              if (count === 0) return null;
              const meta = SEVERITY_META[s];
              return (
                <span key={s} className={`px-1.5 py-0.5 rounded border ${meta.cls}`}>{meta.label} {count}</span>
              );
            })}
          </div>
        )}
      </div>
      <div className="flex-1 overflow-auto">
        {loading ? (
          <div className="flex items-center justify-center h-28 text-sm text-zinc-500">加载证据中…</div>
        ) : findings.length === 0 ? (
          <div className="flex flex-col items-center justify-center h-28 text-sm text-zinc-500 gap-1">
            <ShieldCheck className="w-7 h-7 text-zinc-300" />
            暂无证据 — 选中一个已运行任务即可查看 Finding
          </div>
        ) : (
          <table className="w-full text-xs">
            <thead className="bg-zinc-50 sticky top-0 z-10">
              <tr className="text-left text-zinc-600">
                <th className="px-3 py-2 font-medium">ID</th>
                <th className="px-3 py-2 font-medium">级别</th>
                <th className="px-3 py-2 font-medium">部件</th>
                <th className="px-3 py-2 font-medium">工具</th>
                <th className="px-3 py-2 font-medium">标题</th>
                <th className="px-3 py-2 font-medium">CVE / CVSS</th>
                <th className="px-3 py-2 font-medium">置信度</th>
                <th className="px-3 py-2 font-medium">时间</th>
              </tr>
            </thead>
            <tbody>
              {findings.map(f => {
                const sev = SEVERITY_META[f.severity] ?? SEVERITY_META.info;
                const dc = DOMAIN_COLORS[f.domain] ?? DOMAIN_COLORS.brain;
                const fts = f.ts ?? f.timestamp ?? '';
                return (
                  <tr key={f.id} className="border-b border-zinc-100 hover:bg-zinc-50">
                    <td className="px-3 py-2 font-mono text-[11px] text-zinc-600">{f.id}</td>
                    <td className="px-3 py-2"><span className={`px-1.5 py-0.5 rounded border text-[11px] ${sev.cls}`}>{sev.label}</span></td>
                    <td className="px-3 py-2">
                      <span className={`inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-[11px] ${dc.bg} ${dc.ring} ring-1`}>
                        <span className={`w-1.5 h-1.5 rounded-full ${dc.dot}`} />
                        {DOMAIN_LABELS[f.domain] ?? f.domain}
                      </span>
                    </td>
                    <td className="px-3 py-2 font-mono text-[11px]">{f.tool}</td>
                    <td className="px-3 py-2 max-w-[260px]">
                      <div className="font-medium text-zinc-800">{f.title}</div>
                      {f.description && <div className="text-[11px] text-zinc-500 leading-snug line-clamp-2">{f.description}</div>}
                    </td>
                    <td className="px-3 py-2 font-mono text-[11px]">
                      <div>{f.cve ?? '—'}</div>
                      {f.cvss !== undefined && f.cvss !== null && (
                        <div className="text-zinc-500">CVSS {f.cvss.toFixed ? f.cvss.toFixed(1) : f.cvss}</div>
                      )}
                      {f.cwe && <div className="text-zinc-500">{f.cwe}</div>}
                    </td>
                    <td className="px-3 py-2 text-[11px]">
                      {typeof f.confidence === 'number' ? (
                        <div className="flex items-center gap-1">
                          <div className="w-12 h-1.5 bg-zinc-100 rounded">
                            <div className="h-full rounded bg-fuchsia-500" style={{ width: `${Math.round(f.confidence * 100)}%` }} />
                          </div>
                          <span className="font-mono text-zinc-600">{Math.round(f.confidence * 100)}%</span>
                        </div>
                      ) : '—'}
                    </td>
                    <td className="px-3 py-2 text-[11px] text-zinc-500 whitespace-nowrap" title={fmtTime(fts)}>
                      {fmtAgo(fts)}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// 判定 + 报告卡（frontend-api.md §4.2 / §4.4 / §4.5）
// ---------------------------------------------------------------------------

function VerdictReportCard({ detail, report, loading, task, onExport }: {
  detail: TaskDetail | null;
  report: ReportDoc | null;
  loading: boolean;
  task: TaskInfo | null;
  onExport: () => void;
}) {
  const verdict = detail?.verdict ?? null;
  const v = verdict ? VERDICT_META[verdict] : null;
  const confidence = detail?.confidence ?? task?.confidence;
  const stages = detail?.stages ?? [];
  const thoughtChain = detail?.thought_chain ?? [];

  return (
    <div className="flex flex-col h-full min-h-0">
      <div className="px-4 py-2 border-b bg-white flex items-center gap-2">
        <Layers className="w-4 h-4 text-zinc-500" />
        <span className="text-sm font-semibold">大脑判定 & 报告</span>
        {task && <span className="text-xs text-zinc-500"> · {task.id}</span>}
        <div className="flex-1" />
        {task && (
          <button
            type="button"
            onClick={onExport}
            className="text-[11px] px-2 py-1 rounded border border-zinc-200 hover:bg-zinc-50 inline-flex items-center gap-1"
            title="导出审计 JSON（任务 + findings + ledger + report）"
          >
            <Download className="w-3 h-3" /> 导出审计 JSON
          </button>
        )}
      </div>
      <div className="flex-1 overflow-auto p-4 space-y-4">
        {loading ? (
          <div className="flex items-center justify-center h-24 text-sm text-zinc-500">加载判定 / 报告中…</div>
        ) : !task ? (
          <div className="flex flex-col items-center justify-center h-24 text-sm text-zinc-500 gap-1">
            <FileText className="w-7 h-7 text-zinc-300" />
            先在"任务列表"里选中一个任务
          </div>
        ) : (
          <>
            {/* Verdict 卡（文档 §4.2） */}
            {v ? (
              <div className={`rounded-xl border p-4 ${v.cls}`}>
                <div className="flex items-start justify-between mb-2">
                  <div>
                    <div className="text-xs uppercase tracking-wider opacity-70">威胁判定</div>
                    <div className="text-2xl font-bold mt-0.5">{v.icon} {v.label}</div>
                  </div>
                  <div className="text-right">
                    <div className="text-xs opacity-70">综合置信度</div>
                    <div className="text-xl font-bold">{typeof confidence === 'number' ? `${Math.round(confidence * 100)}%` : '—'}</div>
                  </div>
                </div>
                <div className="text-xs opacity-80 mt-1">
                  当前阶段：{detail?.current_stage ?? '—'}
                  {detail?.error && <span className="ml-2 text-red-700">错误：{detail.error}</span>}
                </div>
              </div>
            ) : (
              <div className="rounded-xl border border-dashed border-zinc-300 bg-zinc-50 p-4 text-xs text-zinc-500 flex items-center gap-2">
                <Gavel className="w-4 h-4 text-zinc-300" />
                任务尚未完成判定 — 完成或运行中会在此展示 verdict / confidence。
              </div>
            )}

            {/* 阶段进度（文档 §4.2 stages） */}
            {stages.length > 0 && (
              <div className="rounded-xl border border-zinc-200 bg-white p-4">
                <div className="text-xs font-semibold text-zinc-700 mb-2">阶段进度</div>
                <div className="space-y-1.5">
                  {stages.map(st => {
                    const m = TASK_STATUS_META[st.status] ?? TASK_STATUS_META.pending;
                    return (
                      <div key={st.id} className="flex items-center gap-2 text-xs">
                        <span className={`px-1.5 py-0.5 rounded ${m.cls}`}>{m.label}</span>
                        <span className="font-medium text-zinc-700 w-20">{STAGE_LABELS[st.stage] ?? st.stage}</span>
                        <span className="text-zinc-500 font-mono">finding×{st.findings_count}</span>
                        {st.started_at && <span className="text-zinc-400 whitespace-nowrap" title={fmtTime(st.started_at)}>{fmtAgo(st.started_at)}</span>}
                        {st.error && <span className="text-red-600 truncate" title={st.error}>{st.error}</span>}
                      </div>
                    );
                  })}
                </div>
              </div>
            )}

            {/* 思维链 / 审计轨迹（文档 §4.2 thought_chain） */}
            {thoughtChain.length > 0 && (
              <div className="rounded-xl border border-zinc-200 bg-white p-4">
                <div className="text-xs font-semibold text-zinc-700 mb-2">思维链 / 审计轨迹</div>
                <div className="space-y-1 max-h-40 overflow-auto">
                  {thoughtChain.map(entry => (
                    <div key={entry.id} className="flex gap-2 text-[11px]">
                      <span className="font-mono text-zinc-400 shrink-0">{fmtTime(entry.ts)}</span>
                      <span className="font-medium text-fuchsia-700 shrink-0">{entry.actor}</span>
                      <span className="text-zinc-600 break-all">{entry.action}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* 报告卡（文档 §4.4：Markdown 字符串） */}
            {report ? (
              <div className="rounded-xl border border-zinc-200 bg-white p-4">
                <div className="flex items-center justify-between mb-2">
                  <div className="flex items-center gap-1.5">
                    <FileText className="w-4 h-4 text-fuchsia-600" />
                    <span className="font-semibold">综合报告（Markdown）</span>
                  </div>
                </div>
                <div className="text-sm leading-relaxed">
                  <ReactMarkdown remarkPlugins={[remarkGfm]}>{report.report}</ReactMarkdown>
                </div>
              </div>
            ) : (
              <div className="rounded-xl border border-dashed border-zinc-300 bg-zinc-50 p-4 text-xs text-zinc-500 flex items-center gap-2">
                <FileText className="w-4 h-4 text-zinc-300" />
                任务未完成或大脑尚未产出报告 — 完成后会自动填充。
              </div>
            )}
          </>
        )}
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// 应急响应（TIR）面板 —— 告警 / 处置预案 / 应急响应报告（tir-frontend.md §4）
// 说明：仅当任务判定为 real_threat 时大脑才会推 8090 并落库，
// 因此三个列表全空是正常态，此处显式提示而非留白。
// ---------------------------------------------------------------------------

/** 告警状态 → 中文（文档 §4.1） */
const TIR_ALERT_STATUS_LABELS: Record<string, string> = {
  new: '新告警',
  notified: '已通知',
  acknowledged: '已确认',
  responded: '已响应',
  closed: '已关闭',
};

/** 处置步骤状态 → 中文（文档 §4.2 steps[].status） */
const TIR_STEP_STATUS_LABELS: Record<string, string> = {
  pending: '待执行',
  approved: '已批准',
  rejected: '已拒绝',
  simulated: '已模拟',
  completed: '已完成',
};

/** 预案模式 → 中文（文档 §4.2 mode） */
const TIR_MODE_LABELS: Record<string, string> = {
  suggestion: '建议模式（待人工确认）',
  simulation: '模拟推演',
};

/**
 * 处置回注（模拟）—— T2-2 前端侧。
 * 在人工"批准"预案后展示：① 由预案 steps 汇总的封禁指令 JSON；② 一键"模拟下发"到 8788
 * 模拟适配路由并展示回执。全程显式标注"模拟"，不触真实设备（计划书 §6-#4 例外 / §7-Q4）。
 */
function TirMockReinjection({ task, playbook }: { task: TaskInfo; playbook: TirPlaybook }) {
  const cmd: MockWafCommand = useMemo(
    () => buildMockWafCommand(task.id, playbook.playbook_id, playbook.payload?.steps ?? []),
    [task.id, playbook.playbook_id, playbook.payload?.steps],
  );
  const [status, setStatus] = useState<'idle' | 'sending' | 'done' | 'failed'>('idle');
  const [receipt, setReceipt] = useState<MockWafBlockResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [open, setOpen] = useState(false);
  // 8788 模拟路由要求顶层 target；预案里没有任何可下发目标时直接禁用，避免 400。
  const canSend = cmd.target.trim() !== '';

  const send = useCallback(async () => {
    setStatus('sending');
    setError(null);
    try {
      const r = await aisocApi.mockWafBlock(cmd);
      setReceipt(r);
      setStatus('done');
    } catch (e) {
      // 404 = 8788 模拟路由尚未部署（linchen 侧 T2-2）；401/超时/网络不可达同样轻提示，不阻断页面。
      setError(e instanceof Error ? e.message : '模拟下发失败');
      setStatus('failed');
    }
  }, [cmd]);

  return (
    <div className="mt-3 rounded-lg border border-amber-200 bg-amber-50/70 p-3 space-y-2">
      <div className="flex items-center gap-2 flex-wrap text-[11px]">
        <span className="px-1.5 py-0.5 rounded bg-amber-200 text-amber-900 font-semibold">模拟</span>
        <span className="font-semibold text-amber-900">处置回注（模拟适配层）</span>
        <span className="text-amber-700">不触真实设备 · 演示"生成指令 → 下发 → 回执"</span>
        <div className="flex-1" />
        <button
          type="button"
          onClick={() => setOpen(v => !v)}
          className="text-amber-800 underline decoration-dotted underline-offset-2 hover:text-amber-950"
        >
          {open ? '收起指令' : `查看指令（${cmd.actions.length} 条）`}
        </button>
      </div>

      {open && (
        <pre className="p-2 rounded bg-white/80 border border-amber-200 text-[10px] leading-relaxed font-mono text-zinc-700 overflow-x-auto">
          {JSON.stringify(cmd, null, 2)}
        </pre>
      )}

      <div className="flex items-center gap-2 flex-wrap">
        <button
          type="button"
          disabled={status === 'sending' || !canSend}
          onClick={send}
          className="text-[11px] px-2.5 py-1 rounded border border-amber-300 bg-white text-amber-900 hover:bg-amber-100 disabled:opacity-50 inline-flex items-center gap-1"
        >
          {status === 'sending'
            ? <Loader2 className="w-3 h-3 animate-spin" />
            : <Send className="w-3 h-3" />}
          {status === 'done' ? '重新模拟下发' : '模拟下发'}
        </button>

        {status === 'done' && receipt && (
          <span className="text-[11px] text-emerald-800 inline-flex items-center gap-1">
            <CheckCircle2 className="w-3 h-3" />
            回执 {receipt.receipt_id} · {fmtAgo(receipt.ts)} · simulated={String(receipt.simulated)}
          </span>
        )}
        {!canSend && (
          <span className="text-[11px] text-amber-800">预案中没有可下发目标，无法模拟下发</span>
        )}
        {status === 'failed' && (
          <span className="text-[11px] text-amber-800">
            模拟下发失败（模拟路由或大脑代理未就绪）：{error}
          </span>
        )}
      </div>
    </div>
  );
}

interface TirPanelProps {
  task: TaskInfo;
  alerts: TirAlert[];
  playbooks: TirPlaybook[];
  reports: TirReport[];
  busy: boolean;
  error: string | null;
  /** 三端点缺失/不可达的归因；null 表示端点正常，空列表可解释为“无应急响应数据”。 */
  unavailable: TirAvailability;
  onApprove: (playbookId: string, decision: 'approved' | 'denied') => void;
}

function TirPanel({ task, alerts, playbooks, reports, busy, error, unavailable, onApprove }: TirPanelProps) {
  const isRealThreat = task.verdict === 'real_threat';
  const empty = alerts.length === 0 && playbooks.length === 0 && reports.length === 0;
  // 本次会话内点过"批准"的预案（乐观记录；后端报告落库后以 reports 为准）
  const [approvedIds, setApprovedIds] = useState<Set<string>>(() => new Set());

  return (
    <div className="flex flex-col h-full min-h-0">
      <div className="px-4 py-2 border-b bg-white flex items-center gap-2">
        <ShieldAlert className="w-4 h-4 text-zinc-500" />
        <span className="text-sm font-semibold">应急响应（TIR）</span>
        <span className="text-xs text-zinc-500"> · {task.id}</span>
        <div className="flex-1" />
        <span className="text-[11px] text-zinc-400">
          告警 {alerts.length} · 预案 {playbooks.length} · 报告 {reports.length}
        </span>
      </div>
      <div className="flex-1 overflow-auto p-4 space-y-4">
        {error && (
          <div className="rounded-lg border border-amber-200 bg-amber-50 px-3 py-2 text-xs text-amber-800 flex items-center gap-2">
            <X className="w-3.5 h-3.5 shrink-0" />
            <span>审批失败：{error}（未影响主流程，可重试）</span>
          </div>
        )}
        {unavailable && (
          <div className="rounded-lg border border-amber-200 bg-amber-50 px-3 py-2 text-xs text-amber-800 flex items-start gap-2">
            <AlertTriangle className="w-3.5 h-3.5 shrink-0" />
            <span>
              {unavailable === 'route-missing'
                ? '应急响应查询路由未部署（/api/tir/* 返回 404）：当前无法展示告警 / 预案 / 报告，这不代表任务没有真实威胁。'
                : '应急响应服务不可达（TIR 8090）：请确认应急响应子 Agent 已启动后刷新。'}
            </span>
          </div>
        )}
        {empty ? (
          unavailable ? null : (
            <div className="rounded-xl border border-dashed border-zinc-300 bg-zinc-50 p-4 text-xs text-zinc-500 flex items-center gap-2">
              <ShieldCheck className="w-4 h-4 text-zinc-300" />
              {isRealThreat
                ? '该任务已判定为真实威胁，但应急响应数据尚未落库 — 稍后刷新会自动填充。'
                : '该任务未判定为真实威胁，无应急响应数据（空列表为正常状态）。'}
            </div>
          )
        ) : (
          <>
            {/* 威胁告警（文档 §4.1） */}
            {alerts.length > 0 && (
              <div className="space-y-3">
                <div className="text-xs font-semibold text-zinc-700">威胁告警（{alerts.length}）</div>
                {alerts.map(a => {
                  const m = SEVERITY_META[a.level] ?? SEVERITY_META.info;
                  return (
                    <div key={a.alert_id} className="rounded-xl border border-zinc-200 bg-white p-4 space-y-2">
                      <div className="flex items-center gap-2 flex-wrap text-xs">
                        <span className={`px-1.5 py-0.5 rounded border ${m.cls}`}>{m.label}</span>
                        <span className="font-mono text-zinc-500">{a.alert_id}</span>
                        <span className="px-1.5 py-0.5 rounded bg-zinc-100 text-zinc-600">
                          {TIR_ALERT_STATUS_LABELS[a.status] ?? a.status}
                        </span>
                        <div className="flex-1" />
                        {a.created_at && (
                          <span className="text-zinc-400" title={fmtTime(a.created_at)}>{fmtAgo(a.created_at)}</span>
                        )}
                      </div>
                      <div className="text-sm leading-relaxed">
                        <ReactMarkdown remarkPlugins={[remarkGfm]}>{a.display_md}</ReactMarkdown>
                      </div>
                    </div>
                  );
                })}
              </div>
            )}

            {/* 处置预案（文档 §4.2） */}
            {playbooks.length > 0 && (
              <div className="space-y-3">
                <div className="text-xs font-semibold text-zinc-700">处置预案（{playbooks.length}）</div>
                {playbooks.map(pb => {
                  const steps = pb.payload?.steps ?? [];
                  const conf = pb.payload?.confidence;
                  return (
                    <div key={pb.playbook_id} className="rounded-xl border border-zinc-200 bg-white p-4 space-y-3">
                      <div className="flex items-center gap-2 flex-wrap text-xs">
                        <span className="px-1.5 py-0.5 rounded bg-fuchsia-50 text-fuchsia-700 border border-fuchsia-200">
                          {TIR_MODE_LABELS[pb.mode] ?? pb.mode}
                        </span>
                        <span className="font-mono text-zinc-500">{pb.playbook_id}</span>
                        {typeof conf === 'number' && (
                          <span className="text-zinc-500">置信度 {Math.round(conf * 100)}%</span>
                        )}
                        <div className="flex-1" />
                        {pb.created_at && (
                          <span className="text-zinc-400" title={fmtTime(pb.created_at)}>{fmtAgo(pb.created_at)}</span>
                        )}
                      </div>

                      <div className="text-sm leading-relaxed">
                        <ReactMarkdown remarkPlugins={[remarkGfm]}>{pb.display_md}</ReactMarkdown>
                      </div>

                      {steps.length > 0 && (
                        <div className="overflow-x-auto">
                          <table className="w-full text-[11px] border-collapse">
                            <thead>
                              <tr className="text-zinc-500 text-left">
                                <th className="py-1 pr-2 font-medium">#</th>
                                <th className="py-1 pr-2 font-medium">阶段</th>
                                <th className="py-1 pr-2 font-medium">动作</th>
                                <th className="py-1 pr-2 font-medium">风险</th>
                                <th className="py-1 pr-2 font-medium">需确认</th>
                                <th className="py-1 pr-2 font-medium">状态</th>
                              </tr>
                            </thead>
                            <tbody>
                              {steps.map(s => {
                                const rm = s.risk_level ? (SEVERITY_META[s.risk_level] ?? null) : null;
                                return (
                                  <tr key={s.seq} className="border-t border-zinc-100 align-top">
                                    <td className="py-1 pr-2 font-mono text-zinc-400">{s.seq}</td>
                                    <td className="py-1 pr-2 text-zinc-600">{s.phase}</td>
                                    <td className="py-1 pr-2 text-zinc-700">
                                      <div>{s.action}</div>
                                      {s.expected_command && (
                                        <div className="mt-1">
                                          <div className="text-[10px] text-zinc-400">参考命令（仅展示，禁止执行）</div>
                                          <pre className="mt-0.5 p-1.5 rounded bg-zinc-50 border border-zinc-200 text-[10px] font-mono text-zinc-600 overflow-x-auto">{s.expected_command}</pre>
                                        </div>
                                      )}
                                    </td>
                                    <td className="py-1 pr-2">
                                      {rm
                                        ? <span className={`px-1.5 py-0.5 rounded border ${rm.cls}`}>{rm.label}</span>
                                        : '—'}
                                    </td>
                                    <td className="py-1 pr-2">
                                      {s.requires_approval
                                        ? <span className="px-1.5 py-0.5 rounded bg-amber-100 text-amber-800">需确认</span>
                                        : <span className="text-zinc-400">自动</span>}
                                    </td>
                                    <td className="py-1 pr-2 text-zinc-600">
                                      {TIR_STEP_STATUS_LABELS[s.status ?? 'pending'] ?? s.status}
                                    </td>
                                  </tr>
                                );
                              })}
                            </tbody>
                          </table>
                        </div>
                      )}

                      <div className="flex items-center gap-2 pt-1">
                        <button
                          type="button"
                          disabled={busy}
                          onClick={() => {
                            onApprove(pb.playbook_id, 'approved');
                            setApprovedIds(prev => {
                              const next = new Set(prev);
                              next.add(pb.playbook_id);
                              return next;
                            });
                          }}
                          className="text-[11px] px-2.5 py-1 rounded border border-green-200 bg-green-50 text-green-800 hover:bg-green-100 disabled:opacity-50 inline-flex items-center gap-1"
                        >
                          <ShieldCheck className="w-3 h-3" /> 批准
                        </button>
                        <button
                          type="button"
                          disabled={busy}
                          onClick={() => onApprove(pb.playbook_id, 'denied')}
                          className="text-[11px] px-2.5 py-1 rounded border border-zinc-200 bg-white text-zinc-700 hover:bg-zinc-50 disabled:opacity-50 inline-flex items-center gap-1"
                        >
                          <X className="w-3 h-3" /> 拒绝
                        </button>
                        {busy && <Loader2 className="w-3 h-3 animate-spin text-zinc-400" />}
                      </div>

                      {approvedIds.has(pb.playbook_id)
                        || reports.some(r => r.playbook_id === pb.playbook_id && r.decision === 'approve')
                        ? <TirMockReinjection task={task} playbook={pb} />
                        : (
                          <div className="text-[11px] text-zinc-400 pt-1">
                            批准预案后可生成处置指令（模拟回注，不触真实设备）
                          </div>
                        )}
                    </div>
                  );
                })}
              </div>
            )}

            {/* 应急响应报告（文档 §4.3） */}
            {reports.length > 0 && (
              <div className="space-y-3">
                <div className="text-xs font-semibold text-zinc-700">应急响应报告（{reports.length}）</div>
                {reports.map(r => (
                  <div key={r.report_id} className="rounded-xl border border-zinc-200 bg-white p-4">
                    <div className="flex items-center gap-1.5 mb-2 flex-wrap text-xs">
                      <FileText className="w-4 h-4 text-fuchsia-600" />
                      <span className="font-mono text-zinc-500">{r.report_id}</span>
                      {r.decision && (
                        <span className="px-1.5 py-0.5 rounded bg-zinc-100 text-zinc-600">
                          {r.decision === 'approve' ? '已批准' : '已拒绝'}
                        </span>
                      )}
                      <div className="flex-1" />
                      {r.created_at && (
                        <span className="text-zinc-400" title={fmtTime(r.created_at)}>{fmtAgo(r.created_at)}</span>
                      )}
                    </div>
                    <div className="text-sm leading-relaxed">
                      <ReactMarkdown remarkPlugins={[remarkGfm]}>{r.report_md}</ReactMarkdown>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </>
        )}
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// 主组件
// ---------------------------------------------------------------------------

export function AisocDashboard({ onExit, initialAgent }: {
  onExit?: () => void;
  /**
   * 初始 Agent 预选（可选）。App.tsx 底部浮动 Popover 选中后传过来，
   * 进入 dashboard 时自动选中 + focus 输入框。
   */
  initialAgent?: QuickChatAgent;
}) {
  // 挂载守卫：防止异步请求在组件卸载 / StrictMode 双重挂载窗口内 resolve 后
  // 触发 setState，导致 React commit 阶段 removeChild 冲突（React 19 经典报错）。
  const mountedRef = useRef(true);
  useEffect(() => {
    mountedRef.current = true;
    return () => { mountedRef.current = false; };
  }, []);

  // Esc 键退出（仅在 focus 在 body 而非输入框时触发，避免误触）
  useEffect(() => {
    if (!onExit) return;
    const handler = (e: KeyboardEvent) => {
      if (e.key !== 'Escape') return;
      const t = e.target as HTMLElement | null;
      const tag = t?.tagName;
      // 输入框 / textarea / contentEditable 中不拦截 Esc，保留原生行为
      if (tag === 'INPUT' || tag === 'TEXTAREA' || t?.isContentEditable) return;
      e.preventDefault();
      onExit();
    };
    window.addEventListener('keydown', handler);
    return () => window.removeEventListener('keydown', handler);
  }, [onExit]);

  // ---- 基础设施状态 ----
  const [brainState, setBrainState] = useState<boolean | null>(null);
  const [registry, setRegistry] = useState<RegistryPart[] | null>(null);
  const [registryLoading, setRegistryLoading] = useState(false);
  // 大脑 /api/agents/status 里的 services（应急响应 TIR 是独立 REST 服务，端口 8090，不归 reasonix 部件注册表管）
  const [agentsStatus, setAgentsStatus] = useState<AgentsStatus | null>(null);

  const healthCheck = useCallback(async () => {
    try {
      const r = await aisocApi.healthCheck();
      if (mountedRef.current) setBrainState(r.status === 'ok');
    } catch {
      if (mountedRef.current) setBrainState(false);
    }
    if (!mountedRef.current) return;
    setRegistryLoading(true);
    try {
      const reg = await aisocApi.getRegistry();
      if (mountedRef.current) setRegistry(reg);
    } catch {
      if (mountedRef.current) setRegistry(null);
    } finally {
      if (mountedRef.current) setRegistryLoading(false);
    }
    try {
      const st = await aisocApi.getAgentsStatus();
      if (mountedRef.current) setAgentsStatus(st);
    } catch {
      if (mountedRef.current) setAgentsStatus(null);
    }
  }, []);
  useEffect(() => { void healthCheck(); }, [healthCheck]);



  // ---- 任务创建表单状态（文档 §4.1 / §5） ----
  const [taskDesc, setTaskDesc] = useState('');
  const [domain, setDomain] = useState<CreateTaskInput['domain']>('logaudit');
  const [pipeline, setPipeline] = useState('');
  const [target, setTarget] = useState('');
  const [scopeTools, setScopeTools] = useState('');
  const [creating, setCreating] = useState(false);
  const [createHint, setCreateHint] = useState<{ kind: 'ok' | 'err'; text: string } | null>(null);

  // ---- 快速聊天状态 ----
  // chatSessionId：本次进入 AiSOC dashboard 的生命周期内稳定（UUID 风格）。
  // 作为大脑侧的 (session_id, domain) 缓存键 —— mount 内多个任务共享一个 session_id，
  // 部件会话复用保留上下文；刷页面 / 重进 dashboard → 新 session_id → 部件开新会话（/new）。
  const [chatSessionId] = useState<string>(() =>
    `aisoc-session-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
  );
  const [chatAgent, setChatAgent] = useState<QuickChatAgent>('auto');
  const [chatText, setChatText] = useState('');
  const [chatSubmitting, setChatSubmitting] = useState(false);

  // 应用外部传入的初始 Agent（App.tsx 浮动 Popover 选中后传过来）—— 仅生效一次
  const initialAgentAppliedRef = useRef(false);
  useEffect(() => {
    if (!initialAgent || initialAgentAppliedRef.current) return;
    initialAgentAppliedRef.current = true;
    setChatAgent(initialAgent);
    // 自动 focus 输入框 + 联动 domain（按 Agent 预填下面表单）
    const opt = QUICK_CHAT_OPTIONS.find(o => o.id === initialAgent);
    if (opt?.setDomain) {
      setDomain(opt.setDomain);
      setPipeline('');
      setTarget(prev => prev || (opt.setDomain === 'logaudit' ? '10.0.0.0/24' : 'https://target.edu.cn'));
    }
    // 下一帧 focus 到 QuickChat 输入框
    requestAnimationFrame(() => {
      const input = document.querySelector<HTMLTextAreaElement>('[data-testid="quick-chat-input"]');
      input?.focus();
    });
  }, [initialAgent]);

  // ---- 任务列表 ----
  const [tasks, setTasks] = useState<TaskInfo[]>([]);
  const [tasksLoading, setTasksLoading] = useState(false);
  const [selectedTask, setSelectedTask] = useState<TaskInfo | null>(null);

  const loadTasks = useCallback(async () => {
    if (mountedRef.current) setTasksLoading(true);
    try {
      const r = await aisocApi.listTasks(100);
      if (mountedRef.current) setTasks(r.tasks.sort((a, b) => (b.updated_at ?? '').localeCompare(a.updated_at ?? '')));
    } catch {
      if (mountedRef.current) setTasks([]);
    } finally {
      if (mountedRef.current) setTasksLoading(false);
    }
  }, []);
  useEffect(() => { void loadTasks(); }, [loadTasks]);

  // ---- 选中任务详情：Finding / Detail / Report ----
  const [findings, setFindings] = useState<Finding[]>([]);
  const [findingsLoading, setFindingsLoading] = useState(false);
  const [detail, setDetail] = useState<TaskDetail | null>(null);
  const [report, setReport] = useState<ReportDoc | null>(null);
  const [detailLoading, setDetailLoading] = useState(false);
  // ---- 应急响应（TIR）：告警 / 预案 / 报告 ----
  const [tirAlerts, setTirAlerts] = useState<TirAlert[]>([]);
  const [tirPlaybooks, setTirPlaybooks] = useState<TirPlaybook[]>([]);
  const [tirReports, setTirReports] = useState<TirReport[]>([]);
  const [tirBusy, setTirBusy] = useState(false);
  const [tirError, setTirError] = useState<string | null>(null);
  // TIR 三端点缺失/不可达的降级提示（与“任务确无应急响应数据”区分开）
  const [tirAvailability, setTirAvailability] = useState<TirAvailability>(null);

  const loadDetail = useCallback(async (taskId: string) => {
    if (mountedRef.current) setDetailLoading(true);
    if (mountedRef.current) setFindingsLoading(true);
    try {
      // TIR 三端点：非 real_threat 任务返回空数组属正常态；
      // 这里保留失败状态码，用于区分“后端路由未部署/服务不可达”。
      const [fs, dt, rp, ta, tp, tr] = await Promise.all([
        aisocApi.getFindings(taskId).catch(() => [] as Finding[]),
        aisocApi.getTask(taskId).catch(() => null),
        aisocApi.getReport(taskId).catch(() => null),
        aisocApi.getTirAlerts(taskId)
          .then((value) => ({ value, status: null as number | null }))
          .catch((e: unknown) => ({ value: [] as TirAlert[], status: tirFailureStatus(e) })),
        aisocApi.getTirPlaybooks(taskId)
          .then((value) => ({ value, status: null as number | null }))
          .catch((e: unknown) => ({ value: [] as TirPlaybook[], status: tirFailureStatus(e) })),
        aisocApi.getTirReports(taskId)
          .then((value) => ({ value, status: null as number | null }))
          .catch((e: unknown) => ({ value: [] as TirReport[], status: tirFailureStatus(e) })),
      ]);
      if (mountedRef.current) {
        setFindings(fs.sort((a, b) => (b.ts ?? b.timestamp ?? '').localeCompare(a.ts ?? a.timestamp ?? '')));
        setDetail(dt);
        setReport(rp);
        setTirAlerts(ta.value);
        setTirPlaybooks(tp.value);
        setTirReports(tr.value);
        setTirAvailability(summarizeTirAvailability([ta.status, tp.status, tr.status]));
      }
    } finally {
      if (mountedRef.current) {
        setFindingsLoading(false);
        setDetailLoading(false);
      }
    }
  }, []);

  useEffect(() => {
    if (!selectedTask) {
      setFindings([]); setDetail(null); setReport(null);
      setTirAlerts([]); setTirPlaybooks([]); setTirReports([]); setTirError(null);
      setTirAvailability(null);
      return;
    }
    void loadDetail(selectedTask.id);
  }, [selectedTask, loadDetail]);

  // TIR 审批：批准/拒绝预案 → 后端触发 8090 decision → 产出应急响应报告（文档 §4.4）
  const handleTirApprove = useCallback(async (playbookId: string, decision: 'approved' | 'denied') => {
    if (!selectedTask) return;
    if (mountedRef.current) { setTirBusy(true); setTirError(null); }
    try {
      const resp = await aisocApi.approveTool(selectedTask.id, playbookId, decision);
      if (mountedRef.current && resp.status === 'responded' && resp.report_id && resp.report_md) {
        // 后端已直接返回报告：先本地落一条，避免等待二次拉取的空白期
        setTirReports(prev => prev.some(r => r.report_id === resp.report_id)
          ? prev
          : [...prev, {
              report_id: resp.report_id as string,
              task_id: resp.task_id,
              playbook_id: resp.playbook_id,
              decision: decision === 'approved' ? 'approve' : 'reject',
              report_md: resp.report_md as string,
              created_at: new Date().toISOString(),
            }]);
      }
      // 再以后端落库结果为准刷新一次
      const fresh = await aisocApi.getTirReports(selectedTask.id).catch(() => null);
      if (fresh && mountedRef.current) setTirReports(fresh);
    } catch (err) {
      // 502 = 8090 不可用；401/404 = 鉴权失效 / 任务不存在。轻提示，不阻断页面。
      const msg = err instanceof Error ? err.message : '审批请求失败';
      if (mountedRef.current) setTirError(msg);
    } finally {
      if (mountedRef.current) setTirBusy(false);
    }
  }, [selectedTask]);

  // 任务列表轮询：每 8s 拉一次（用于列表状态、verdict 等字段刷新）。
  // 注意：不轮询 detail，避免周期重置 detail panel 的滚动位置/展开状态。
  // detail 刷新的触发点：
  //   1. selectedTask 变化（useEffect 依赖检测，已实现）
  //   2. RealtimePanel SSE 推送 stage_start/answer/report_ready 帧时（走 wire event 订阅）
  // 用 ref 持有当前选中任务，interval 只创建一次，避免选中切换时 teardown/recreate 造成的竞态。
  const pollRef = useRef<number | null>(null);
  useEffect(() => {
    pollRef.current = window.setInterval(() => {
      void loadTasks();
    }, 8000);
    return () => { if (pollRef.current) window.clearInterval(pollRef.current); };
  }, [loadTasks]);

  // ---- 创建任务（复用 /api/chat/stream，与聊天一样走透传流）—— 见下方 submitTaskViaStream ----

  // ---- 审计导出：GET /api/tasks/{id}/export（文档 §4.5） ----
  const exportTask = useCallback(async (taskId: string) => {
    try {
      const data = await aisocApi.exportTask(taskId);
      const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `aisoc-audit-${taskId}.json`;
      a.click();
      URL.revokeObjectURL(url);
    } catch (e) {
      setCreateHint({ kind: 'err', text: `导出失败：${e instanceof Error ? e.message : String(e)}` });
    }
  }, []);

  // ---- 复用 chat/stream 的流式输出（与聊天 Transcript 完全同源） ----
  // 设计：AisocDashboard 不再调 aisocApi.createTask，改调 webApiProxy.AisocSubmitForTab（包装了 chat/stream）。
  // 后端 chat/stream 识别为任务意图后会自动创建任务，并以 reasonix 原样帧透传到前端（pass_through=true）。
  // webApiProxy.AisocSubmitForTab 内部走 onFrame → emitEvent（与聊天 Submit 完全同源）。
  // AisocDashboard 通过 webApiProxy.onEvent(cb) 订阅同一份 WireEvent，按 tabId 过滤后维护本地 Item[]。
  // 流式输出区直接复用 chat 同款 AssistantMessage + ToolCard 渲染 —— 视觉上与聊天 Transcript 完全一致。
  type StreamItemsByTask = Record<string, { items: import('../lib/useController').Item[]; version: number; createdAt?: number }>;
  // 修复 Bug 1：streamItemsByTask 原本只放在 useState（组件内存态），AisocDashboard 在 viewMode
  // 切换 / 父组件 re-render 时会 unmount，之前的流式数据全部丢失。
  // 现在改为"本地 useState + webApiProxy 单例"双写：AisocDashboard mount 时从 webApiProxy
  // 拉回历史 items + version，unmount 后 webApiProxy 仍然持有，remount 能恢复。
  const [streamItemsByTask, setStreamItemsByTask] = useState<StreamItemsByTask>({});
  // 保留 setActiveStreamTabId 以备未来详情跳转使用。streamTabId → brain task_id 映射走
  // webApiProxy._lastStreamTaskId（onFrame 入口 set / getBrainTaskIdForStreamTab 暴露 getter）。
  const [_activeStreamTabId, setActiveStreamTabId] = useState<string | null>(null);

  /**
   * 修复 Bug 1：AisocDashboard mount 时从 webApiProxy 拉回历史流式 items，避免 remount 后清空。
   * 仅拉回 _lastStreamTaskId 已记录过的 streamTabId（避免恢复已 GC 的旧任务，减小内存）。
   */
  useEffect(() => {
    const webApi = getWebApi();
    const recovered: StreamItemsByTask = {};
    // 修复 Bug 1：key 必须严格对齐。getKnownStreamTabIds() 返回的是 streamTabId（`aisoc-task-...`），
    // 但 _aisocStreamItems 是按 brain task_id（`T...`）为 key 写入的（applyWireEvent 接的 taskId 是
    // brain task_id）。这里必须先把 streamTabId 转成 brain task_id，再用 brain task_id 去查
    // getAisocStreamItems，否则永远查不到、remount 后恢复为空。
    const knownTabs = webApi.getKnownStreamTabIds ? webApi.getKnownStreamTabIds() : [];
    for (const streamTabId of knownTabs) {
      const brainTaskId = webApi.getBrainTaskIdForStreamTab(streamTabId);
      if (!brainTaskId) continue; // frame 还没来，过滤掉仅注册了 streamTabId 但没收到 task_id 的
      const persisted = webApi.getAisocStreamItems(brainTaskId);
      if (!persisted) continue;
      // 同时拉回原 streamTabId → brain task_id 的映射（让 RealtimePanel 渲染时 key 用 brain task_id）
      recovered[brainTaskId] = {
        items: persisted.items as import('../lib/useController').Item[],
        version: persisted.version,
      };
    }
    if (Object.keys(recovered).length > 0) {
      setStreamItemsByTask(prev => ({ ...recovered, ...prev }));
    }
  }, []);

  /**
   * 把 items + version 同步到 webApiProxy 单例（修复 Bug 1）。
   * 接受 setState updater 函数，在 updater 返回的新 state 里对比 prev，把版本号有变化的 streamTabId
   * 同步到 webApiProxy。这样 unmount 后 webApiProxy 仍然持有，下次 remount 能拉回。
   */
  const persistStreamItems = useCallback((updater: (prev: StreamItemsByTask) => StreamItemsByTask) => {
    setStreamItemsByTask(prev => {
      const next = updater(prev);
      const webApi = getWebApi();
      for (const tabId of Object.keys(next)) {
        const cur = next[tabId];
        const old = prev[tabId];
        if (!old || old.version !== cur.version) {
          webApi.setAisocStreamItems(tabId, cur.items as unknown[], cur.version);
        }
      }
      return next;
    });
  }, []);

  /**
   * 把 WireEvent 增量维护到 streamItemsByTask[taskId]。
   * 复用 reducer 的事件形态（text/reasoning/tool_dispatch/tool_result/notice/phase/turn_done/message）
   * 让本地 Item[] 与 chat Transcript 同构。
   */
  const applyWireEvent = useCallback((ev: import('../lib/types').WireEvent, taskId: string) => {
    persistStreamItems(prev => {
      const cur = prev[taskId] ?? { items: [], version: 0 };
      // items 级 reducer 逻辑已提取到 lib/aisocStreamItems.ts（纯函数，便于用真实帧序列
      // 单测 answer 增量+全量 / tool_result 同文本去重等场景），此处只负责 bump + 持久化。
      const nextItems = applyStreamEvent([...cur.items], ev, taskId);
      if (nextItems === null) return prev; // 未消费的 kind：保持原 state、不 bump
      const trimmed = nextItems.length > 500 ? nextItems.slice(-500) : nextItems;
      return { ...prev, [taskId]: { items: trimmed, version: cur.version + 1 } };
    });
  }, [persistStreamItems]);

  /**
   * 订阅 webApiProxy.onEvent（与聊天 Transcript 同一份数据通道）。
   * 只订阅一次（unmount 取消）。
   */
  useEffect(() => {
    const webApi = getWebApi();
    const unsub = webApi.onEvent((ev) => {
      const tabId = ev.tabId;
      if (!tabId) return;
      // 修复 Bug 2：streamTabId → brain task_id 映射走 webApiProxy._lastStreamTaskId
      // （onFrame 入口统一记录，不依赖 task_created 帧，pass_through=true 模式下也生效）。
      // 这里不再用本地 useRef，避免 AisocDashboard unmount 后映射丢失。
      const brainTaskId = webApi.getBrainTaskIdForStreamTab(tabId);
      const taskId = brainTaskId ?? tabId; // 没收到 frame 前退化用 tabId 本身
      applyWireEvent(ev, taskId);
    });
    return unsub;
  }, [applyWireEvent]);

  const submitTaskViaStream = useCallback(async () => {
    if (!target || !taskDesc) return;
    setCreating(true);
    setCreateHint(null);
    try {
      // 复用 /api/chat/stream（同一套接口）—— 后端 chat/stream 识别为任务意图后自动创建任务，
      // 并以 reasonix 原样帧持续透传到前端（pass_through=true）。
      const userMessage = `${domain === 'pentest' ? '渗透测试' : domain === 'logaudit' ? '审计' : domain === 'incident' ? '应急响应' : '分析'} ${target} ${taskDesc}`;
      const streamTabId = `aisoc-task-${Date.now()}`;
      // 修复 Bug 1/2：streamTabId 不再记本地 useRef，改由 webApiProxy.onFrame 入口统一维护映射。
      setActiveStreamTabId(streamTabId);
      // 优化：用户提交任务后，RealtimePanel 之前是一片空白直到首个 SSE 帧到达
      // （pass_through=true 实测首字节 36 秒）。这里立即写一条 phase 占位 + 记录 createdAt，
      // 让 RealtimePanel 立刻渲染 spinner + 等待提示，避免视觉上空白的等待感。
      persistStreamItems(prev => ({
        ...prev,
        [streamTabId]: {
          items: [{
            kind: 'phase',
            id: `phase-waiting-${Date.now()}`,
            text: '⏳ 等待大脑响应（首字节通常 5–30 秒，长任务更久）',
          }],
          version: 1,
          createdAt: Date.now(),
        },
      }));
      // 走 webApiProxy.AisocSubmitForTab → onFrame → emitEvent → onEvent（与聊天 Transcript 同源）
      const webApi = getWebApi();
      // 修复 Bug【pipeline 丢失】:之前只传 userMessage，pipeline / domain / target 只走 UI state
      // 没传到后端，导致“创建任务 → pipeline=data_leak”只走单 stage 后端被默认处理成单 stage。
      // 现在透传给 AisocSubmitForTab → webApiProxy → aisocApi.chatStream，后端能拿到这三个字段。
      // 后端 chat/stream 拿到 pipeline 后会启动多阶段管道（logaudit → pentest → verdict → report）。
      void webApi.AisocSubmitForTab(streamTabId, userMessage, {
        passThrough: true,
        sessionId: chatSessionId,
        pipeline: pipeline || undefined,
        domain,
        target,
      }).catch((err: unknown) => {
        setCreateHint({
          kind: 'err',
          text: `下发失败（未预期异常）：${err instanceof Error ? err.message : String(err)}。检查大脑服务（:${DOMAIN_PORTS.brain}）是否在线 / 命中授权白名单。`,
        });
      });
      setCreateHint({
        kind: 'ok',
        text: `任务已通过 chat/stream 下发（streamTabId=${streamTabId}），流式输出见“实时监控 → 流式输出区”。`,
      });
      setTaskDesc('');
      setScopeTools('');
      await loadTasks();
      setRightTab('realtime');
    } catch (e) {
      setCreateHint({
        kind: 'err',
        text: `下发失败：${e instanceof Error ? e.message : String(e)}。检查大脑服务（:${DOMAIN_PORTS.brain}）是否在线 / 命中授权白名单。`,
      });
    } finally {
      setCreating(false);
    }
  }, [target, taskDesc, domain, pipeline, scopeTools, loadTasks, chatSessionId]);

  /**
   * 快速聊天提交：用户选 Agent + 输入文本 → 加上触发词前缀 → 复用 AisocSubmitForTab
   * 走 chat/stream（与 TaskCreateForm 同一套数据通道、流式输出、错误兑底逻辑）。
   * Agent 选 ≠ null 时会预填 TaskCreateForm 的 domain（保持两个面板联动），
   * 并在 hint 中说明本次任务使用了哪个 Agent。
   */
  const submitQuickChat = useCallback(async () => {
    const text = chatText.trim();
    if (!text) return;

    const opt = QUICK_CHAT_OPTIONS.find(o => o.id === chatAgent) ?? QUICK_CHAT_OPTIONS[0];
    const userMessage = opt.prefix(text);

    // 联动 TaskCreateForm：预填 domain（用户后续也可以手动改）
    if (opt.setDomain) {
      setDomain(opt.setDomain);
      setPipeline(''); // 快捷聊天默认不走 pipeline
      // 如果 target 为空也补一个默认 placeholder
      setTarget(prev => prev || (opt.setDomain === 'logaudit' ? '10.0.0.0/24' : 'https://target.edu.cn'));
    }

    setChatSubmitting(true);
    setCreateHint(null);
    try {
      const streamTabId = `aisoc-task-${Date.now()}`;
      setActiveStreamTabId(streamTabId);
      // 立即写占位 phase（与 submitTaskViaStream 一致）
      persistStreamItems(prev => ({
        ...prev,
        [streamTabId]: {
          items: [{
            kind: 'phase',
            id: `phase-waiting-${Date.now()}`,
            text: `⏳ ${opt.label} 等待大脑响应（首字节通常 5–30 秒）`,
          }],
          version: 1,
          createdAt: Date.now(),
        },
      }));

      const webApi = getWebApi();
      // 修复 Bug【pipeline 丢失】同 submitTaskViaStream：补齐 domain / target 透传，
      // 让大脑能正确接受快聊创建的单 stage 任务（之前只传 userMessage → 后端拿不到 target / domain）。
      // 快捷聊天默认不走 pipeline（setPipeline(''))。
      void webApi.AisocSubmitForTab(streamTabId, userMessage, {
        passThrough: true,
        sessionId: chatSessionId,
        domain: opt.setDomain ?? domain,
        target,
      }).catch((err: unknown) => {
        setCreateHint({
          kind: 'err',
          text: `下发失败（${opt.label}）：${err instanceof Error ? err.message : String(err)}。检查大脑服务（:${DOMAIN_PORTS.brain}）是否在线。`,
        });
      });

      setCreateHint({
        kind: 'ok',
        text: `✅ [${opt.label}] 已下发：${userMessage.slice(0, 80)}${userMessage.length > 80 ? '…' : ''}`,
      });
      setChatText(''); // 清空输入
      await loadTasks();
      setRightTab('realtime');
    } catch (e) {
      setCreateHint({
        kind: 'err',
        text: `下发失败：${e instanceof Error ? e.message : String(e)}`,
      });
    } finally {
      setChatSubmitting(false);
    }
  }, [chatAgent, chatText, loadTasks, chatSessionId]);

  // ---- UI：右侧主 Tab ----
  const [rightTab, setRightTab] = useState<'tasks' | 'realtime' | 'detail' | 'whitelist'>('tasks');

  // ---- 布局：左右两列可拖拽分隔（修复子界面不能左右拖拽放大的问题） ----
  // leftRatio：左列占比（百分比 15~85）。持久化到 localStorage，刷新后保留。
  // topRatio：detail panel 里上下两区域占比（15~85，默认 50）。
  // 拖拽过程中状态以 ref 存，避免 React 重渲染受鼠标移动频繁拖累。
  const SPLIT_LS_KEY = 'aisoc:left-ratio';
  const SPLIT_V_LS_KEY = 'aisoc:detail-top-ratio';

  const readPersistedNumber = (key: string, fallback: number, min: number, max: number): number => {
    try {
      const raw = typeof window !== 'undefined' ? window.localStorage.getItem(key) : null;
      const n = raw ? Number(raw) : NaN;
      return Number.isFinite(n) && n >= min && n <= max ? n : fallback;
    } catch { return fallback; }
  };

  const [leftRatio, setLeftRatio] = useState<number>(() => readPersistedNumber(SPLIT_LS_KEY, 33, 15, 85));
  const [topRatio, setTopRatio] = useState<number>(() => readPersistedNumber(SPLIT_V_LS_KEY, 50, 15, 85));

  // 拖拽起点：在 shell 元素上记下鼠标 X/Y + 当时比例 + shell 元素，后续 mousemove
  // 根据 delta / shellWidth 算出新比例。这样不受 CSS grid re-layout 干扰。
  type DragState = { axis: 'h' | 'v'; startCoord: number; startRatio: number; shellEl: HTMLElement | null };
  const dragStateRef = useRef<DragState | null>(null);

  const onSplitMouseDown = (e: React.MouseEvent<HTMLDivElement>) => {
    e.preventDefault();
    const shellEl = (e.currentTarget.closest('.aisoc-shell') as HTMLElement | null);
    dragStateRef.current = { axis: 'h', startCoord: e.clientX, startRatio: leftRatio, shellEl };
    document.body.style.cursor = 'col-resize';
    document.body.style.userSelect = 'none';
  };

  const onSplitVMouseDown = (e: React.MouseEvent<HTMLDivElement>) => {
    e.preventDefault();
    const shellEl = (e.currentTarget.closest('.aisoc-detail-panel') as HTMLElement | null);
    dragStateRef.current = { axis: 'v', startCoord: e.clientY, startRatio: topRatio, shellEl };
    document.body.style.cursor = 'row-resize';
    document.body.style.userSelect = 'none';
  };

  useEffect(() => {
    const onMove = (e: MouseEvent) => {
      const st = dragStateRef.current;
      if (!st || !st.shellEl) return;
      const rect = st.shellEl.getBoundingClientRect();
      if (st.axis === 'h') {
        // 减掉 12px (p-3 × 2) + 8px (分隔条) 得到有效内容区宽度
        const usable = Math.max(200, rect.width - 12 * 2 - 8);
        const deltaRatio = ((e.clientX - st.startCoord) / usable) * 100;
        const next = Math.min(85, Math.max(15, st.startRatio + deltaRatio));
        setLeftRatio(next);
      } else {
        // 减掉 8px (分隔条) 得到有效内容区高度
        const usable = Math.max(150, rect.height - 8);
        const deltaRatio = ((e.clientY - st.startCoord) / usable) * 100;
        const next = Math.min(85, Math.max(15, st.startRatio + deltaRatio));
        setTopRatio(next);
      }
    };
    const onUp = () => {
      if (dragStateRef.current) {
        dragStateRef.current = null;
        document.body.style.cursor = '';
        document.body.style.userSelect = '';
      }
    };
    window.addEventListener('mousemove', onMove);
    window.addEventListener('mouseup', onUp);
    return () => {
      window.removeEventListener('mousemove', onMove);
      window.removeEventListener('mouseup', onUp);
      document.body.style.cursor = '';
      document.body.style.userSelect = '';
    };
  }, []);

  // 持久化 leftRatio / topRatio
  useEffect(() => {
    try { window.localStorage.setItem(SPLIT_LS_KEY, String(Math.round(leftRatio))); } catch {}
  }, [leftRatio]);
  useEffect(() => {
    try { window.localStorage.setItem(SPLIT_V_LS_KEY, String(Math.round(topRatio))); } catch {}
  }, [topRatio]);

  // 双击分隔条重置为默认比例
  const onSplitDoubleClick = () => setLeftRatio(33);
  const onSplitVDoubleClick = () => setTopRatio(50);

  // ---- 计算：部件连接灯（注册表数组查找；应急响应 incident 走 /api/agents/status 的 services.tir） ----
  const domainStates: Record<string, ConnectState> = useMemo(() => {
    const out: Record<string, ConnectState> = {};
    for (const d of ALL_DOMAINS) {
      if (d === 'incident') {
        // 应急响应 TIR 是独立 REST 服务（:8090），不在 registry 里。
        // 用大脑 /api/agents/status 的 services.tir.status 判定。
        const tir = agentsStatus?.services?.tir;
        if (!agentsStatus) out[d] = brainState === null ? 'loading' : (brainState ? 'off' : 'warn');
        else if (!tir) out[d] = 'off';
        else if (tir.status === 'online') out[d] = brainState ? 'ok' : 'warn';
        else if (tir.status === 'starting') out[d] = 'loading';
        else out[d] = 'off';
        continue;
      }
      if (registryLoading) out[d] = 'loading';
      else if (!registry) out[d] = brainState === null ? 'loading' : 'off';
      else if (registry.find(r => r.domain === d)) {
        out[d] = brainState ? 'ok' : 'warn';
      }
      else out[d] = 'off';
    }
    return out;
  }, [registry, registryLoading, brainState, agentsStatus]);

  const brainConnectState = stateFromHealth(brainState, registryLoading);

  return (
    <div className="aisoc-shell h-full w-full min-h-0 flex flex-col" style={{ fontFamily: 'system-ui, -apple-system, "Segoe UI", "PingFang SC", "Microsoft YaHei", sans-serif' }}>
      {/* 顶栏 */}
      <header className="px-4 py-2 border-b aisoc-header text-white flex items-center gap-3">
        {onExit && (
          <button
            type="button"
            onClick={onExit}
            className="text-xs px-2 py-1 rounded bg-white/15 hover:bg-white/25 transition-colors inline-flex items-center gap-1 shrink-0"
          >
            <ArrowLeft className="w-3.5 h-3.5" /> 返回聊天
          </button>
        )}
        <div className="w-7 h-7 rounded-full bg-white/20 flex items-center justify-center shrink-0">
          <Sparkles className="w-4 h-4" />
        </div>
        <div>
          <div className="text-sm font-bold">校园智盾 AiSOC · 多 Agent 安全运营平台</div>
          <div className="text-[11px] opacity-80">DeepSeek 作动力源 · 大脑 FastAPI :{DOMAIN_PORTS.brain} 编排 · 统一 CreateTask / TaskInfo / Finding / Report 协议</div>
        </div>
        <div className="flex-1" />
        <button
          type="button"
          onClick={() => void healthCheck()}
          className="text-xs px-2 py-1 rounded bg-white/15 hover:bg-white/25 transition-colors inline-flex items-center gap-1"
        >
          <RefreshCw className="w-3 h-3" /> 健康检查
        </button>
        <button
          type="button"
          onClick={() => void loadTasks()}
          className="text-xs px-2 py-1 rounded bg-white/15 hover:bg-white/25 transition-colors inline-flex items-center gap-1"
        >
          <Zap className="w-3 h-3" /> 刷新任务
        </button>
        {onExit && (
          <button
            type="button"
            onClick={onExit}
            data-testid="aisoc-exit-button"
            aria-label="退出 AiSOC 返回聊天"
            title="退出 AiSOC 返回聊天（Esc）"
            className="ml-1 text-xs px-2 py-1 rounded bg-rose-500/80 hover:bg-rose-500 transition-colors inline-flex items-center gap-1 font-medium"
          >
            <X className="w-3.5 h-3.5" /> 退出
          </button>
        )}
      </header>

      {/* 大脑离线提示：优雅降级，不再暴露原始 502 */}
      {brainState === false && (
        <div className="mx-3 mt-3 px-3 py-2 rounded-lg border border-amber-300 bg-amber-50 text-amber-800 text-xs flex items-center gap-2">
          <AlertTriangle className="w-4 h-4 shrink-0" />
          <span>
            大脑服务未运行（127.0.0.1:{DOMAIN_PORTS.brain}）。当前为离线预览模式：任务创建与实时监控暂不可用，请先启动大脑 FastAPI 服务后再试。
          </span>
        </div>
      )}

      {/* 主体两列（可拖拽分隔） */}
      <div
        className="flex-1 min-h-0 p-3"
        style={{
          display: 'grid',
          gridTemplateColumns: `${leftRatio}% 8px ${100 - leftRatio}%`,
          gap: 12,
        }}
      >
        {/* 左列（架构 + 表单） */}
        <div className="min-h-0 flex flex-col gap-3 overflow-y-auto pr-1">
          {/* 流程监控图（顶视图：用户 → 大脑 → 4 Agent 数据流） */}
          <ArchitectureFlow
            brainState={brainConnectState}
            domainStates={domainStates}
            tasks={tasks}
            onSelectAgent={(d) => {
              if (d === 'pentest' || d === 'logaudit') {
                setDomain(d);
                setPipeline('');
              }
              setTarget(t => t || (d === 'logaudit' ? '10.0.0.0/24' : 'https://target.edu.cn'));
            }}
            onFocusUserInput={() => {
              const input = document.querySelector<HTMLTextAreaElement>('[data-testid="quick-chat-input"]');
              input?.focus();
              input?.scrollIntoView({ block: 'center', behavior: 'smooth' });
            }}
          />

          {/* 大脑中心卡 */}
          <BrainCenterCard
            brainState={brainConnectState}
            registryLoaded={registry !== null}
            registryCount={registry ? registry.length : 0}
          />

          {/* 子部件状态：2 列（上面渗透+审计，下面情报+应急） */}
          <div className="grid grid-cols-2 gap-2">
            {ALL_DOMAINS.map(d => (
              <DomainNode
                key={d}
                domain={d}
                registry={registry?.find(r => r.domain === d)}
                portOverride={d === 'incident' ? agentsStatus?.services?.tir?.port : undefined}
                state={domainStates[d] ?? 'off'}
                onClick={() => {
                  // 点击部件域 → 预填 domain（只有 pentest / logaudit 是大脑可直跑的单域）
                  if (d === 'pentest' || d === 'logaudit') {
                    setDomain(d);
                    setPipeline('');
                  }
                  setTarget(t => t || (d === 'logaudit' ? '10.0.0.0/24' : 'https://target.edu.cn'));
                }}
              />
            ))}
          </div>

          {/* 快速聊天（指定 Agent）—— 最常用的入口：选 Agent + 填描述 + Enter 发送 */}
          <QuickChatInput
            chatAgent={chatAgent}
            setChatAgent={setChatAgent}
            chatText={chatText}
            setChatText={setChatText}
            submitting={chatSubmitting}
            onSend={() => void submitQuickChat()}
            disabled={brainState === false}
          />

          {/* 任务创建表单（复用 chat/stream 接口，与聊天一样走流式输出） */}
          <TaskCreateForm
            taskDesc={taskDesc}
            setTaskDesc={setTaskDesc}
            domain={domain}
            setDomain={setDomain}
            pipeline={pipeline}
            setPipeline={setPipeline}
            target={target}
            setTarget={setTarget}
            scopeTools={scopeTools}
            setScopeTools={setScopeTools}
            submitting={creating}
            onSubmit={submitTaskViaStream}
            brainOk={brainState}
          />

          {createHint && (
            <div className={`rounded-lg border px-3 py-2 text-xs flex items-start gap-2 ${
              createHint.kind === 'ok' ? 'bg-emerald-50 text-emerald-800 border-emerald-200' : 'bg-red-50 text-red-800 border-red-200'
            }`}>
              {createHint.kind === 'ok' ? <CheckCircle2 className="w-4 h-4 mt-0.5 shrink-0" /> : <AlertTriangle className="w-4 h-4 mt-0.5 shrink-0" />}
              <span>{createHint.text}</span>
            </div>
          )}

          {/* 星型拓扑示意（文本型） */}
          <div className="rounded-xl border border-dashed border-fuchsia-200 bg-fuchsia-50/40 p-3 text-[11px] text-zinc-600 leading-relaxed">
            <div className="font-semibold text-zinc-700 mb-1 flex items-center gap-1">
              <Network className="w-3.5 h-3.5" />
              架构提醒（星型拓扑）
            </div>
            <p>前端不直接访问子部件。<strong className="text-fuchsia-700">所有任务 → AiSOC 大脑 :{DOMAIN_PORTS.brain}</strong>（统一白名单校验 / 证据入库 / 交叉验证 / 判定 / 报告 / SSE / 思维链审计）。大脑再按阶段调度各部件端口（{DOMAIN_PORTS.pentest} / {DOMAIN_PORTS.logaudit} / …）。用户永远只和大脑交互。</p>
          </div>
        </div>

        {/* 可拖拽分隔条（双击重置 33%）。做成 IDE 风格的“点点把手”，对用户明显可见。
           关键点：内层圆点要 pointer-events:none + cursor:inherit，否则鼠标移到圆点上时光标会从 col-resize 变回 auto。 */}
        <div
          className="cursor-col-resize bg-zinc-200 hover:bg-fuchsia-100 active:bg-fuchsia-200 transition-colors rounded-sm flex items-center justify-center"
          onMouseDown={onSplitMouseDown}
          onDoubleClick={onSplitDoubleClick}
          title="拖拽调整左右列宽（双击重置 33%）"
          role="separator"
          aria-orientation="vertical"
          aria-label="调整左右列宽"
          style={{ cursor: 'col-resize' }}
        >
          <div className="flex flex-col gap-1 items-center" style={{ pointerEvents: 'none', cursor: 'col-resize' }}>
            <span className="w-1 h-1 rounded-full bg-zinc-500" />
            <span className="w-1 h-1 rounded-full bg-zinc-500" />
            <span className="w-1 h-1 rounded-full bg-zinc-500" />
          </div>
        </div>

        {/* 右列：Tab 切换（任务列表 / 实时面板 / 详情） */}
        <div className="min-h-0 flex flex-col border border-zinc-200 rounded-xl bg-white overflow-hidden">
          <div className="flex items-center gap-1 px-2 py-1.5 border-b bg-zinc-50">
            <button
              type="button"
              onClick={() => setRightTab('tasks')}
              className={`px-3 py-1 text-xs font-medium rounded-t flex items-center gap-1 transition-colors ${
                rightTab === 'tasks' ? 'bg-white text-fuchsia-700 ring-1 ring-fuchsia-200' : 'text-zinc-600 hover:text-zinc-800 hover:bg-white'
              }`}
            >
              <Database className="w-3.5 h-3.5" /> 任务列表
            </button>
            <button
              type="button"
              onClick={() => setRightTab('realtime')}
              className={`px-3 py-1 text-xs font-medium rounded-t flex items-center gap-1 transition-colors ${
                rightTab === 'realtime' ? 'bg-white text-fuchsia-700 ring-1 ring-fuchsia-200' : 'text-zinc-600 hover:text-zinc-800 hover:bg-white'
              }`}
            >
              <Activity className="w-3.5 h-3.5" /> 实时 SSE 面板
            </button>
            <button
              type="button"
              onClick={() => setRightTab('detail')}
              className={`px-3 py-1 text-xs font-medium rounded-t flex items-center gap-1 transition-colors ${
                rightTab === 'detail' ? 'bg-white text-fuchsia-700 ring-1 ring-fuchsia-200' : 'text-zinc-600 hover:text-zinc-800 hover:bg-white'
              }`}
            >
              <Cpu className="w-3.5 h-3.5" /> 证据 & 判定 & 报告
              {selectedTask && <span className="ml-1 font-mono text-[10px] text-zinc-500">{selectedTask.id}</span>}
            </button>
            <button
              type="button"
              onClick={() => setRightTab('whitelist')}
              className={`px-3 py-1 text-xs font-medium rounded-t flex items-center gap-1 transition-colors ${
                rightTab === 'whitelist' ? 'bg-white text-fuchsia-700 ring-1 ring-fuchsia-200' : 'text-zinc-600 hover:text-zinc-800 hover:bg-white'
              }`}
            >
              <ShieldCheck className="w-3.5 h-3.5" /> 授权白名单
            </button>
            <div className="flex-1" />
            {selectedTask && (
              <div className="text-[11px] text-zinc-500 flex items-center gap-1 mr-2">
                当前选中：<ChevronRight className="w-3 h-3" /> {selectedTask.id}
                <span className={`ml-1 px-1.5 py-0.5 rounded ${TASK_STATUS_META[selectedTask.status]?.cls ?? ''}`}>
                  {TASK_STATUS_META[selectedTask.status]?.label ?? selectedTask.status}
                </span>
              </div>
            )}
          </div>

          <div className="flex-1 min-h-0">
            {rightTab === 'tasks' && (
              <TaskList
                tasks={tasks}
                loading={tasksLoading}
                selectedId={selectedTask?.id ?? null}
                onSelect={setSelectedTask}
                onRefresh={() => void loadTasks()}
              />
            )}
            {rightTab === 'realtime' && (
              <div className="h-full min-h-0">
                <RealtimePanel
                  autoConnect={brainState !== false}
                  streamItemsByTask={streamItemsByTask}
                  onTaskClick={(streamTabId) => {
                    // 修复 Bug 2：streamTabId 是前端临时 ID（`aisoc-task-${Date.now()}`），
                    // 与 tasks 列表里的 brain 任务 ID（`T...`）格式完全不同——之前直接用
                    // tasks.find(x => x.id === streamTabId) 永远找不到，导致点"查看详情"后
                    // selectedTask 始终为 null，detail tab 空白。
                    // 现在通过 webApiProxy 维护的 streamTabId → brain task_id 映射反查。
                    const webApi = getWebApi();
                    const brainTaskId = webApi.getBrainTaskIdForStreamTab(streamTabId);
                    const t = brainTaskId ? (tasks.find(x => x.id === brainTaskId) ?? null) : null;
                    if (t) setSelectedTask(t);
                    setRightTab('detail');
                  }}
                />
              </div>
            )}
            {rightTab === 'detail' && (
              <div
                className="aisoc-detail-panel h-full min-h-0"
                style={{
                  display: 'grid',
                  gridTemplateRows: `${topRatio}% 8px ${100 - topRatio}%`,
                }}
              >
                <div className="min-h-0 overflow-hidden">
                  <FindingsView findings={findings} loading={findingsLoading} task={selectedTask} />
                </div>

                {/* 可拖拽分隔条（双击重置 50%）。三点把手，明显可见。
                   同上：圆点 pointer-events:none + cursor:row-resize，防止内层拦截事件/光标变成 auto。 */}
                <div
                  className="cursor-row-resize bg-zinc-200 hover:bg-fuchsia-100 active:bg-fuchsia-200 transition-colors rounded-sm flex items-center justify-center"
                  onMouseDown={onSplitVMouseDown}
                  onDoubleClick={onSplitVDoubleClick}
                  title="拖拽调整上下区域高度（双击重置 50%）"
                  role="separator"
                  aria-orientation="horizontal"
                  aria-label="调整详情上下区域高度"
                  style={{ cursor: 'row-resize' }}
                >
                  <div className="flex gap-1 items-center" style={{ pointerEvents: 'none', cursor: 'row-resize' }}>
                    <span className="w-1 h-1 rounded-full bg-zinc-500" />
                    <span className="w-1 h-1 rounded-full bg-zinc-500" />
                    <span className="w-1 h-1 rounded-full bg-zinc-500" />
                  </div>
                </div>

                <div className="min-h-0 overflow-y-auto">
                  <VerdictReportCard
                    detail={detail}
                    report={report}
                    loading={detailLoading}
                    task={selectedTask}
                    onExport={() => { if (selectedTask) void exportTask(selectedTask.id); }}
                  />
                  {selectedTask && (
                    <TirPanel
                      task={selectedTask}
                      alerts={tirAlerts}
                      playbooks={tirPlaybooks}
                      reports={tirReports}
                      busy={tirBusy}
                      error={tirError}
                      unavailable={tirAvailability}
                      onApprove={handleTirApprove}
                    />
                  )}
                </div>
              </div>
            )}
            {rightTab === 'whitelist' && <WhitelistPanel />}
          </div>
        </div>
      </div>

      {/* 底栏状态条 */}
      <footer className="px-4 py-1.5 border-t bg-white text-[11px] text-zinc-500 flex items-center gap-3 flex-wrap">
        <span>统一接口：POST /api/tasks · GET /api/tasks · /findings · /reports · /stream（frontend-api.md）</span>
        <span>·</span>
        <span>状态机：pending → running → approval → completed / failed</span>
        <span>·</span>
        <span>报告为 Markdown · 审计可导出 JSON · token 脱敏不渲染</span>
      </footer>
    </div>
  );
}

export default AisocDashboard;

// ---------------------------------------------------------------------------
// 白名单管理面板（授权白名单·GET/POST /api/whitelist）
// ---------------------------------------------------------------------------

/**
 * 授权白名单 Tab：查看当前 targets / 添加 / 删除 / 开关 enabled。
 *
 * - 后端：aisoc-brain-lyx/api，端口 6657
 *   GET  /api/whitelist → { enabled, targets }
 *   POST /api/whitelist { action: 'add'|'remove'|'set_enabled', target?, enabled? }
 *   写入 data/whitelist.json，重启不丢
 * - 不支持 CIDR，是精确字符串匹配（单 IP / 域名 / 带 scheme 的 URL）
 * - enabled=false → 后端全部放行（危险！仅临时调试用，UI 上会高亮警告）
 */
function WhitelistPanel() {
  const [data, setData] = useState<WhitelistView | null>(null);
  const [loading, setLoading] = useState(false);
  const [input, setInput] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const reload = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const w = await aisocApi.listWhitelist();
      setData(w);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void reload();
  }, [reload]);

  const onAdd = useCallback(async () => {
    const t = input.trim();
    if (!t) {
      setError('请输入目标（IP / 域名 / URL）');
      return;
    }
    setBusy(true);
    setError(null);
    try {
      const w = await aisocApi.addWhitelistTarget(t);
      setData(w);
      setInput('');
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  }, [input]);

  const onRemove = useCallback(async (target: string) => {
    setBusy(true);
    setError(null);
    try {
      const w = await aisocApi.removeWhitelistTarget(target);
      setData(w);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  }, []);

  const onToggleEnabled = useCallback(async (next: boolean) => {
    setBusy(true);
    setError(null);
    try {
      const w = await aisocApi.setWhitelistEnabled(next);
      setData(w);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  }, []);

  const enabled = data?.enabled ?? true;
  const targets = data?.targets ?? [];

  return (
    <div className="h-full min-h-0 overflow-auto p-4 space-y-4">
      {/* 标题 + 刷新 */}
      <div className="flex items-center gap-2">
        <ShieldCheck className="w-4 h-4 text-fuchsia-700" />
        <h3 className="text-sm font-semibold text-zinc-800">授权白名单</h3>
        <span className="text-[11px] text-zinc-500">
          （后端 aisoc-brain-lyx：GET/POST /api/whitelist）
        </span>
        <div className="flex-1" />
        <button
          type="button"
          onClick={() => void reload()}
          disabled={loading || busy}
          className="px-2 py-1 text-[11px] rounded border border-zinc-300 hover:bg-zinc-50 disabled:opacity-50 flex items-center gap-1"
        >
          <RefreshCw className={`w-3 h-3 ${loading ? 'animate-spin' : ''}`} />
          刷新
        </button>
      </div>

      {/* 开关 */}
      <div className="flex items-center gap-3 p-3 rounded-lg border border-zinc-200 bg-zinc-50">
        <label className="flex items-center gap-2 cursor-pointer">
          <input
            type="checkbox"
            checked={enabled}
            disabled={busy}
            onChange={(e) => void onToggleEnabled(e.target.checked)}
            className="w-4 h-4 accent-fuchsia-600"
          />
          <span className="text-sm text-zinc-800">
            白名单{' '}
            <span className={enabled ? 'text-emerald-700 font-medium' : 'text-rose-700 font-medium'}>
              {enabled ? '已启用' : '已关闭（全部放行）'}
            </span>
          </span>
        </label>
        {!enabled && (
          <span className="text-[11px] text-rose-700 bg-rose-50 border border-rose-200 px-1.5 py-0.5 rounded">
            ⚠ 危险：关闭后大脑不检查目标，任何 IP/域名都可通过
          </span>
        )}
      </div>

      {/* 添加输入 */}
      <div className="flex items-center gap-2 p-3 rounded-lg border border-zinc-200 bg-white">
        <input
          type="text"
          value={input}
          disabled={busy}
          onChange={(e) => setInput(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === 'Enter') void onAdd();
          }}
          placeholder="输入 IP / 域名 / URL，如 192.168.1.100 或 example.com"
          className="flex-1 px-2 py-1 text-sm border border-zinc-300 rounded font-mono focus:outline-none focus:ring-1 focus:ring-fuchsia-400"
        />
        <button
          type="button"
          onClick={() => void onAdd()}
          disabled={busy || !input.trim()}
          className="px-3 py-1 text-xs rounded bg-fuchsia-600 text-white hover:bg-fuchsia-700 disabled:opacity-50 flex items-center gap-1"
        >
          <Plus className="w-3.5 h-3.5" />
          添加
        </button>
      </div>

      {/* 错误提示 */}
      {error && (
        <div className="px-3 py-2 text-xs text-rose-700 bg-rose-50 border border-rose-200 rounded flex items-center gap-2">
          <AlertTriangle className="w-3.5 h-3.5" />
          {error}
        </div>
      )}

      {/* 列表 */}
      <div className="space-y-1">
        <div className="flex items-center gap-2 text-[11px] text-zinc-500 px-1">
          <span>共 {targets.length} 个目标</span>
          <span>·</span>
          <span>精确匹配，不支持 CIDR</span>
        </div>
        {targets.length === 0 ? (
          <div className="text-xs text-zinc-400 px-3 py-6 text-center border border-dashed border-zinc-200 rounded">
            {loading ? '加载中…' : '白名单为空，请添加至少一个目标'}
          </div>
        ) : (
          <ul className="divide-y divide-zinc-200 border border-zinc-200 rounded-lg overflow-hidden bg-white">
            {targets.map((t) => (
              <li
                key={t}
                className="flex items-center gap-2 px-3 py-2 hover:bg-zinc-50 group"
              >
                <ShieldCheck className="w-3.5 h-3.5 text-emerald-600 shrink-0" />
                <span className="flex-1 font-mono text-xs text-zinc-800 break-all">{t}</span>
                <button
                  type="button"
                  onClick={() => void onRemove(t)}
                  disabled={busy}
                  className="px-2 py-0.5 text-[11px] rounded border border-zinc-300 text-rose-700 hover:bg-rose-50 hover:border-rose-300 disabled:opacity-50 flex items-center gap-1 opacity-0 group-hover:opacity-100 transition-opacity"
                  title={`从白名单移除 ${t}`}
                >
                  <Minus className="w-3 h-3" />
                  删除
                </button>
              </li>
            ))}
          </ul>
        )}
      </div>
    </div>
  );
}
