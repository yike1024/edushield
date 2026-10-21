/**
 * 实时面板组件
 * 按 docs/frontend-api.md §4.8（SSE）与 §4.1c（Agent 状态墙）实现
 * 显示Agent状态墙 + 流式输出区
 */

import { useEffect, useState, useCallback, useRef } from 'react';
import { RefreshCw, AlertCircle, CheckCircle2, Clock, Play, Pause, Eye, Activity, Loader2 } from 'lucide-react';
import { aisocApi, type StreamEvent, type Finding } from '../lib/aisoc-api';
import type { Item } from '../lib/useController';
import { AssistantMessage } from './Message';
import { ToolCard } from './ToolCard';

/**
 * Agent状态
 */
interface AgentStatus {
  domain: string;           // 部件域名
  displayName: string;      // 显示名称
  status: 'idle' | 'running' | 'error' | 'waiting_approval';
  currentTask?: string;     // 当前任务ID
  currentPhase?: string;    // 当前阶段
  activeTools: ToolStatus[]; // 活跃工具列表
  lastUpdate: string;       // 最后更新时间
  busy?: boolean;           // 忙闲（来自 GET /api/agents/status）
  enabled?: boolean;        // 是否启用（来自 GET /api/agents/status）
}

/**
 * 工具状态
 */
interface ToolStatus {
  id: string;
  name: string;
  status: 'running' | 'completed' | 'failed' | 'pending_approval';
  startTime: string;
  duration?: number;
  result?: string;
  error?: string;
}

/**
 * 任务输出（复 chat Transcript 同款 Item[]：assistant / tool / notice / phase 等）
 */
interface TaskOutput {
  task_id: string;
  items: Item[];
  /** 该 streamTabId 创建时刻（提交任务时戳），用于'等待首字节'已耗时显示。 */
  createdAt?: number;
}

/**
 * 阶段状态（用于 data_leak / pentest 等 pipeline 的多智能体协作可视化）
 * - 数据源：SSE stage_start / stage_finished / stage_failed / status_completed / status_failed 帧
 * - 兜底：当 SSE 没推全 stages 时，按 KNOWN_PIPELINES 的预定义顺序填充 pending 占位
 * - 单域任务（domain=pentest 等）：用一个 stage 占位，跟'完整 pipeline'视觉一致
 */
type StageStatus = 'pending' | 'running' | 'completed' | 'failed';
interface StageState {
  stage: string;          // 原始 stage 名，如 'logaudit' / 'pentest' / 'verdict' / 'report'
  label: string;          // 中文显示
  status: StageStatus;
  startedAt?: number;
  finishedAt?: number;
  findingsCount?: number;
  error?: string;
}

/** 阶段名 → 中文显示 */
const STAGE_LABELS: Record<string, string> = {
  logaudit: '日志审计',
  pentest: '渗透测试',
  verdict: '威胁判定',
  tir: '威胁情报',
  report: '报告',
  intel: '分析',
  incident: '应急响应',
};

/** 已知 pipeline 的 stages 顺序（后端没推 stage_start 帧时按这个填充 pending 占位） */
const KNOWN_PIPELINES: Record<string, string[]> = {
  data_leak: ['logaudit', 'pentest', 'verdict', 'report'],
};

/**
 * 实时面板属性
 */
interface RealtimePanelProps {
  authToken?: string;        // 认证token
  autoConnect?: boolean;     // 是否自动连接
  maxMessages?: number;      // 每个任务最大消息数
  showTimestamp?: boolean;   // 是否显示时间戳
  onTaskClick?: (taskId: string) => void; // 任务点击回调
  onFindingClick?: (finding: Finding) => void; // 证据点击回调
  /**
   * 父组件透传的 chat/stream 帧（复用 chat/stream onFrame 的输出）。
   * 每项表示一个任务的一个帧。AisocDashboard.submitTask 调 chat/stream(pass_through=true)
   * 后会把 text / reasoning / tool_dispatch / tool_progress / tool_result 都 push 到这里，
   * RealtimePanel 负责把它们按 task_id 合并到 taskOutputs.messages，流式输出区立即可见。
   */
  streamItemsByTask?: Record<string, { items: Item[]; version: number; createdAt?: number }>;
}

/**
 * 等待首字节占位（优化 pass_through=true 模式下大脑首字节 36 秒的视觉空白）。
 * - Spinner + 文本提示
 * - 已耗时计时器（createdAt → now）
 * - 超过 60 秒附加安抚文案
 */
function WaitingPlaceholder({ createdAt }: { createdAt?: number }) {
  const [elapsedMs, setElapsedMs] = useState(0);
  useEffect(() => {
    const start = createdAt ?? Date.now();
    const tick = () => setElapsedMs(Math.max(0, Date.now() - start));
    tick();
    const id = setInterval(tick, 500);
    return () => clearInterval(id);
  }, [createdAt]);
  const secs = Math.floor(elapsedMs / 1000);
  const veryLongWait = secs >= 60;
  return (
    <div className="flex flex-col items-center justify-center h-full gap-3 text-zinc-500">
      <Loader2 className="h-6 w-6 animate-spin text-fuchsia-500" />
      <div className="text-sm">
        等待大脑响应（已等待 {secs}s）
      </div>
      <div className="text-[11px] text-zinc-400 max-w-xs text-center leading-snug">
        {veryLongWait
          ? '⏳ 透传模式首字节较慢（reasoning 模型推理中），最长约 1–2 分钟，请稍候'
          : '⏳ 首次响应通常 5–30 秒，复杂推理任务可能更久'}
      </div>
    </div>
  );
}

export function RealtimePanel({
  authToken: _authToken,
  autoConnect = true,
  maxMessages = 1000,
  showTimestamp: _showTimestamp = true,
  onTaskClick,
  onFindingClick: _onFindingClick,
  streamItemsByTask,
}: RealtimePanelProps) {
  const [isConnected, setIsConnected] = useState(false);
  const [connectionError, setConnectionError] = useState<string | null>(null);
  const [agentStatuses, setAgentStatuses] = useState<Record<string, AgentStatus>>({});
  const [taskOutputs, setTaskOutputs] = useState<Record<string, TaskOutput>>({});
  /** Pipeline 阶段进度（data_leak: logaudit → pentest → verdict → report） */
  const [stagesByTask, setStagesByTask] = useState<Record<string, StageState[]>>({});
  const [mainTab, setMainTab] = useState<string>('agents'); // 主Tab：agents/outputs
  // 已合并到 taskOutputs 的 version（避免父组件 prop 重复触发）
  const mergedVersionRef = useRef<Record<string, number>>({});
  const [activeTaskFilter, setActiveTaskFilter] = useState<string>('all'); // 任务过滤

  const eventSourceRef = useRef<EventSource | null>(null);
  const reconnectTimeoutRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  // 部件显示名称映射（大脑侧部件名为 'intel'）
  const domainDisplayNames: Record<string, string> = {
    brain: '大脑',
    pentest: '渗透测试',
    logaudit: '日志审计',
    intel: '威胁情报',
    threatintel: '威胁情报', // 兼容旧调用
    incident: '应急响应',
  };

  /**
   * 初始化部件状态
   */
  const initializeAgentStatus = useCallback((domain: string) => {
    if (!agentStatuses[domain]) {
      setAgentStatuses(prev => ({
        ...prev,
        [domain]: {
          domain,
          displayName: domainDisplayNames[domain] || domain,
          status: 'idle',
          activeTools: [],
          lastUpdate: new Date().toISOString(),
          busy: false,
        },
      }));
    }
  }, [agentStatuses]);

  /**
   * 更新Agent状态（文档 §4.8：10 种事件帧 {task_id, domain, event, payload}）
   */
  const updateAgentStatus = useCallback((event: StreamEvent) => {
    const { domain, task_id, event: eventName, payload } = event;

    if (!domain) return;

    initializeAgentStatus(domain);

    setAgentStatuses(prev => {
      const updated = { ...prev };
      const agent = { ...updated[domain] };

      agent.lastUpdate = new Date().toISOString();
      if (task_id) agent.currentTask = task_id;

      switch (eventName) {
        case 'task_created':
        case 'status_running':
          agent.status = 'running';
          break;
        case 'stage_start':
          agent.status = 'running';
          agent.currentPhase = typeof payload?.stage === 'string' ? payload.stage : 'unknown';
          break;
        case 'stage_finished':
          agent.status = 'running';
          agent.currentPhase = 'completed';
          break;
        case 'stage_failed':
          agent.status = 'error';
          agent.currentPhase = 'failed';
          break;
        case 'findings_stored':
          agent.status = 'running';
          if (payload?.tool) {
            const t = payload.tool as { name?: string } | string;
            const toolName = typeof t === 'string' ? t : t?.name;
            if (toolName) {
              const newTool: ToolStatus = {
                id: `${task_id}-${toolName}`,
                name: toolName,
                status: 'completed',
                startTime: new Date().toISOString(),
              };
              agent.activeTools = [...agent.activeTools.filter(x => x.id !== newTool.id), newTool];
            }
          }
          break;
        case 'verdict':
          agent.status = 'running';
          agent.currentPhase = 'verdict';
          break;
        case 'report_ready':
          agent.status = 'running';
          agent.currentPhase = 'report_ready';
          break;
        case 'status_completed':
          agent.status = 'idle';
          agent.currentPhase = 'completed';
          break;
        case 'status_failed':
          agent.status = 'error';
          agent.currentPhase = 'failed';
          break;
      }

      updated[domain] = agent;
      return updated;
    });
  }, [initializeAgentStatus]);

  /**
   * 添加任务输出（按新事件名转为 notice item，与 chat/stream 透传的 items 一起渲染在同一个 outputs 区）。
   * 设计：SSE 元事件（task_created/status_running/stage_start/...）本质是“系统提示”，
   * 转化为 Item(kind=notice) 后复用 chat Transcript 同款 notice 样式（黄/蓝框），与 chat/stream
   * 透传的 text/reasoning/tool 一同显示，流式输出区完全统一。
   */
  const addTaskOutput = useCallback((event: StreamEvent) => {
    if (!event.task_id) return;

    const { event: eventName, payload, domain, task_id } = event;

    // 元事件 → notice level 映射（之前是 info/error；现在跟 notice.kind 对齐）
    const levelByEvent: Record<string, 'info' | 'warn'> = {
      task_created: 'info',
      status_running: 'info',
      stage_start: 'info',
      stage_finished: 'info',
      stage_failed: 'warn',
      findings_stored: 'info',
      verdict: 'info',
      report_ready: 'info',
      status_completed: 'info',
      status_failed: 'warn',
    };

    // 安全读取 payload 字段
    const p = (payload ?? {}) as Record<string, unknown>;
    const stage = typeof p.stage === 'string' ? p.stage : null;
    const errMsg = typeof p.error === 'string' ? p.error : null;
    const count = typeof p.count === 'number' ? p.count : null;
    const verdict = typeof p.verdict === 'string' ? p.verdict : null;
    const confidence = typeof p.confidence === 'number' ? p.confidence : null;
    const findingsCount = typeof p.findings_count === 'number' ? p.findings_count : null;
    const currentStage = typeof p.current_stage === 'string' ? p.current_stage : null;
    const domainField = domain || p.domain as string || 'unknown';
    const shortId = task_id.length > 14 ? `${task_id.slice(0, 10)}…${task_id.slice(-4)}` : task_id;

    let content = '';
    switch (eventName) {
      case 'task_created':
        content = `🚀 任务创建（domain=${domainField}）\n   task_id=${shortId}\n   target=${typeof p.target === 'string' ? p.target : '—'}`;
        break;
      case 'status_running':
        content = `▶ 任务开始运行（部件 ${domainField} 已接单）`;
        break;
      case 'stage_start':
        content = `🔵 阶段开始：${stage ?? '未知'}\n   domain=${domainField} | task=${shortId}${findingsCount !== null ? ` | 已累计发现×${findingsCount}` : ''}`;
        break;
      case 'stage_finished':
        content = `✅ 阶段完成：${stage ?? '未知'}\n   domain=${domainField} | task=${shortId}${findingsCount !== null ? ` | 本阶段发现×${findingsCount}` : ''}`;
        break;
      case 'stage_failed':
        content = `❌ 阶段失败：${stage ?? '未知'}\n   domain=${domainField} | task=${shortId}\n   原因：${errMsg ?? '未知'}`;
        break;
      case 'findings_stored':
        content = `🧩 新发现入库（domain=${domainField}）\n   task=${shortId}\n   本批入库×${count ?? '?'}${findingsCount !== null ? ` | 累计发现×${findingsCount}` : ''}`;
        break;
      case 'verdict':
        content = `⚖️ 判定：${verdict ?? '未知'}${confidence !== null ? `（置信度 ${Math.round(confidence * 100)}%）` : ''}\n   task=${shortId}${currentStage ? ` | 当前阶段=${currentStage}` : ''}`;
        break;
      case 'report_ready':
        content = `📄 报告已就绪\n   task=${shortId}\n   提示：切到“详情”tab 查看完整报告`;
        break;
      case 'status_completed':
        content = `🏁 任务已完成\n   task=${shortId}\n   提示：切到“详情”tab 查看报告`;
        break;
      case 'status_failed':
        content = `💥 任务失败\n   task=${shortId}\n   原因：${errMsg ?? '未知'}`;
        break;
      default:
        content = `[${eventName}] task=${shortId}`;
    }

    setTaskOutputs(prev => {
      const updated = { ...prev };
      if (!updated[event.task_id!]) {
        updated[event.task_id!] = {
          task_id: event.task_id!,
          items: [],
          createdAt: Date.now(),
        };
      }

      const taskOutput = updated[event.task_id!];
      const noticeItem: Item = {
        kind: 'notice',
        id: `notice-sse-${task_id}-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
        level: levelByEvent[eventName] ?? 'info',
        text: content,
      };
      taskOutput.items.push(noticeItem);

      // 限制 items 数量（避免长任务推 event 过多撑爆 DOM）
      if (taskOutput.items.length > maxMessages) {
        taskOutput.items = taskOutput.items.slice(-maxMessages);
      }

      return updated;
    });
  }, [maxMessages]);

  /**
   * 同步维护 stagesByTask（pipeline 横道图数据源）
   * 必须在 handleRealtimeEvent 之前定义（避免 useCallback deps 的 TDZ）。
   * - stage_start：把对应 stage 状态置为 running、记录 startedAt
   * - stage_finished：把对应 stage 状态置为 completed、记录 finishedAt + findingsCount
   * - stage_failed：状态置为 failed、记录 error
   * - status_completed：把剩下未结束的 stage 全置为 completed
   * - status_failed：把当前 running 的 stage 置为 failed
   * - task_created (domain != 'all' 即单域任务)：预填 1 个 stage 占位（domain 本身）
   */
  const upsertStage = useCallback((event: StreamEvent) => {
    const { event: eventName, payload, domain, task_id } = event;
    if (!task_id) return;
    const p = (payload ?? {}) as Record<string, unknown>;
    const stageName = typeof p.stage === 'string' ? p.stage : null;
    const findingsCount = typeof p.findings_count === 'number' ? p.findings_count : undefined;
    const errMsg = typeof p.error === 'string' ? p.error : null;

    setStagesByTask(prev => {
      const cur = prev[task_id] ? [...prev[task_id]] : [];

      // 工具函数：根据 stage 名找现有下标
      const findIdx = (name: string) => cur.findIndex(s => s.stage === name);

      // 工具函数：新建 stage
      const newStage = (name: string, status: StageStatus): StageState => ({
        stage: name,
        label: STAGE_LABELS[name] ?? name,
        status,
        startedAt: status === 'running' ? Date.now() : undefined,
      });

      switch (eventName) {
        case 'task_created': {
          // 单域任务（domain != 'all'）：预填该 domain 作为唯一 stage 占位
          // pipeline 任务（domain='all'）：等 stage_start 推再补，不在这里瞎填
          if (domain && domain !== 'all' && KNOWN_PIPELINES[domain] === undefined && findIdx(domain) < 0) {
            cur.push(newStage(domain, 'pending'));
          }
          break;
        }
        case 'stage_start': {
          if (!stageName) break;
          const idx = findIdx(stageName);
          if (idx >= 0) {
            cur[idx] = { ...cur[idx], status: 'running', startedAt: Date.now() };
          } else {
            cur.push(newStage(stageName, 'running'));
          }
          break;
        }
        case 'stage_finished': {
          if (!stageName) break;
          const idx = findIdx(stageName);
          if (idx >= 0) {
            cur[idx] = {
              ...cur[idx],
              status: 'completed',
              finishedAt: Date.now(),
              findingsCount: findingsCount ?? cur[idx].findingsCount,
            };
          } else {
            cur.push({
              ...newStage(stageName, 'completed'),
              finishedAt: Date.now(),
              findingsCount,
            });
          }
          break;
        }
        case 'stage_failed': {
          if (!stageName) break;
          const idx = findIdx(stageName);
          if (idx >= 0) {
            cur[idx] = { ...cur[idx], status: 'failed', finishedAt: Date.now(), error: errMsg ?? undefined };
          } else {
            cur.push({ ...newStage(stageName, 'failed'), finishedAt: Date.now(), error: errMsg ?? undefined });
          }
          break;
        }
        case 'status_completed': {
          // 整体任务完成 → 把所有未完成的 stage 都标记 completed
          for (let i = 0; i < cur.length; i++) {
            if (cur[i].status === 'running' || cur[i].status === 'pending') {
              cur[i] = { ...cur[i], status: 'completed', finishedAt: Date.now() };
            }
          }
          break;
        }
        case 'status_failed': {
          // 整体任务失败 → 把当前 running 的 stage 标记 failed
          for (let i = 0; i < cur.length; i++) {
            if (cur[i].status === 'running') {
              cur[i] = { ...cur[i], status: 'failed', finishedAt: Date.now(), error: errMsg ?? '未知错误' };
            }
          }
          break;
        }
      }

      // 没有任何变化：保持原 state（避免不必要的 re-render）
      if (cur.length === (prev[task_id]?.length ?? 0)) {
        let same = true;
        for (let i = 0; i < cur.length; i++) {
          if (cur[i].status !== prev[task_id][i].status || cur[i].findingsCount !== prev[task_id][i].findingsCount) {
            same = false;
            break;
          }
        }
        if (same) return prev;
      }

      return { ...prev, [task_id]: cur };
    });
  }, []);

  /**
   * 处理实时事件
   */
  const handleRealtimeEvent = useCallback((event: StreamEvent) => {
    console.log('Realtime event received:', event);

    // 更新Agent状态
    updateAgentStatus(event);

    // 添加任务输出
    addTaskOutput(event);

    // 同步维护 stagesByTask（横道图数据源）
    upsertStage(event);
  }, [updateAgentStatus, addTaskOutput, upsertStage]);

  /**
   * 连接SSE流
   */
  const connect = useCallback(() => {
    if (eventSourceRef.current) {
      eventSourceRef.current.close();
    }

    try {
      const eventSource = aisocApi.connectRealtimeStream(
        handleRealtimeEvent,
        (error) => {
          console.error('SSE connection error:', error);
          setConnectionError('连接中断，正在重连...');
          setIsConnected(false);

          // 自动重连
          if (reconnectTimeoutRef.current) {
            clearTimeout(reconnectTimeoutRef.current);
          }
          reconnectTimeoutRef.current = setTimeout(() => {
            setConnectionError(null);
            connect();
          }, 5000);
        }
      );

      eventSourceRef.current = eventSource;
      setIsConnected(true);
      setConnectionError(null);
    } catch (error) {
      console.error('Failed to connect to SSE stream:', error);
      setConnectionError('连接失败');
      setIsConnected(false);
    }
  }, [handleRealtimeEvent]);

  /**
   * 断开连接
   */
  const disconnect = useCallback(() => {
    if (eventSourceRef.current) {
      eventSourceRef.current.close();
      eventSourceRef.current = null;
    }
    if (reconnectTimeoutRef.current) {
      clearTimeout(reconnectTimeoutRef.current);
      reconnectTimeoutRef.current = null;
    }
    setIsConnected(false);
  }, []);

  /**
   * Agent 状态墙忙闲轮询（文档 §4.1c GET /api/agents/status）
   * 用 busy/enabled 覆盖各 domain 的 busy 与启用状态，SSE 事件继续驱动 running/error 等
   */
  const refreshAgentsStatus = useCallback(async () => {
    try {
      const data = await aisocApi.getAgentsStatus();
      if (!data?.parts?.length) return;
      setAgentStatuses(prev => {
        const next = { ...prev };
        for (const p of data.parts) {
          const d = p.domain;
          if (!next[d]) {
            next[d] = {
              domain: d,
              displayName: domainDisplayNames[d] || d,
              status: 'idle',
              activeTools: [],
              lastUpdate: new Date().toISOString(),
              busy: !!p.busy,
              enabled: p.enabled,
            };
          } else {
            next[d] = { ...next[d], busy: !!p.busy, enabled: p.enabled, lastUpdate: new Date().toISOString() };
          }
        }
        return next;
      });
    } catch {
      // 大脑离线时静默失败，由 SSE 重连与全局离线横幅提示
    }
  }, []);

  useEffect(() => {
    refreshAgentsStatus();
    const id = setInterval(refreshAgentsStatus, 5000);
    return () => clearInterval(id);
  }, [refreshAgentsStatus]);

  /**
   * 合并父组件透传的 chat/stream Item[]（修复：SSE 实时流不推 reasonix 流式帧，
   * AisocDashboard.submitTask 调 webApiProxy.AisocSubmitForTab 走与聊天同源的 onFrame → emitEvent，
   * 拿到 text/reasoning/tool_dispatch/tool_result 后转成 Item[] 推到这里，与 SSE 元事件一起显示）。
   * 按 version 去重，避免父组件重复触发同一帧被重复渲染。
   */
  useEffect(() => {
    if (!streamItemsByTask) return;
    setTaskOutputs(prev => {
      const updated = { ...prev };
      let changed = false;
      for (const [taskId, payload] of Object.entries(streamItemsByTask)) {
        if (mergedVersionRef.current[taskId] === payload.version) continue;
        mergedVersionRef.current[taskId] = payload.version;
        const trimmed = payload.items.length > maxMessages ? payload.items.slice(-maxMessages) : payload.items;
        const prevOutput = updated[taskId];
        updated[taskId] = {
          task_id: taskId,
          items: trimmed,
          createdAt: payload.createdAt ?? prevOutput?.createdAt,
        };
        changed = true;
      }
      return changed ? updated : prev;
    });
  }, [streamItemsByTask, maxMessages]);

  /**
   * 清理定时器和连接
   */
  useEffect(() => {
    if (autoConnect) {
      connect();
    }

    return () => {
      disconnect();
    };
  }, [autoConnect, connect, disconnect]);

  /**
   * 获取工具状态图标
   */
  const getToolStatusIcon = (status: ToolStatus['status']) => {
    switch (status) {
      case 'running':
        return <Play className="h-3 w-3 text-blue-500" />;
      case 'completed':
        return <CheckCircle2 className="h-3 w-3 text-green-500" />;
      case 'failed':
        return <AlertCircle className="h-3 w-3 text-red-500" />;
      case 'pending_approval':
        return <Clock className="h-3 w-3 text-yellow-500" />;
    }
  };

  /**
   * 获取Agent状态颜色
   */
  const getAgentStatusColor = (status: AgentStatus['status']) => {
    switch (status) {
      case 'idle':
        return 'bg-gray-100 border-gray-300';
      case 'running':
        return 'bg-blue-50 border-blue-300';
      case 'error':
        return 'bg-red-50 border-red-300';
      case 'waiting_approval':
        return 'bg-yellow-50 border-yellow-300';
    }
  };

  /**
   * 渲染Agent状态卡片
   */
  const renderAgentCard = (domain: string, agent: AgentStatus) => (
    <div
      key={domain}
      className={`mb-3 border-l-4 ${getAgentStatusColor(agent.status)} bg-white rounded-lg shadow-sm hover:shadow-md transition-all p-4`}
    >
      <div className="flex items-center justify-between mb-3">
        <div className="text-lg font-semibold">{agent.displayName}</div>
        <div className={`px-2 py-1 rounded text-xs font-medium ${
          agent.status === 'running' ? 'bg-blue-100 text-blue-800' :
          agent.status === 'error' ? 'bg-red-100 text-red-800' :
          agent.status === 'waiting_approval' ? 'bg-yellow-100 text-yellow-800' :
          'bg-gray-100 text-gray-800'
        }`}>
          {agent.status}
        </div>
      </div>
      {typeof agent.busy === 'boolean' && (
        <div className={`text-xs mb-2 ${agent.busy ? 'text-blue-600' : 'text-gray-500'}`}>
          {agent.busy ? '● 忙（有任务排队执行）' : '○ 空闲'}
          {typeof agent.enabled === 'boolean' && !agent.enabled && (
            <span className="ml-2 text-red-600">（部件未启用）</span>
          )}
        </div>
      )}
      {agent.currentTask && (
        <div className="text-sm text-gray-600 mb-2">
          任务: {agent.currentTask}
          {agent.currentPhase && ` | 阶段: ${agent.currentPhase}`}
        </div>
      )}
      <div className="mt-3">
        {agent.activeTools.length > 0 ? (
          <div className="space-y-2">
            {agent.activeTools.map(tool => (
              <div key={tool.id} className="flex items-center justify-between text-sm py-1">
                <div className="flex items-center gap-2">
                  {getToolStatusIcon(tool.status)}
                  <span className="font-medium">{tool.name}</span>
                  {tool.duration && <span className="text-gray-500">({tool.duration}ms)</span>}
                </div>
                {tool.error && (
                  <div className="px-2 py-1 bg-red-100 text-red-800 rounded text-xs">
                    {tool.error}
                  </div>
                )}
              </div>
            ))}
          </div>
        ) : (
          <div className="text-sm text-gray-500 italic">无活跃工具</div>
        )}
      </div>
    </div>
  );

  /**
   * 渲染 Pipeline 横道图（多智能体协作进度的核心可视化）
   * 输入：stagesByTask[taskId] 数组（已按出现顺序）
   * 输出：横排的 stage 节点 + 连接箭头
   *   [✓ 日志审计] → [● 渗透测试 0:23] → [○ 判定] → [○ 报告]
   */
  const renderStagePipeline = (stages: StageState[]) => {
    if (!stages || stages.length === 0) return null;
    return (
      <div className="mb-2 flex flex-wrap items-center gap-1 rounded-md border border-zinc-200 bg-zinc-50 px-3 py-2">
        <span className="text-[10px] uppercase tracking-wider text-zinc-500 mr-1">pipeline</span>
        {stages.map((s, idx) => {
          const meta = getStageMeta(s.status);
          const Icon = meta.icon;
          const elapsedSec = s.startedAt && !s.finishedAt
            ? Math.floor((Date.now() - s.startedAt) / 1000)
            : null;
          return (
            <div key={`${s.stage}-${idx}`} className="flex items-center">
              <div
                className={`inline-flex items-center gap-1 rounded px-2 py-0.5 text-xs ${meta.cls}`}
                title={
                  s.error
                    ? `失败：${s.error}`
                    : elapsedSec !== null
                      ? `运行中（已耗时 ${elapsedSec}s）`
                      : `${s.label}`
                }
              >
                <Icon className="h-3 w-3" />
                <span>{s.label}</span>
                {typeof s.findingsCount === 'number' && s.findingsCount > 0 && (
                  <span className="ml-0.5 text-[10px] opacity-80">×{s.findingsCount}</span>
                )}
                {elapsedSec !== null && (
                  <span className="ml-0.5 text-[10px] opacity-80">{elapsedSec}s</span>
                )}
              </div>
              {idx < stages.length - 1 && (
                <span className="mx-1 text-zinc-400">→</span>
              )}
            </div>
          );
        })}
      </div>
    );
  };

  /**
   * 阶段状态 → 颜色 + 图标
   */
  const getStageMeta = (status: StageStatus): { cls: string; icon: typeof CheckCircle2 } => {
    switch (status) {
      case 'pending':
        return { cls: 'bg-zinc-100 text-zinc-600 border border-zinc-200', icon: Clock };
      case 'running':
        return { cls: 'bg-blue-50 text-blue-700 border border-blue-200', icon: Loader2 };
      case 'completed':
        return { cls: 'bg-emerald-50 text-emerald-700 border border-emerald-200', icon: CheckCircle2 };
      case 'failed':
        return { cls: 'bg-red-50 text-red-700 border border-red-200', icon: AlertCircle };
    }
  };

  /**
   * 渲染任务输出（复用 chat Transcript 同款 AssistantMessage + ToolCard，与聊天视觉一致）
   */
  const renderTaskOutput = (taskId: string, output: TaskOutput) => (
    <div key={taskId} className="mb-4">
      <div className="flex items-center justify-between mb-2">
        <h4 className="font-medium">任务 {taskId}</h4>
        {onTaskClick && (
          <button
            className="text-sm px-3 py-1 bg-blue-50 text-blue-700 rounded hover:bg-blue-100 transition-colors"
            onClick={() => onTaskClick(taskId)}
          >
            <div className="flex items-center gap-1">
              <Eye className="h-3 w-3" />
              查看详情
            </div>
          </button>
        )}
      </div>
      {/* Pipeline 横道图（多智能体协作进度，data_leak 等 pipeline 任务才有多 stage；单域任务只有 1 个） */}
      {renderStagePipeline(stagesByTask[taskId])}
      <div className="h-[28rem] w-full rounded border overflow-y-auto p-3 space-y-3 bg-white">
        {output.items.length === 0 ? (
          <WaitingPlaceholder createdAt={output.createdAt} />
        ) : null}
        {output.items.map((item, index) => {
          if (item.kind === 'assistant') {
            return <AssistantMessage key={item.id || index} item={item} creationMode={false} />;
          }
          if (item.kind === 'tool') {
            return <ToolCard key={item.id || index} item={item} />;
          }
          if (item.kind === 'phase') {
            return (
              <div key={item.id || index} className="text-xs text-gray-500 italic border-l-2 border-gray-300 pl-2">
                {item.text}
              </div>
            );
          }
          if (item.kind === 'notice') {
            return (
              <div
                key={item.id || index}
                className={`text-sm rounded px-3 py-2 ${
                  item.level === 'warn' ? 'bg-yellow-50 text-yellow-800 border border-yellow-200' : 'bg-blue-50 text-blue-800 border border-blue-200'
                }`}
              >
                {item.text}
              </div>
            );
          }
          return null;
        })}
      </div>
    </div>
  );

  const taskList = Object.keys(taskOutputs);
  const activeTaskOutputs = activeTaskFilter === 'all'
    ? taskOutputs
    : Object.fromEntries(
        Object.entries(taskOutputs).filter(([taskId]) => taskId === activeTaskFilter)
      );

  return (
    <div className="flex flex-col h-full bg-gray-50">
      {/* 控制栏 */}
      <div className="flex items-center justify-between p-4 border-b bg-white">
        <h2 className="text-xl font-bold flex items-center gap-2">
          <Activity className="h-5 w-5" />
          实时监控面板
        </h2>
        <div className="flex items-center gap-2">
          <div className="flex items-center gap-1">
            <div
              className={`w-2 h-2 rounded-full ${
                isConnected ? 'bg-green-500' : 'bg-red-500'
              }`}
            />
            <span className="text-sm text-gray-600">
              {isConnected ? '已连接' : '未连接'}
            </span>
          </div>
          {isConnected ? (
            <button
              className="text-sm px-3 py-1 border border-gray-300 rounded hover:bg-gray-50 transition-colors"
              onClick={disconnect}
            >
              <div className="flex items-center gap-1">
                <Pause className="h-4 w-4" />
                断开
              </div>
            </button>
          ) : (
            <button
              className="text-sm px-3 py-1 border border-gray-300 rounded hover:bg-gray-50 transition-colors"
              onClick={connect}
            >
              <div className="flex items-center gap-1">
                <RefreshCw className="h-4 w-4" />
                连接
              </div>
            </button>
          )}
        </div>
      </div>

      {connectionError && (
        <div className="bg-yellow-50 border border-yellow-200 p-3 m-4 rounded">
          <div className="flex items-center gap-2 text-yellow-800">
            <AlertCircle className="h-4 w-4" />
            <span>{connectionError}</span>
          </div>
        </div>
      )}

      {/* 主要内容区域 */}
      <div className="flex-1 overflow-hidden flex flex-col">
        {/* 简单的Tab切换 */}
        <div className="border-b bg-white">
          <div className="flex">
            <button
              className={`px-4 py-2 font-medium text-sm border-b-2 transition-colors ${
                mainTab === 'agents'
                  ? 'border-blue-500 text-blue-600'
                  : 'border-transparent text-gray-500 hover:text-gray-700'
              }`}
              onClick={() => setMainTab('agents')}
            >
              Agent状态墙
            </button>
            <button
              className={`px-4 py-2 font-medium text-sm border-b-2 transition-colors ${
                mainTab === 'outputs'
                  ? 'border-blue-500 text-blue-600'
                  : 'border-transparent text-gray-500 hover:text-gray-700'
              }`}
              onClick={() => setMainTab('outputs')}
            >
              流式输出区
            </button>
          </div>
        </div>

        <div className="flex-1 overflow-auto p-4">
          {mainTab === 'agents' ? (
            Object.keys(agentStatuses).length > 0 ? (
              Object.entries(agentStatuses).map(([domain, agent]) =>
                renderAgentCard(domain, agent)
              )
            ) : (
              <div className="text-center text-gray-500 py-8">
                暂无Agent活动
              </div>
            )
          ) : (
            taskList.length > 0 ? (
              <>
                {taskList.length > 1 && (
                  <div className="mb-4">
                    <div className="flex flex-wrap gap-2">
                      <button
                        className={`px-3 py-1 text-sm rounded transition-colors ${
                          activeTaskFilter === 'all'
                            ? 'bg-blue-500 text-white'
                            : 'bg-gray-200 text-gray-700 hover:bg-gray-300'
                        }`}
                        onClick={() => setActiveTaskFilter('all')}
                      >
                        全部任务
                      </button>
                      {taskList.map(taskId => (
                        <button
                          key={taskId}
                          className={`px-3 py-1 text-sm rounded transition-colors ${
                            activeTaskFilter === taskId
                              ? 'bg-blue-500 text-white'
                              : 'bg-gray-200 text-gray-700 hover:bg-gray-300'
                          }`}
                          onClick={() => setActiveTaskFilter(taskId)}
                        >
                          {taskId}
                        </button>
                      ))}
                    </div>
                  </div>
                )}
                {Object.entries(activeTaskOutputs).map(([taskId, output]) =>
                  renderTaskOutput(taskId, output)
                )}
              </>
            ) : (
              <div className="text-center text-gray-500 py-8">
                暂无任务输出
              </div>
            )
          )}
        </div>
      </div>
    </div>
  );
}

export default RealtimePanel;