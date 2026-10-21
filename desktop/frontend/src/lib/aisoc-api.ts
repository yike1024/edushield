/**
 * AiSOC API Client
 * 严格按照 docs/frontend-api.md（大脑 FastAPI 6657）实现的前端客户端。
 * 前端呈现什么 = 大脑有什么。
 */

// 基础URL配置 - 直连大脑 FastAPI（6657）
// frontend-api.md 明确：CORS 已全开，前端任意端口直连即可。
// Wails 生产环境（8082）没有 Vite dev 代理，相对路径 /aisoc-brain/api 会 404，
// 导致任务无法发送；故默认直连 127.0.0.1:6657。
// 仍可用 VITE_BRAIN_API_URL 覆盖（如部署到 cpolar/nginx 暴露的对外地址）。
// 注意：import.meta.env 仅在 Vite 构建时注入；tsx/node 测试环境下为 undefined，
// 因此用可选链，避免 TypeError，默认回退直连地址。
import type { MockWafCommand } from './mockWafCommand';

const BRAIN_API_BASE = import.meta.env?.VITE_BRAIN_API_URL || 'http://127.0.0.1:6657/api';

/** 域标识（文档 §4.1：logaudit / pentest / intel；前端保留四部件展示） */
// 注：大脑侧部件名为 'intel'（端口 8789），历史前端误称为 'threatintel'。
// 这里保留 'threatintel' 兼容条目（同值映射到 /aisoc-intel），避免外部脚本/缓存破口。
export type TaskDomain = 'pentest' | 'logaudit' | 'intel' | 'threatintel' | 'incident';
/** 任务状态枚举（文档 §4.2） */
export type TaskStatus = 'pending' | 'running' | 'approval' | 'completed' | 'failed' | 'cancelled' | 'archived';
/** 判定枚举（文档 §4.2） */
export type Verdict = 'real_threat' | 'false_positive' | 'pending_review';
/** 严重级别枚举（文档 §4.3） */
export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';
/** 阶段枚举（文档 §4.2） */
export type StageName = 'logaudit' | 'pentest' | 'verdict' | 'tir' | 'report';

/**
 * 下发任务请求体（文档 §4.1）
 */
export interface CreateTaskInput {
  task: string;                    // 自然语言任务描述（必填）
  domain: TaskDomain;              // logaudit / pentest（必填）
  target: string;                  // 目标，必须在授权白名单内，否则 403（必填）
  pipeline?: string;               // 目前支持 data_leak
  params?: Record<string, unknown>;// 透传给部件的参数
  tools?: string[];                // 工具白名单，缺省 = 部件全部
  /**
   * 前端会话 ID（可选）。大脑侧按 (session_id, domain) 缓存“已开过新会话”标记：
   *   - 首次出现 (session_id, domain) 组合 → 部件调 /new（清空上下文）
   *   - 命中缓存 → 复用部件会话（保留上下文）
   *   - 省略 session_id → 退化到当前行为（每次任务开新会话）
   * 推荐传值：前端 tabId（如 `aisoc-task-1762…`）或同会话内生成的稳定 UUID。
   */
  session_id?: string;
}

/** 兼容别名：UI 曾用 TaskMessage 名，现在指下发任务请求 */
export type TaskMessage = CreateTaskInput;

/**
 * 证据（Finding）— 文档 §4.3
 */
export interface Finding {
  id: string;                // F-<task_id>-<seq>
  task_id: string;           // 来源任务
  domain: string;            // 产出部件
  target: string;            // 目标
  tool: string;              // 产出工具名
  severity: Severity;
  cve?: string | null;
  cwe?: string | null;
  cvss?: number | null;
  title: string;             // 人读摘要
  description: string;       // 详情
  evidence: string;          // 支撑证据片段
  remediation?: string;      // 修复建议
  confidence: number;        // 0~1
  mitre?: string[];
  ts: string;                // ISO8601 UTC（文档字段名）
  timestamp?: string;        // 兼容别名
  project_id?: string | null; // 所属评估项目（17 号方案 B2，未归类为 null）
}

/**
 * 阶段进度（文档 §4.2 stages 数组元素）
 */
export interface TaskStage {
  id: number;
  task_id: string;
  stage: StageName;
  status: TaskStatus;
  started_at?: string;
  finished_at?: string;
  findings_count: number;
  error?: string;
}

/**
 * 思维链条目（文档 §4.2 thought_chain）
 */
export interface ThoughtChainEntry {
  id: number;
  task_id: string;
  ts: string;
  actor: string;             // 如 "brain"
  action: string;            // 如 "task_created" / "status_completed"
  detail?: Record<string, unknown>;
}

/**
 * 任务列表项（文档 §4.1b）
 */
export interface TaskInfo {
  id: string;                // 任务ID
  task_id?: string;          // 兼容别名（= id）
  domain: TaskDomain;
  target: string;
  status: TaskStatus;
  verdict?: Verdict;
  confidence?: number;
  created_at: string;
  updated_at: string;
  findings_count?: number;
  current_stage?: string;
  stages?: TaskStage[];
  project_id?: string | null; // 所属评估项目（17 号方案 B2，未归类为 null）
}

/**
 * 任务详情（文档 §4.2）
 */
export interface TaskDetail extends TaskInfo {
  error?: string;
  thought_chain?: ThoughtChainEntry[];
}

/**
 * 报告（文档 §4.4）— report 为 Markdown 字符串
 */
export interface ReportDoc {
  task_id: string;
  report: string;            // Markdown 字符串
}

/**
 * 授权白名单视图（GET /api/whitelist 返回值）
 * - enabled=false：白名单关闭，后端全部放行（仅运维临时使用）
 * - targets：精确字符串列表（单 IP / 域名 / 带 scheme 的 URL，不支持 CIDR）
 */
export interface WhitelistView {
  enabled: boolean;
  targets: string[];
}

/**
 * 部件注册表项（文档 §4.6）— token 脱敏，前端不展示
 */
export interface RegistryPart {
  domain: TaskDomain;
  host: string;
  port: number;
  token?: string;            // 仅标记存在，绝不在 UI 渲染
  auth?: string;
  enabled: boolean;
}

/**
 * Agent 忙闲状态（文档 §4.1c 状态墙）
 */
export interface AgentStatusItem {
  domain: TaskDomain;
  host?: string;
  port?: number;
  auth?: string;
  enabled?: boolean;
  busy: boolean;
}

/** 各 Agent 忙闲状态（文档 §4.1c） */
export interface AgentsStatus {
  brain: { status: string; service: string };
  parts: AgentStatusItem[];
  /** 各 REST 服务（应急响应 TIR 等）的端口与在线状态 */
  services?: Record<string, { name?: string; port?: number; status?: string }>;
}

/**
 * 单条告警（后端 GET /api/data/alarms 返回结构）。
 *
 * 字段来源：当前 6657 大脑对接 XDR（深信服 aES / 360 XDR / 奇安信等），
 * 不同 source 的字段可能略有差异；下面是已知完整字段。
 */
export interface Alarm {
  id?: string;
  source?: string;                  // xdr / siem / edr / waf …
  severity: Severity;
  severity_score?: number;          // 0-100 综合评分
  verdict_hint?: string;            // AI 研判：real_threat / false_positive / pending_review
  source_ip?: string[];             // 攻击方（多 IP）
  dest_ip?: string[];               // 受害方
  src_port?: number[];
  dst_port?: number[];
  direction?: number;               // 流量方向
  protocol?: string;                // http / tcp / dns …
  threat_class?: number;            // 威胁大类编号（前端预案匹配 key 之一）
  threat_type?: number;             // 威胁子类编号
  threat_sub_type?: number;
  rule_id?: string;                 // XDR 规则 ID（前端预案匹配 key 之一）
  engine?: string[];                // 触发引擎（Alpha / Beta / 360 / Sangfor …）
  deal_status?: number;             // 0=未处置 1=处置中 2=已处置 3=已忽略
  title?: string;
  description?: string;
  analysis?: string;                // AI 研判全文（可能是 JSON 字符串）
  url?: string;
  host?: string;
  user_agent?: string;
  first_time?: number;              // unix seconds
  last_time?: number;               // unix seconds
  occur_time?: number;
  raw?: Record<string, unknown>;    // 原始 payload，调试用
  // 兼容老字段（深信服 / XDR 不同源可能用 src/dst_ip 而非 source/dest_ip）
  src_ip?: string;
  dst_ip?: string;
  rule?: string;
  ts?: string;
  [key: string]: unknown;
}

/** 告警统计（文档 §4.7） */
export interface AlarmsSummary {
  total: number;
  by_severity: Record<string, number>;
  by_verdict_hint?: Record<string, number>;
}

// ==================== 应急响应（TIR，见 tir-frontend.md）====================
// 说明：只有当任务判定为 real_threat 时大脑才会推 8090 并落库，
// 因此三个列表端点返回空数组是正常态（文档 §2）。

/** 告警级别：严格三档（文档 §4.1） */
export type TirLevel = 'high' | 'medium' | 'low';

/** 告警状态（文档 §4.1） */
export type TirAlertStatus = 'new' | 'notified' | 'acknowledged' | 'responded' | 'closed';

/** 告警 payload 的已知字段（结构化展示时用；display_md 已可直接渲染） */
export interface TirAlertPayload {
  alert_id?: string;
  title?: string;
  level?: string;
  attack_type?: string;
  mitre_technique?: string;
  confidence?: number;
  source_ip?: string;
  target?: string;
  summary?: string;
  evidence?: string;
  recommended_action?: string;
  reasoning?: string;
  verdict?: string;               // true_positive / false_positive / benign / uncertain
  status?: string;
  created_at?: string;
  notified_at?: string;
  [key: string]: unknown;
}

/** 单条威胁告警（GET /api/tir/alerts） */
export interface TirAlert {
  alert_id: string;
  task_id: string;
  event_ref?: string;
  level: TirLevel;
  status: TirAlertStatus;
  display_md: string;             // 8090 生成的告警 Markdown，直接渲染
  created_at?: string;
  payload?: TirAlertPayload;
}

/** 处置预案单步（文档 §4.2 payload.steps[]） */
export interface TirPlaybookStep {
  seq: number;
  phase: string;
  action: string;
  expected_command?: string;      // 参考命令文本，仅展示，禁止执行
  risk_level?: TirLevel;
  requires_approval?: boolean;
  rationale?: string;
  status?: 'pending' | 'approved' | 'rejected' | 'simulated' | 'completed';
  simulated_result?: string | null;
  [key: string]: unknown;
}

/** 预案 payload（文档 §4.2） */
export interface TirPlaybookPayload {
  playbook_id?: string;
  level?: string;
  objective?: string;
  mode?: string;
  summary?: string;
  confidence?: number;
  mitre?: string[];
  steps?: TirPlaybookStep[];
  created_at?: string;
  [key: string]: unknown;
}

/** 处置预案（GET /api/tir/playbooks） */
export interface TirPlaybook {
  playbook_id: string;
  alert_id: string;
  task_id: string;
  mode: 'suggestion' | 'simulation';
  display_md: string;
  created_at?: string;
  payload?: TirPlaybookPayload;
}

/** 应急响应报告（GET /api/tir/reports，审批后产生） */
export interface TirReport {
  report_id: string;
  task_id: string;
  playbook_id?: string;
  alert_id?: string;
  decision?: string;              // approve / reject
  report_md: string;
  created_at?: string;
  payload?: Record<string, unknown>;
}

/** 审批响应（POST /api/approve，文档 §4.4） */
export interface TirApproveResponse {
  task_id: string;
  action: string;
  decision: string;
  status: 'responded' | 'recorded';   // responded=已产出报告；recorded=无预案仅记账
  playbook_id?: string;
  report_id?: string;
  report_md?: string;
}

/** 模拟 WAF 适配路由响应（POST /mock/waf/block，8788 侧，T2-2） */
export interface MockWafBlockResponse {
  ok: boolean;
  /** 恒为 true：本路由是纯模拟适配层，不触真实设备 */
  simulated: boolean;
  receipt_id: string;
  ts: string;
  /** 回执文案（可选） */
  message?: string;
  [key: string]: unknown;
}

/**
 * 实时事件流（文档 §4.8 SSE）— 每帧 data: {task_id, domain, event, payload}
 */
export type StreamEventName =
  | 'task_created' | 'status_running' | 'stage_start' | 'stage_finished'
  | 'stage_failed' | 'findings_stored' | 'verdict' | 'report_ready'
  | 'status_completed' | 'status_failed';

export interface StreamEvent {
  task_id: string;
  domain: string;
  event: StreamEventName;
  payload: Record<string, unknown>;
}

/**
 * chat/stream 接力流全帧类型
 *
 * - 默认模式（pass_through=false）：07 协议 9 种简化帧，参考 aisoc-docs/07-chat-stream-adaptive-relay.md §5.1
 * - 透传模式（pass_through=true）：reasonix 原样事件 9 种新 kind，参考 aisoc-docs/10-chat-stream-原模原样透传.md §3
 *
 * 大脑侧 /api/chat/stream 在识别为任务意图后会持续接力部件的思考 / 工具调用 / 工具结果 /
 * 最终回答帧，前端 chatStream 原来只解 delta；后续 onFrame 回调全帧派发，
 * 旧调用方（只读 onDelta）继续工作。
 *
 * 注意：tool_call / tool_result 的 tool 字段保留为 string（dict/string 兼容逻辑在 flush 内完成），
 * 透传模式新增 tool_dispatch / tool_progress 两个独立 kind（保留 tool 为原始 dict）。
 * 实证补充（2026-09-02）：reasonix 还会输出顶层字段 `kind: "stream_error"` 和 `kind: "error"`
 * 这类错误帧（reasonix 错误帧分类不统一），前端统一归为 `stream_error` kind 上报。
 */
export type ChatStreamFrame =
  // === 07 协议简化模式（默认 pass_through=false）===
  | { kind: 'delta';          delta: string; task_id?: string }
  | { kind: 'thinking';       thinking: string; task_id?: string }
  | { kind: 'tool_call';      tool: string; args: unknown; task_id?: string }
  | { kind: 'tool_result';    tool: string; output: string; exit_code?: number; partial?: boolean; task_id?: string; toolId?: string; args?: unknown }
  | { kind: 'stage_start';    stage: string; task_id?: string }
  | { kind: 'stage_finished'; stage: string; ok: boolean; task_id?: string }
  | { kind: 'task_created';   task_id: string; domain: string }
  | { kind: 'answer';         text: string; task_id?: string }
  | { kind: 'report_ready';   task_id: string; report_url: string }
  // === 10 协议透传模式新增（pass_through=true，reasonix 原样事件）===
  | { kind: 'turn_started';           task_id?: string }
  | { kind: 'memory_compiler_stats';  memoryCompiler: Record<string, unknown>; task_id?: string }
  | { kind: 'reasoning';              text: string; task_id?: string }
  | { kind: 'text';                   text: string; task_id?: string }
  | { kind: 'tool_dispatch';          tool: Record<string, unknown>; task_id?: string }
  | { kind: 'tool_progress';          tool: Record<string, unknown>; output: string; partial: true; task_id?: string }
  | { kind: 'message';                text: string; reasoning?: string; task_id?: string }
  | { kind: 'usage';                  usage: Record<string, unknown>; task_id?: string }
  | { kind: 'turn_done';              task_id?: string }
  // === 16 号方案 B3 新增：记忆/会话绑定帧（登录用户对话，SSE 首条 delta 之前下发）===
  // 17 号方案：conversation_bound 增补可选 projectId（会话被绑定到评估项目时回传）
  | { kind: 'conversation_bound';     conversationId: string; projectId?: string; task_id?: string }
  | { kind: 'memory_retrieved';       entries: MemoryRetrievedEntry[]; injected: boolean; task_id?: string }
  // === 实证补充的 reasonix 错误帧（10 协议未列入，实际 SSE 会出现）===
  | { kind: 'stream_error';           err: string; task_id?: string };

/** memory_retrieved 帧条目（后端 /api/chat/stream B3 帧契约，2026-10-09 抓流实证） */
export interface MemoryRetrievedEntry {
  id: string;
  content: string;
  type?: string;
  importance?: number;
  matchedBy?: string;
}

/** 服务端记忆条目（GET/POST /api/memory 实测响应结构，16 号方案 B2） */
export interface MemoryEntryDto {
  id: string;
  content: string;
  type?: string; // fact | preference | goal | entity | skill
  importance?: number;
  keywords?: string[];
  source?: string;
  scope?: string;
  createdAt?: string;
  updatedAt?: string;
  lastAccessedAt?: string;
  accessCount?: number;
}

/** GET /api/memory 分页响应 */
export interface MemoryListResult {
  items: MemoryEntryDto[];
  total: number;
  page: number;
  pageSize: number;
}

// ==================== 评估项目（17 号方案，方案 B：项目=一次安全评估对象）====================

/** 项目状态：active 进行中 / archived 已归档（归档不出现在默认左栏） */
export type ProjectStatus = 'active' | 'archived';

/** 服务端项目 DTO（GET/POST /api/projects，camelCase 风格对齐 conversations） */
export interface ProjectDto {
  id: string;
  name: string;
  /** 评估目标：IP/CIDR/域名/URL，如 10.20.1.0/24 或 www.example.edu.cn */
  target?: string | null;
  description?: string | null;
  /** 颜色 key：'' | red | orange | amber | green | teal | blue | purple | pink（对齐 PROJECT_COLOR_OPTIONS） */
  color?: string | null;
  pinned?: boolean;
  /** 同层级手动排序值，小数递增；后端按 order ASC NULLS LAST, updated_at DESC 返回 */
  order?: number | null;
  status?: ProjectStatus;
  createdAt?: string;
  updatedAt?: string;
  // 后端聚合计数（左栏徽标用；未部署该版后端时为 undefined，前端不显示）
  conversationCount?: number;
  taskCount?: number;
  findingCount?: number;
}

/** GET /api/projects 分页响应（与 /api/memory 同一形态） */
export interface ProjectListResult {
  items: ProjectDto[];
  total: number;
  page: number;
  pageSize: number;
}

/** POST /api/projects 请求体 */
export interface ProjectCreateInput {
  name: string;
  target?: string;
  description?: string;
  color?: string;
}

/** PATCH /api/projects/{id} 请求体（字段级更新） */
export interface ProjectPatchInput {
  name?: string;
  target?: string | null;
  description?: string | null;
  color?: string | null;
  pinned?: boolean;
  order?: number | null;
  status?: ProjectStatus;
}

/** 会话列表项（GET /api/conversations 实测 + 17 号方案新增 projectId） */
export interface ConversationSummaryDto {
  id: string;
  title: string;
  domain?: string | null;
  pinned?: boolean;
  status?: string;
  summary?: string | null;
  messageCount?: number;
  tokenCount?: number;
  /** 所属项目 id；null/undefined=未归类（左栏进"未归类会话"） */
  projectId?: string | null;
  createdAt?: string;
  updatedAt?: string;
}

export interface ConversationListResult {
  items: ConversationSummaryDto[];
  total: number;
  page: number;
  pageSize: number;
}

/** 会话消息（GET /api/conversations/{id}/messages 实测结构） */
export interface ConversationMessageDto {
  id: string;
  role: string;
  content: string;
  reasoning?: string | null;
  toolName?: string | null;
  toolOutput?: string | null;
  model?: string | null;
  tokenCount?: number;
  sequenceNum?: number;
  createdAt?: string;
}

export interface ConversationMessageListResult {
  items: ConversationMessageDto[];
  total: number;
}

/**
 * API错误响应
 */
export interface ApiError {
  error: string;
  detail?: string;
  code?: string;
}

/**
 * AiSOC 请求错误：携带 HTTP 状态码与「服务是否不可达」标记，
 * 便于上层做优雅降级（大脑离线时展示友好提示而非原始 502）。
 */
export class AisocApiError extends Error {
  readonly status: number;
  readonly isUnreachable: boolean;
  constructor(message: string, status = 0, isUnreachable = false) {
    super(message);
    this.name = 'AisocApiError';
    this.status = status;
    this.isUnreachable = isUnreachable;
  }
}

/**
 * AiSOC API客户端类
 */
export class AisocApi {
  private baseUrl: string;
  private headers: Record<string, string>;

  constructor(baseUrl: string = BRAIN_API_BASE, authToken?: string) {
    this.baseUrl = baseUrl;
    this.headers = {
      'Content-Type': 'application/json',
    };
    if (authToken) {
      this.headers['Authorization'] = `Bearer ${authToken}`;
    }
  }

  /**
   * 设置认证token
   */
  setAuthToken(token: string): void {
    this.headers['Authorization'] = `Bearer ${token}`;
  }

  /**
   * 清除认证token（注销时调用）
   */
  clearAuthToken(): void {
    delete this.headers['Authorization'];
  }

  /** 是否已注入 Bearer token（16 号方案 F3：Web 记忆面板按登录态切数据源） */
  hasAuthToken(): boolean {
    return typeof this.headers['Authorization'] === 'string' && this.headers['Authorization'].length > 7;
  }

  // 18 号方案 F4：401 确认防抖定时器（null=空闲）
  private _unauthorizedConfirmTimer: ReturnType<typeof setTimeout> | null = null;

  /**
   * 首次 401 后 3s 用原生 fetch（绕过 request，避免递归调度）发轻量确认请求；
   * 确认仍为 401 才广播 edushield:unauthorized。200/5xx/网络错误视为抖动，不登出。
   */
  private scheduleUnauthorizedConfirm(): void {
    if (this._unauthorizedConfirmTimer != null) return;
    this._unauthorizedConfirmTimer = setTimeout(() => {
      this._unauthorizedConfirmTimer = null;
      void (async () => {
        try {
          // 优先用 GET /auth/me 复核（18 号方案 §6.2 契约）；后端未上线该接口（404）
          // 时退化为业务接口探针。仅当复核仍 401 才确认登出，网络抖动/后端重启不闪退。
          let res = await fetch(`${this.baseUrl}/auth/me`, {
            headers: { ...this.headers },
          });
          if (res.status === 404) {
            res = await fetch(`${this.baseUrl}/conversations?page=1&page_size=1`, {
              headers: { ...this.headers },
            });
          }
          if (res.status === 401 && typeof window !== 'undefined') {
            window.dispatchEvent(new CustomEvent('edushield:unauthorized'));
          }
        } catch {
          // 网络错误：不登出
        }
      })();
    }, 3000);
  }

  /**
   * 通用请求方法
   */
  private async request<T>(
    endpoint: string,
    options: RequestInit = {}
  ): Promise<T> {
    const url = `${this.baseUrl}${endpoint}`;
    let response: Response;
    try {
      response = await fetch(url, {
        ...options,
        headers: {
          ...this.headers,
          ...options.headers,
        },
      });
    } catch {
      throw new AisocApiError('无法连接大脑服务，请确认服务已启动', 0, true);
    }

    if (!response.ok) {
      // 502/503/504 多为上游（大脑/子部件）未启动或网关超时，做友好降级
      if (response.status === 502 || response.status === 503 || response.status === 504) {
        throw new AisocApiError(
          `大脑服务不可用（HTTP ${response.status}），请先启动大脑服务`,
          response.status,
          true,
        );
      }
      // 16 号方案 F4：token 失效统一广播，AuthGate 监听后弹登录，避免各调用方重复处理
      // 18 号方案 F4：防抖——单次 401 可能是后端重启/网关抖动，3s 后带原 token 确认一次，
      // 仅当确认请求仍是 401 才广播登出；确认期间多个 401 合并。
      if (response.status === 401 && typeof window !== 'undefined') {
        this.scheduleUnauthorizedConfirm();
      }
      let message = `HTTP ${response.status}`;
      let detail: string | undefined;
      try {
        const parsed = (await response.json()) as Partial<ApiError>;
        message = parsed.error || message;
        detail = parsed.detail;
      } catch {
        // 非 JSON 响应体（如 HTML 网关错误），保留状态码即可
      }
      throw new AisocApiError(detail ? `${message} - ${detail}` : message, response.status);
    }

    return response.json() as Promise<T>;
  }

  /**
   * 下发任务（文档 §4.1）
   * POST /api/tasks — 单域任务或多阶段管道（pipeline 目前支持 data_leak）
   * 任务异步执行：返回 202 + pending 状态，后续用 SSE 或轮询刷新。
   */
  async createTask(task: CreateTaskInput): Promise<{ task_id: string; status: string; domain: string }> {
    return this.request('/tasks', {
      method: 'POST',
      body: JSON.stringify(task),
    });
  }

  /**
   * 任务状态 + 阶段进度 + 思维链（文档 §4.2）
   * GET /api/tasks/{task_id}
   */
  async getTask(taskId: string): Promise<TaskDetail> {
    return this.request(`/tasks/${taskId}`);
  }

  /**
   * 审计导出（文档 §4.5）
   * GET /api/tasks/{task_id}/export
   * 返回完整 JSON：任务 + findings + ledger + report。
   */
  async exportTask(taskId: string): Promise<Record<string, unknown>> {
    return this.request(`/tasks/${taskId}/export`);
  }

  /**
   * 查询证据（文档 §4.3）
   * GET /api/findings?task_id=
   * 响应包在 {task_id, findings} 中，这里解包出数组。
   */
  async getFindings(taskId: string): Promise<Finding[]> {
    const data = await this.request<{ task_id: string; findings: Finding[] }>(
      `/findings?task_id=${encodeURIComponent(taskId)}`,
    );
    return data.findings ?? [];
  }

  /**
   * 审批预案（TIR，文档 §4.4）
   * POST /api/approve — 批准/拒绝 → 大脑触发 8090 decision → 产出应急响应报告。
   * @param action 建议传具体 playbook_id；传 '' 则取该任务最新预案
   * 响应 status=responded 时带 report_md/report_id；recorded 表示该任务无 TIR 预案，仅记账。
   */
  async approveTool(
    taskId: string,
    action: string,
    decision: 'approved' | 'denied'
  ): Promise<TirApproveResponse> {
    return this.request<TirApproveResponse>('/approve', {
      method: 'POST',
      body: JSON.stringify({ task_id: taskId, action, decision }),
    });
  }

  /**
   * 模拟 WAF 适配路由（T2-2，8788 侧 `/mock/waf/block`）。
   * 纯模拟：请求体带 `simulated:true`，响应亦带 `simulated:true`，供 UI 显式标注"模拟"。
   * 由人工在审批 UI 点"批准"后由前端调用；**禁止 LLM 直接触发**。
   * 路由未部署（404）/401/超时/网络不可达时 `request()` 会抛错 —— 调用方须 catch 并轻提示，不阻断页面。
   */
  async mockWafBlock(cmd: MockWafCommand): Promise<MockWafBlockResponse> {
    return this.request<MockWafBlockResponse>('/mock/waf/block', {
      method: 'POST',
      body: JSON.stringify(cmd),
    });
  }

  // ==================== 应急响应（TIR）列表查询（文档 §4.1~4.3）====================
  // 注意：三个端点返回空数组是正常态（任务非 real_threat 时大脑不推 8090）。
  // request() 对非 2xx 一律抛 AisocApiError（无 404 静默降级），调用方需自行 catch。

  /** GET /api/tir/alerts?task_id= — 威胁告警列表 */
  async getTirAlerts(taskId: string): Promise<TirAlert[]> {
    const data = await this.request<{ task_id: string; alerts: TirAlert[] }>(
      `/tir/alerts?task_id=${encodeURIComponent(taskId)}`,
    );
    return data.alerts ?? [];
  }

  /** GET /api/tir/playbooks?task_id= — 处置预案列表 */
  async getTirPlaybooks(taskId: string): Promise<TirPlaybook[]> {
    const data = await this.request<{ task_id: string; playbooks: TirPlaybook[] }>(
      `/tir/playbooks?task_id=${encodeURIComponent(taskId)}`,
    );
    return data.playbooks ?? [];
  }

  /** GET /api/tir/reports?task_id= — 应急响应报告列表（审批后产生） */
  async getTirReports(taskId: string): Promise<TirReport[]> {
    const data = await this.request<{ task_id: string; reports: TirReport[] }>(
      `/tir/reports?task_id=${encodeURIComponent(taskId)}`,
    );
    return data.reports ?? [];
  }

  // ==================== 用户长期记忆（16 号方案 B2/F3，2026-10-09 实测契约）====================

  async listMemory(params: { page?: number; pageSize?: number; type?: string; q?: string; minImportance?: number } = {}): Promise<MemoryListResult> {
    const sp = new URLSearchParams();
    if (params.page) sp.set('page', String(params.page));
    if (params.pageSize) sp.set('page_size', String(params.pageSize));
    if (params.type) sp.set('type', params.type);
    if (params.q) sp.set('q', params.q);
    if (params.minImportance !== undefined) sp.set('min_importance', String(params.minImportance));
    const qs = sp.toString();
    return this.request<MemoryListResult>(`/memory${qs ? `?${qs}` : ''}`);
  }

  /** 新建记忆（手动"记住"）。后端强制 source=user_marked、importance>=80。 */
  async createMemory(body: { content: string; type?: string; importance?: number; keywords?: string[] }): Promise<MemoryEntryDto> {
    return this.request('/memory', { method: 'POST', body: JSON.stringify(body) });
  }

  /** 更新记忆（PATCH /api/memory/{id}，软字段级更新） */
  async updateMemory(id: string, body: { content?: string; type?: string; importance?: number; keywords?: string[] }): Promise<MemoryEntryDto> {
    return this.request(`/memory/${encodeURIComponent(id)}`, { method: 'PATCH', body: JSON.stringify(body) });
  }

  /** 删除记忆（DELETE /api/memory/{id}，服务端软删除） */
  async deleteMemory(id: string): Promise<void> {
    await this.request(`/memory/${encodeURIComponent(id)}`, { method: 'DELETE' });
  }

  /** 清空当前用户全部记忆（POST /api/memory/forget-all） */
  async forgetAllMemory(): Promise<void> {
    await this.request('/memory/forget-all', { method: 'POST' });
  }

  // ==================== 运行时设置（F5，docs/runtime-settings-api.md）====================

  /** 读取运行时行为字段（7 字段全量返回；失败由调用方降级 localStorage） */
  async getRuntimeSettings(): Promise<Record<string, unknown>> {
    return this.request('/settings/runtime');
  }

  /** 保存运行时行为字段（部分 patch；后端 2026-10-09 起支持持久化） */
  async saveRuntimeSettings(patch: Record<string, unknown>): Promise<void> {
    await this.request('/settings/runtime', { method: 'POST', body: JSON.stringify(patch) });
  }

  // ==================== 评估项目（17 号方案方案 B，Bearer 鉴权 + 用户隔离）====================

  /** 列出当前用户的项目（默认只返回 active；分页形态对齐 /api/memory） */
  async listProjects(params: { page?: number; pageSize?: number; q?: string; status?: ProjectStatus } = {}): Promise<ProjectListResult> {
    const sp = new URLSearchParams();
    if (params.page) sp.set('page', String(params.page));
    if (params.pageSize) sp.set('page_size', String(params.pageSize));
    if (params.q) sp.set('q', params.q);
    if (params.status) sp.set('status', params.status);
    const qs = sp.toString();
    return this.request<ProjectListResult>(`/projects${qs ? `?${qs}` : ''}`);
  }

  async createProject(body: ProjectCreateInput): Promise<ProjectDto> {
    return this.request('/projects', { method: 'POST', body: JSON.stringify(body) });
  }

  async getProject(id: string): Promise<ProjectDto> {
    return this.request(`/projects/${encodeURIComponent(id)}`);
  }

  async updateProject(id: string, patch: ProjectPatchInput): Promise<ProjectDto> {
    return this.request(`/projects/${encodeURIComponent(id)}`, { method: 'PATCH', body: JSON.stringify(patch) });
  }

  /** 删除项目（前端语义：归档用 PATCH status=archived；DELETE 仅在"删除项目及其空关联"确认后调用） */
  async deleteProject(id: string): Promise<void> {
    await this.request(`/projects/${encodeURIComponent(id)}`, { method: 'DELETE' });
  }

  // ==================== 会话（16 号方案已有表，17 号方案补 project_id 维度）====================

  /**
   * 列出当前用户的会话。projectId 过滤：
   *   - 传具体 id：该项目下会话
   *   - 传 'none'：未归类会话（后端约定 project_id=none）
   *   - 不传：全部
   */
  async listConversations(params: { page?: number; pageSize?: number; projectId?: string; q?: string } = {}): Promise<ConversationListResult> {
    const sp = new URLSearchParams();
    if (params.page) sp.set('page', String(params.page));
    if (params.pageSize) sp.set('page_size', String(params.pageSize));
    if (params.projectId) sp.set('project_id', params.projectId);
    if (params.q) sp.set('q', params.q);
    const qs = sp.toString();
    return this.request<ConversationListResult>(`/conversations${qs ? `?${qs}` : ''}`);
  }

  /** 拉取会话消息（打开历史会话时灌进 tab），按 sequenceNum 升序 */
  async getConversationMessages(conversationId: string): Promise<ConversationMessageListResult> {
    return this.request(`/conversations/${encodeURIComponent(conversationId)}/messages`);
  }

  /** 更新会话（重命名/置顶/归档绑定）。PATCH 语义用 PUT（后端实测开放 PUT /api/conversations/{id}） */
  async updateConversation(conversationId: string, patch: { title?: string; pinned?: boolean; projectId?: string | null }): Promise<ConversationSummaryDto> {
    const body: Record<string, unknown> = {};
    if (patch.title !== undefined) body.title = patch.title;
    if (patch.pinned !== undefined) body.pinned = patch.pinned;
    if (patch.projectId !== undefined) body.project_id = patch.projectId;
    return this.request(`/conversations/${encodeURIComponent(conversationId)}`, {
      method: 'PUT',
      body: JSON.stringify(body),
    });
  }

  /** 删除会话（DELETE /api/conversations/{id}） */
  async deleteConversation(conversationId: string): Promise<void> {
    await this.request(`/conversations/${encodeURIComponent(conversationId)}`, { method: 'DELETE' });
  }


  /**
   * 查询报告（文档 §4.4）
   * GET /api/reports/{task_id} — report 为 Markdown 字符串。
   */
  async getReport(taskId: string): Promise<ReportDoc> {
    return this.request(`/reports/${taskId}`);
  }

  /**
   * 部件注册表（文档 §4.6）
   * GET /api/registry — 返回 {parts: [...]}，token 已脱敏，前端不要渲染 token。
   */
  async getRegistry(): Promise<RegistryPart[]> {
    const data = await this.request<{ parts: RegistryPart[] }>('/registry');
    return data.parts ?? [];
  }

  /**
   * 各 Agent 忙闲状态（文档 §4.1c 状态墙）
   * GET /api/agents/status
   */
  async getAgentsStatus(): Promise<AgentsStatus> {
    return this.request('/agents/status');
  }

  /**
   * XDR 告警样例（文档 §4.7）
   * GET /api/data/alarms?limit=
   */
  async getAlarms(limit: number = 10): Promise<{ source?: string; count?: number; alarms: Alarm[] }> {
    return this.request(`/data/alarms?limit=${limit}`);
  }

  /**
   * 告警统计（文档 §4.7）
   * GET /api/data/alarms/summary
   */
  async getAlarmsSummary(): Promise<AlarmsSummary> {
    return this.request('/data/alarms/summary');
  }

  /**
   * 健康检查（文档 §4.10）
   * GET /api/health
   */
  async healthCheck(): Promise<{ status: string; service: string }> {
    return this.request('/health');
  }

  /**
   * 实时事件流（文档 §4.8）
   * GET /api/stream (SSE)
   * 每帧 data: {task_id, domain, event, payload}；15 秒心跳帧由 EventSource 自动忽略。
   */
  connectRealtimeStream(
    onEvent: (event: StreamEvent) => void,
    onError?: (error: Event) => void,
    taskId?: string,
    domain?: string
  ): EventSource {
    const params = new URLSearchParams();
    if (taskId) params.append('task_id', taskId);
    if (domain) params.append('domain', domain);

    const url = `${this.baseUrl}/stream${params.toString() ? `?${params.toString()}` : ''}`;
    const eventSource = new EventSource(url);

    eventSource.onmessage = (event) => {
      try {
        const data = JSON.parse(event.data) as StreamEvent;
        onEvent(data);
      } catch (error) {
        console.error('Failed to parse SSE event:', error);
      }
    };

    if (onError) {
      eventSource.onerror = onError;
    }

    return eventSource;
  }

  /**
   * 最近任务列表（文档 §4.1b）
   * GET /api/tasks?limit=
   */
  async listTasks(limit: number = 50): Promise<{ tasks: TaskInfo[] }> {
    return this.request(`/tasks?limit=${limit}`);
  }

  /**
   * 授权白名单：查看当前列表（GET /api/whitelist）
   * 返回 { enabled, targets }；后端会优先读 data/whitelist.json，回退到 .env 默认值
   */
  async listWhitelist(): Promise<WhitelistView> {
    return this.request<WhitelistView>('/whitelist');
  }

  /**
   * 授权白名单：增加目标（POST /api/whitelist { action: 'add', target }）
   * target 必须是单 IP / 域名 / 带 scheme 的 URL（不支持 CIDR）
   * 后端会写入 data/whitelist.json，重启不丢
   */
  async addWhitelistTarget(target: string): Promise<WhitelistView> {
    const trimmed = target.trim();
    if (!trimmed) throw new Error('目标不能为空');
    return this.request<WhitelistView>('/whitelist', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ action: 'add', target: trimmed }),
    });
  }

  /**
   * 授权白名单：删除目标（POST /api/whitelist { action: 'remove', target }）
   */
  async removeWhitelistTarget(target: string): Promise<WhitelistView> {
    const trimmed = target.trim();
    if (!trimmed) throw new Error('目标不能为空');
    return this.request<WhitelistView>('/whitelist', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ action: 'remove', target: trimmed }),
    });
  }

  /**
   * 授权白名单：开关（POST /api/whitelist { action: 'set_enabled', enabled }）
   * enabled=false 会让后端全部放行（危险！仅临时调试用）
   */
  async setWhitelistEnabled(enabled: boolean): Promise<WhitelistView> {
    return this.request<WhitelistView>('/whitelist', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ action: 'set_enabled', enabled }),
    });
  }

  // GET /api/chat/stream（大脑侧）
  // - 默认模式（pass_through=false）：07 协议 9 种简化帧
  //   delta / thinking / tool_call / tool_result / stage_start / stage_finished
  //   / task_created / answer / report_ready
  // - 透传模式（pass_through=true）：reasonix 原样 9 种新 kind
  //   turn_started / memory_compiler_stats / reasoning / text / tool_dispatch
  //   / tool_progress / message / usage / turn_done
  //
  // 每帧 data: {…}；结束 data: [DONE]。
  // 返回拼接后的完整回复文本（delta + text + answer + message.text）。
  //
  // 旧调用方继续传 onDelta；onFrame 接收全帧（推理过程展示）。
  async chatStream(
    message: string,
    options: {
      system?: string;
      onDelta?: (delta: string) => void;
      signal?: AbortSignal;
      onFrame?: (frame: ChatStreamFrame) => void;
      /** true=透传模式（reasonix 原样事件，10 协议），false=默认 07 协议简化帧。默认 false。 */
      passThrough?: boolean;
      /**
       * 前端会话 ID（可选）。与 CreateTaskInput.session_id 同一语义：
       * 大脑按 (session_id, domain) 缓存“新会话”标记。不传 → 退化到原行为。
       * 推荐传前端 tabId（同一聊天窗口内复用同一 ID）。
       */
      sessionId?: string;
      /**
       * Pipeline 名称（可选）。目前支持 'data_leak'。
       * 透传到后端 chat/stream，让大脑走多阶段管道（logaudit → pentest → verdict → report）而不是单 stage。
       * 不传 → 退化到原行为（按 message 路由到单 domain）。
       */
      pipeline?: string;
      /**
       * 域（可选）。透传到后端 chat/stream。
       * 与 pipeline 配合：data_leak 通常配合 domain='logaudit'（第一个 stage）。
       */
      domain?: string;
      /**
       * 目标（可选）。透传到后端 chat/stream。
       * 任务意图必备字段（用于部件白名单校验 + findings 上下文）。
       */
      target?: string;
      /**
       * 历史对话 ID（可选，16 号方案 F1）。已登录用户传入后，本轮消息
       * 自动落库到该会话；不传时后端自动建会话并经 conversation_bound 帧回传 id。
       */
      conversationId?: string;
      /**
       * 用户长期记忆召回开关（16 号方案 B3）。true=传 use_memory=true，
       * false=传 use_memory=false；undefined=不传（后端默认 true）。
       */
      useMemory?: boolean;
      /**
       * 评估项目 ID（17 号方案方案 B）。传入后本轮自动建/续接的会话绑定到该项目，
       * 任务/发现随会话归属项目；不传=未归类。
       */
      projectId?: string;
      /**
       * 服务端附件元数据（21 号方案）。已落会话目录的附件（name + 相对 ATTACHMENT_ROOT
       * 路径），后端 prompt 只注入路径引用、部件工具按路径读盘，不再内联全文。
       * 未上线 21 号的后端会静默丢弃该未声明字段，向前兼容。
       */
      attachments?: Array<{ name: string; path: string }>;
    } = {},
  ): Promise<string> {
    const { system, onDelta, signal, onFrame, passThrough = false, sessionId, pipeline, domain, target, conversationId, useMemory, projectId, attachments } = options;
    const requestBody: Record<string, unknown> = { message };
    if (system !== undefined) requestBody.system = system;
    if (passThrough) requestBody.pass_through = true;
    if (sessionId) requestBody.session_id = sessionId;
    if (pipeline) requestBody.pipeline = pipeline;
    if (domain) requestBody.domain = domain;
    if (target) requestBody.target = target;
    if (conversationId) requestBody.conversation_id = conversationId;
    if (useMemory !== undefined) requestBody.use_memory = useMemory;
    if (projectId) requestBody.project_id = projectId;
    if (attachments && attachments.length > 0) requestBody.attachments = attachments;
    let response: Response;
    try {
      response = await fetch(`${this.baseUrl}/chat/stream`, {
        method: 'POST',
        // 16 号方案 F4：流式请求同样携带 Bearer（登录后 conversation 落库、记忆召回都依赖身份）
        headers: { ...this.headers, 'Content-Type': 'application/json' },
        body: JSON.stringify(requestBody),
        signal,
      });
    } catch {
      throw new AisocApiError('无法连接大脑服务，请确认服务已启动', 0, true);
    }

    if (!response.ok) {
      let detail = '';
      try { detail = (await response.text()).slice(0, 300); } catch { /* ignore */ }
      throw new AisocApiError(
        detail ? `大脑聊天接口 HTTP ${response.status} - ${detail}` : `大脑聊天接口 HTTP ${response.status}`,
        response.status,
      );
    }

    if (!response.body) {
      throw new AisocApiError('大脑聊天接口无响应体（流式不可用）', response.status);
    }

    // 简易类型守卫（chatStream flush 内复用）
    function isObject(v: unknown): v is Record<string, unknown> {
      return typeof v === 'object' && v !== null && !Array.isArray(v);
    }

    const reader = response.body.getReader();
    const decoder = new TextDecoder('utf-8');
    let buffer = '';
    let full = '';
    // 修复：之前一直等到 reader.read() 返回 done 才退出，但 Python 反代 SSE
    // (serve_frontend.py) 不主动发 EOF，浏览器 reader 会永远等下去，
    // 导致 chatStream 不 resolve、streamStats phase 永远停在 streaming，
    // spinner 一直显示“正在接收回答”。现在 flush 遇到 [DONE] 就标 doneSse，
    // 下一个 chunk 出来后立刻 break。
    let doneSse = false;

    const flush = (raw: string) => {
      for (const line of raw.split('\n')) {
        const trimmed = line.trim();
        if (!trimmed.startsWith('data:')) continue;
        const payload = trimmed.slice(5).trim();
        if (payload === '[DONE]') { doneSse = true; continue; }
        if (!payload) continue;
        try {
          const evt = JSON.parse(payload) as Record<string, unknown>;
          const taskId: string | undefined = typeof evt.task_id === 'string' ? evt.task_id : undefined;

          // === kind 包装帧（部件接力原样透传，2026-09-28 抓流实证）===
          // 任务意图消息经大脑接力到部件（pentest/logaudit/intel）后，部件（reasonix serve）
          // 原生 SSE 是 {"kind": "...", ...} 包装格式，大脑原样转发。此前解析器只认裸键帧
          // （{tool_result: ...} / {reasoning: ...}），导致：
          //   1) tool_dispatch / tool_progress / tool_result 全部静默丢弃 → bash 卡片无输出；
          //   2) {"kind":"reasoning","text":"用户"} 被下方 evt.text 检查误判成 text 帧 → 思考链混入正文；
          //   3) {"kind":"notice","text":"Decision recorded..."} 同样误判成 text 污染回答。
          // 注意：kind 分支必须先于裸键检查，且未识别的 kind 必须在此终结（continue），
          // 否则 notice/turn_phase 等带 text 字段的元数据帧会漏到裸键 text 检查。
          const wrappedKind = typeof evt.kind === 'string' ? evt.kind : '';
          if (wrappedKind && wrappedKind !== 'stream_error' && wrappedKind !== 'error') {
            switch (wrappedKind) {
              case 'text':
                if (typeof evt.text === 'string') {
                  full += evt.text;
                  onDelta?.(evt.text);
                  onFrame?.({ kind: 'text', text: evt.text, task_id: taskId });
                }
                break;
              case 'reasoning':
                // 实证：kind 包装的 reasoning 帧正文在 text 字段（非 reasoning 字段），双字段兜底
                onFrame?.({
                  kind: 'reasoning',
                  text: typeof evt.text === 'string' ? evt.text : (typeof evt.reasoning === 'string' ? evt.reasoning : ''),
                  task_id: taskId,
                });
                break;
              case 'message':
                if (typeof evt.text === 'string') {
                  full += evt.text;
                  onDelta?.(evt.text);
                }
                onFrame?.({
                  kind: 'message',
                  text: typeof evt.text === 'string' ? evt.text : '',
                  reasoning: typeof evt.reasoning === 'string' ? evt.reasoning : undefined,
                  task_id: taskId,
                });
                break;
              case 'tool_dispatch': {
                const tdTool = isObject(evt.tool) ? evt.tool as Record<string, unknown> : {};
                onFrame?.({ kind: 'tool_dispatch', tool: tdTool, task_id: taskId });
                break;
              }
              case 'tool_progress': {
                const tpTool = isObject(evt.tool) ? evt.tool as Record<string, unknown> : {};
                const tpOutput = typeof tpTool.output === 'string'
                  ? tpTool.output
                  : (typeof evt.output === 'string' ? evt.output : '');
                onFrame?.({ kind: 'tool_progress', tool: tpTool, output: tpOutput, partial: true, task_id: taskId });
                break;
              }
              case 'tool_result': {
                // kind 包装的 tool_result.tool 是完整 dict（含 id/name/args/output/partial）。
                // 内部帧约定 tool 为 name 字符串；webApiProxy 按 task_id 查最近 dispatch id 合并，
                // 查不到时 reducer 兜底按"同名 + running"匹配，卡片不会丢。
                const trTool = isObject(evt.tool) ? evt.tool as Record<string, unknown> : {};
                let trName = typeof trTool.name === 'string' && trTool.name ? trTool.name
                  : (typeof trTool.id === 'string' ? trTool.id : '');
                if (!trName) trName = 'unknown';
                const trOutput = typeof trTool.output === 'string'
                  ? trTool.output
                  : (typeof evt.output === 'string' ? evt.output : '');
                const trToolId = typeof trTool.id === 'string' ? trTool.id : '';
                onFrame?.({
                  kind: 'tool_result',
                  tool: trName,
                  output: trOutput,
                  exit_code: typeof evt.exit_code === 'number' ? evt.exit_code : undefined,
                  partial: trTool.partial === true,
                  task_id: taskId,
                  // 保留真实 call id：透传模式下同一 turn 可能并发多个 bash，
                  // webApiProxy 必须按 id 精确合并，不能只按 counter 猜最近一张卡。
                  toolId: trToolId || undefined,
                  // 部分调用只发 progress + result（没有 dispatch），命令参数仅存在于 result 帧，
                  // 必须带下去，否则卡片 args 为空、标题栏只有一个 "{}"。
                  args: trTool.args,
                } as ChatStreamFrame);
                break;
              }
              case 'usage':
                if (isObject(evt.usage)) {
                  onFrame?.({ kind: 'usage', usage: evt.usage as Record<string, unknown>, task_id: taskId });
                }
                break;
              case 'turn_started':
                onFrame?.({ kind: 'turn_started', task_id: taskId });
                break;
              case 'turn_done':
                onFrame?.({ kind: 'turn_done', task_id: taskId });
                break;
              case 'conversation':
              case 'conversation_bound': {
                // 16 号方案 B3：大脑自动建会话时回传 id。
                // 实证帧形：{"kind":"conversation","id":"..."} 与 {"kind":"conversation_bound","conversationId":"..."}，
                // 语义等价，统一归一为 conversation_bound（conversationId 字段，id 字段兜底）。
                // 17 号方案：projectId 随绑定帧回传（可能缺省，缺省即未归类）。
                const cid = typeof evt.conversationId === 'string' && evt.conversationId
                  ? evt.conversationId
                  : (typeof evt.id === 'string' ? evt.id : '');
                const boundProjectId = typeof evt.projectId === 'string' && evt.projectId ? evt.projectId : undefined;
                if (cid) onFrame?.({ kind: 'conversation_bound', conversationId: cid, projectId: boundProjectId, task_id: taskId });
                break;
              }
              case 'memory_retrieved': {
                // 16 号方案 B3：本轮召回到的用户长期记忆（首条 delta 前下发）。
                const rawEntries = Array.isArray(evt.entries) ? evt.entries : [];
                const entries: MemoryRetrievedEntry[] = rawEntries
                  .filter(isObject)
                  .map((e) => ({
                    id: typeof e.id === 'string' ? e.id : '',
                    content: typeof e.content === 'string' ? e.content : '',
                    type: typeof e.type === 'string' ? e.type : undefined,
                    importance: typeof e.importance === 'number' ? e.importance : undefined,
                    matchedBy: typeof e.matchedBy === 'string' ? e.matchedBy : undefined,
                  }))
                  .filter((e) => e.id || e.content);
                onFrame?.({ kind: 'memory_retrieved', entries, injected: evt.injected !== false, task_id: taskId });
                break;
              }
              default:
                // notice / turn_phase / stream_attempt / approval_request（服务端 yolo 已自动放行）
                // 等元数据帧：对 UI 无增量价值，静默忽略
                break;
            }
            continue;
          }

          // === 10 协议透传模式独有顶层字段（reasonix 原样事件）===
          // 先判别这些不会与 07 帧冲突的顶层字段，避免误判 task_created。
          if (evt.turn_started !== undefined) {
            onFrame?.({ kind: 'turn_started', task_id: taskId });
            continue;
          }
          if (evt.turn_done !== undefined) {
            onFrame?.({ kind: 'turn_done', task_id: taskId });
            continue;
          }
          if (isObject(evt.memory_compiler_stats)) {
            // reasonix 帧形如 {memory_compiler_stats:{memoryCompiler:...}, task_id}
            const mcs = evt.memory_compiler_stats as Record<string, unknown>;
            const mcsBody = (isObject(mcs.memoryCompiler) ? mcs.memoryCompiler as Record<string, unknown> : mcs);
            onFrame?.({ kind: 'memory_compiler_stats', memoryCompiler: mcsBody, task_id: taskId });
            continue;
          }
          if (isObject(evt.usage)) {
            onFrame?.({ kind: 'usage', usage: evt.usage as Record<string, unknown>, task_id: taskId });
            continue;
          }

          // === delta / text（互斥：delta 是 07，text 是 10）===
          if (typeof evt.delta === 'string') {
            full += evt.delta;
            onDelta?.(evt.delta);
            onFrame?.({ kind: 'delta', delta: evt.delta, task_id: taskId });
            continue;
          }
          if (typeof evt.text === 'string') {
            // 透传模式：reasonix 输出的文本增量（与 delta 互斥，已被上面排除）
            full += evt.text;
            onDelta?.(evt.text);
            onFrame?.({ kind: 'text', text: evt.text, task_id: taskId });
            continue;
          }

          // === thinking / reasoning（互斥）===
          if (typeof evt.thinking === 'string') {
            onFrame?.({ kind: 'thinking', thinking: evt.thinking, task_id: taskId });
            continue;
          }
          if (typeof evt.reasoning === 'string') {
            onFrame?.({ kind: 'reasoning', text: evt.reasoning, task_id: taskId });
            continue;
          }

          // === tool_call / tool_dispatch（互斥）===
          if (isObject(evt.tool_call)) {
            // 兼容三种部件事件格式：
            //   - mock_part 旧格式：evt.tool_call = { tool: "<name>", args: {...} }
            //   - reasonix serve 新格式：evt.tool_call = { tool: {id,name,args,readOnly,...}, args: ... }
            //   - name 为空时回退到 tool.id，避免丢帧
            // tool 名都从 tool.name / tool / tool.id 拿。
            const tc = evt.tool_call as Record<string, unknown>;
            let toolName = '';
            let toolArgs: unknown = tc.args;
            if (typeof tc.tool === 'string') {
              toolName = tc.tool;
            } else if (isObject(tc.tool)) {
              const tObj = tc.tool as Record<string, unknown>;
              toolName = typeof tObj.name === 'string' ? tObj.name : '';
              if (!toolName && typeof tObj.id === 'string') toolName = tObj.id;
              if (toolArgs === undefined || toolArgs === null) toolArgs = tObj.args;
            }
            if (!toolName) toolName = 'unknown';
            onFrame?.({ kind: 'tool_call', tool: toolName, args: toolArgs ?? {}, task_id: taskId });
            continue;
          }
          if (isObject(evt.tool_dispatch)) {
            // 透传模式：保留 tool 原始 dict（含 id/name/args/partial）
            const td = evt.tool_dispatch as Record<string, unknown>;
            const tdTool = isObject(td.tool) ? td.tool as Record<string, unknown> : td;
            onFrame?.({ kind: 'tool_dispatch', tool: tdTool, task_id: taskId });
            continue;
          }

          // === tool_result / tool_progress（互斥）===
          if (isObject(evt.tool_result)) {
            // 兼容 mock_part（tool 是 string）与 reasonix（tool 是 dict），
            // 以及 reasonix 偶发 tool.name 为空字符串时的退化情况。
            const tr = evt.tool_result as Record<string, unknown>;
            let trToolName = '';
            if (typeof tr.tool === 'string') {
              trToolName = tr.tool;
            } else if (isObject(tr.tool)) {
              const tObj = tr.tool as Record<string, unknown>;
              trToolName = typeof tObj.name === 'string' ? tObj.name : '';
              if (!trToolName && typeof tObj.id === 'string') trToolName = tObj.id;
            }
            if (!trToolName) trToolName = 'unknown';
            const trOutput = typeof tr.output === 'string' ? tr.output : '';
            const trExit = typeof tr.exit_code === 'number' ? tr.exit_code : undefined;
            const trPartial = tr.partial === true;  // 透传 partial 标记（reasonix tool_progress）
            onFrame?.({ kind: 'tool_result', tool: trToolName, output: trOutput, exit_code: trExit, task_id: taskId, partial: trPartial } as ChatStreamFrame);
            continue;
          }
          if (isObject(evt.tool_progress)) {
            // 透传模式：保留 tool 原始 dict（含 id/name/output/partial）
            const tp = evt.tool_progress as Record<string, unknown>;
            const tpTool = isObject(tp.tool) ? tp.tool as Record<string, unknown> : {};
            const tpOutput = typeof tpTool.output === 'string'
              ? tpTool.output
              : (typeof tp.output === 'string' ? tp.output : '');
            onFrame?.({ kind: 'tool_progress', tool: tpTool, output: tpOutput, partial: true, task_id: taskId });
            continue;
          }

          // === stage_start / stage_finished ===
          if (typeof evt.stage_start === 'string') {
            onFrame?.({ kind: 'stage_start', stage: evt.stage_start, task_id: taskId });
            continue;
          }
          if (isObject(evt.stage_finished) && typeof (evt.stage_finished as Record<string, unknown>).stage === 'string') {
            const sf = evt.stage_finished as { stage: string; ok?: boolean };
            onFrame?.({ kind: 'stage_finished', stage: sf.stage, ok: sf.ok !== false, task_id: taskId });
            continue;
          }

          // === task_created（带 task_id + domain 但不带 delta）===
          if (typeof evt.task_id === 'string' && typeof evt.domain === 'string' && evt.delta === undefined) {
            onFrame?.({ kind: 'task_created', task_id: evt.task_id, domain: evt.domain });
            continue;
          }

          // === answer / message（互斥）===
          if (isObject(evt.answer) && typeof (evt.answer as Record<string, unknown>).text === 'string') {
            const ans = evt.answer as { text: string };
            full += ans.text;
            onFrame?.({ kind: 'answer', text: ans.text, task_id: taskId });
            continue;
          }
          if (isObject(evt.message) && typeof (evt.message as Record<string, unknown>).text === 'string') {
            // 透传模式：reasonix 一轮 turn 结束时的合并消息（含 reasoning）
            const m = evt.message as { text: string; reasoning?: string };
            full += m.text;
            onFrame?.({ kind: 'message', text: m.text, reasoning: m.reasoning, task_id: taskId });
            continue;
          }

          // === report_ready ===
          // 07 协议嵌套结构：{report_ready: {task_id, report_url}, task_id}
          // 兼容顶层字段形式（task_id/report_url 都在顶层）。
          if (isObject(evt.report_ready)) {
            const rr = evt.report_ready as Record<string, unknown>;
            const rrTaskId = typeof rr.task_id === 'string' ? rr.task_id : (taskId ?? '');
            const rrUrl = typeof rr.report_url === 'string' ? rr.report_url : '';
            onFrame?.({ kind: 'report_ready', task_id: rrTaskId, report_url: rrUrl });
            continue;
          }
          if (typeof evt.task_id === 'string' && typeof evt.report_url === 'string') {
            onFrame?.({ kind: 'report_ready', task_id: evt.task_id, report_url: evt.report_url });
            continue;
          }
          // === stream_error ===
          // 实测帧形如（3 种来源）：
          //   - 10 协议顶层 kind：{kind:"stream_error", err:"..."}
          //   - 10 协议顶层 kind：{kind:"error", message:"..."}
          //   - 07 协议嵌套对象：{error: {code, message, ...}, task_id}
          // 这里把三类都归到 ChatStreamFrame 的 stream_error，err 字段兼容 err/message/error 三个来源。
          if (isObject(evt.error) && !Array.isArray(evt.error)) {
            const errObj = evt.error as Record<string, unknown>;
            let errMsg = '';
            if (typeof errObj.message === 'string') errMsg = errObj.message;
            else if (typeof errObj.error === 'string') errMsg = errObj.error;
            else if (typeof errObj.err === 'string') errMsg = errObj.err;
            else if (typeof errObj.code === 'string') errMsg = errObj.code;
            else errMsg = JSON.stringify(errObj).slice(0, 200);
            onFrame?.({ kind: 'stream_error', err: errMsg, task_id: taskId });
            continue;
          }
          if (evt.kind === 'stream_error' || evt.kind === 'error') {
            let errMsg = '';
            if (typeof evt.err === 'string') errMsg = evt.err;
            else if (typeof evt.message === 'string') errMsg = evt.message;
            else if (typeof evt.error === 'string') errMsg = evt.error;
            else errMsg = `unknown ${String(evt.kind)} error`;
            onFrame?.({ kind: 'stream_error', err: errMsg, task_id: taskId });
            continue;
          }
          // 其他未知字段静默忽略（实测有 stage_start: "turn" / "working" 等冗余 key）
        } catch { /* 跳过无法解析的帧 */ }
      }
    };

    while (true) {
      // signal 被 abort 后立刻 throw，让 Promise.race 超时分支能走 reject 路径
      // （避免只 abort fetch 而 reader.read() 仍 pending，导致 onFinally 不跑、
      // React submitting 卡死）。
      signal?.throwIfAborted?.();
      const { done, value } = await reader.read();
      if (done) break;
      buffer += decoder.decode(value, { stream: true });
      let sepIdx: number;
      while ((sepIdx = buffer.indexOf('\n\n')) !== -1) {
        const raw = buffer.slice(0, sepIdx);
        buffer = buffer.slice(sepIdx + 2);
        flush(raw);
        if (doneSse) break;
      }
      if (doneSse) break;
    }
    // 末尾可能没有 \n\n 结尾，flush 残留 buffer
    if (buffer.trim()) flush(buffer);
    return full;
  }
}

/**
 * 默认API客户端实例
 */
export const aisocApi = new AisocApi();

/**
 * 工厂函数：创建特定域的API客户端
 */
export function createDomainApiClient(domain: string, authToken?: string): AisocApi {
  // 通过 Vite 代理访问各部件端口，避免 CORS
  // 主路由全部用大脑侧部件名（intel）；threatintel 保留做兼容。
  const domainProxies: Record<string, string> = {
    brain: '/aisoc-brain/api',
    pentest: '/aisoc-pentest/api',
    logaudit: '/aisoc-logaudit/api',
    intel: '/aisoc-intel/api',
    threatintel: '/aisoc-intel/api', // 兼容旧调用，已弃用
    incident: '/aisoc-incident/api',
  };

  const baseUrl = domainProxies[domain] || domainProxies.brain;
  return new AisocApi(baseUrl, authToken);
}

/**
 * 任务生成器：生成符合格式的任务ID
 */
export function generateTaskId(): string {
  const now = new Date();
  const dateStr = now.toISOString().slice(0, 10).replace(/-/g, ''); // YYYYMMDD
  const timeStr = now.toISOString().slice(11, 19).replace(/:/g, ''); // HHMMSS
  const random = Math.random().toString(36).substring(2, 6).toUpperCase();
  return `T${dateStr}-${timeStr}${random}`;
}

/**
 * Finding ID生成器
 */
export function generateFindingId(taskId: string, sequence: number): string {
  return `F-${taskId}-${sequence.toString().padStart(3, '0')}`;
}

// ============================================================================
// 前端友好常量（按 03-大脑设计.md 配置）
// ============================================================================

/** 部件域 → 中文显示名称 */
export const DOMAIN_LABELS: Record<string, string> = {
  brain: '大脑 (AiSOC Brain)',
  pentest: '渗透测试 Agent',
  logaudit: '日志审计 Agent',
  intel: '威胁情报 Agent',
  threatintel: '威胁情报 Agent', // 兼容旧调用
  incident: '应急响应 Agent',
};

/** 部件域 → 颜色（架构图/徽标配色） */
export const DOMAIN_COLORS: Record<string, { dot: string; bg: string; ring: string }> = {
  brain:       { dot: 'bg-fuchsia-500', bg: 'bg-fuchsia-50',  ring: 'ring-fuchsia-300' },
  pentest:     { dot: 'bg-rose-500',    bg: 'bg-rose-50',     ring: 'ring-rose-300' },
  logaudit:    { dot: 'bg-sky-500',     bg: 'bg-sky-50',      ring: 'ring-sky-300' },
  intel:       { dot: 'bg-amber-500',   bg: 'bg-amber-50',    ring: 'ring-amber-300' },
  threatintel: { dot: 'bg-amber-500',   bg: 'bg-amber-50',    ring: 'ring-amber-300' }, // 兼容旧调用
  incident:    { dot: 'bg-emerald-500', bg: 'bg-emerald-50',  ring: 'ring-emerald-300' },
};

/** 部件域 → 描述（计划书 §3.2 身体部件公式） */
export const DOMAIN_DESCRIPTIONS: Record<string, string> = {
  brain:       '编排调度 · 威胁判定 · 知识库 · 报告合规 · 审计留档',
  pentest:     '渗透测试（端口扫描、漏洞探测、CVE 验证、利用）',
  logaudit:    '日志审计（异常检测、访问溯源、关联分析、攻击链重建）',
  intel:       '威胁情报（IP/域名信誉、情报源聚合、OSINT 查询）',
  threatintel: '威胁情报（IP/域名信誉、情报源聚合、OSINT 查询）', // 兼容旧调用
  incident:    '应急响应（处置剧本、封禁工单、加固建议）',
};

/** 部件域 → 默认端口（5 个域统一走大脑 6657；注册表占位；运行时以大脑 /api/registry 为准） */
export const DOMAIN_PORTS: Record<string, number> = {
  brain: 6657,
  pentest: 6657,
  logaudit: 6657,
  intel: 6657,
  threatintel: 6657, // 兼容旧调用
  incident: 6657,
};

/** 严重级别 → 中文 + 样式尾词 */
export const SEVERITY_META: Record<string, { label: string; cls: string }> = {
  critical: { label: '严重', cls: 'bg-red-100 text-red-800 border-red-200' },
  high:     { label: '高危', cls: 'bg-orange-100 text-orange-800 border-orange-200' },
  medium:   { label: '中危', cls: 'bg-yellow-100 text-yellow-800 border-yellow-200' },
  low:      { label: '低危', cls: 'bg-blue-50 text-blue-700 border-blue-200' },
  info:     { label: '信息', cls: 'bg-gray-100 text-gray-700 border-gray-200' },
};

/** 任务状态 → 中文 + 颜色徽标 */
export const TASK_STATUS_META: Record<string, { label: string; cls: string }> = {
  pending:   { label: '等待中',   cls: 'bg-gray-100 text-gray-700' },
  running:   { label: '运行中',   cls: 'bg-blue-100 text-blue-800 animate-pulse' },
  approval:  { label: '待审批',   cls: 'bg-amber-100 text-amber-800' },
  completed: { label: '已完成',   cls: 'bg-green-100 text-green-800' },
  failed:    { label: '失败',     cls: 'bg-red-100 text-red-800' },
  cancelled: { label: '已取消',   cls: 'bg-zinc-100 text-zinc-600' },
  archived:  { label: '已归档',   cls: 'bg-violet-50 text-violet-700' },
};

/** 判定结果 → 中文 + 样式 */
export const VERDICT_META: Record<string, { label: string; cls: string; icon: string }> = {
  real_threat:    { label: '真实威胁', cls: 'bg-red-50 border-red-200 text-red-800',  icon: '⚠️' },
  false_positive: { label: '误报排除', cls: 'bg-green-50 border-green-200 text-green-800', icon: '✅' },
  pending_review: { label: '待人工复核', cls: 'bg-yellow-50 border-yellow-200 text-yellow-800', icon: '🗂️' },
};

/**
 * 管道预设（计划书 §3.6 多 Agent 协作场景 + 03 大脑设计 §2.2 管道定义）
 * stage 顺序即编排顺序；含 "∥" 的标记在同一阶段内并行
 */
export type PipelineStage = {
  domain: TaskMessage['domain'];
  name: string;                  // 阶段名（中文显示）
  tools?: string[];              // 工具白名单（留空=全部）
  passFindings?: boolean;        // 是否把上阶段 Finding 摘要作为 context 注入（星型证据流转）
};
export type PipelinePreset = {
  id: string;
  name: string;                  // 中文短名
  description: string;           // 完整说明
  story: string;                 // 通俗说明（对应计划书"协作场景"条目）
  stages: PipelineStage[];
};

export const PIPELINE_PRESETS: PipelinePreset[] = [
  {
    id: 'data_leak_investigation',
    name: '疑似数据泄露调查（旗舰场景）',
    description: 'logaudit → pentest → [情报] → incident → 大脑交叉判定',
    story: '外部通报数据泄露 → ①日志审计定位可疑 IP+时间线 → ②渗透测试验证漏洞入口 → ③威胁情报溯源 → ④应急响应封禁加固 → 大脑交叉确认并出完整报告（计划书 §3.6 场景 1）',
    stages: [
      { domain: 'logaudit',    name: '日志审计：定位可疑 IP + 攻击时间线',          passFindings: false },
      { domain: 'pentest',     name: '渗透测试：验证漏洞入口',                        passFindings: true },
      { domain: 'intel', name: '威胁情报：IP 溯源',                             passFindings: true },
      { domain: 'incident',    name: '应急响应：封禁 + 加固',                          passFindings: true },
    ],
  },
  {
    id: 'attack_chain',
    name: '定向攻击链调查',
    description: 'logaudit → pentest → 判定 → 报告',
    story: '发现 webshell → 日志审计溯源入口攻击链 → 渗透测试复现/验证 → 大脑关联时间线输出攻击链图（计划书 §3.6 场景 2）',
    stages: [
      { domain: 'logaudit', name: '日志审计：溯源入口→横向→外联',                     passFindings: false },
      { domain: 'pentest',  name: '渗透测试：漏洞复现/验证',                           passFindings: true },
    ],
  },
  {
    id: 'new_system_assessment',
    name: '新系统上线评估（并行）',
    description: 'pentest ∥ logaudit → 合规 → 判定 → 报告',
    story: '渗透部件（新系统漏洞）与日志审计部件（历史攻击模式）并行 → 大脑交叉引用"新系统是否暴露历史攻击路径"→ 等保合规扫描（计划书 §3.6 场景 3）',
    stages: [
      { domain: 'pentest',  name: '渗透测试：漏洞面扫描',                              passFindings: false },
      { domain: 'logaudit', name: '日志审计：历史攻击模式匹配（并行）',                 passFindings: false },
    ],
  },
  {
    id: 'red_blue_drill',
    name: '攻防演练（红蓝并行）',
    description: 'pentest(红) ∥ logaudit(蓝) → 实时态势 → 报告',
    story: '红队（渗透部件）与蓝队（日志审计部件）并行 → 大脑实时汇总态势生成报告（计划书 §3.6 场景 4）',
    stages: [
      { domain: 'pentest',  name: '红队：主动进攻面利用',                              passFindings: false },
      { domain: 'logaudit', name: '蓝队：实时审计 + 异常检测（并行）',                  passFindings: false },
    ],
  },
  {
    id: 'pentest_only',
    name: '仅渗透测试',
    description: '单部件：渗透测试',
    story: '仅下发到渗透部件，产出渗透 Finding + 单域报告',
    stages: [
      { domain: 'pentest', name: '渗透测试', passFindings: false },
    ],
  },
  {
    id: 'logaudit_only',
    name: '仅日志审计',
    description: '单部件：日志审计',
    story: '仅下发到日志审计部件，查异常、攻击源、时间线',
    stages: [
      { domain: 'logaudit', name: '日志审计', passFindings: false },
    ],
  },
];

/** 默认任务参数 */
export const DEFAULT_TASK_PARAMS = {
  timeout_s: 1800,
  max_steps: 50,
};
