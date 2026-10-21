/**
 * Web版API代理
 * 为网页版提供直接调用DeepSeek API的代理服务
 * 实现完整的AppBindings接口
 */

import type {
  HistoryMessage,
  Meta,
  ContextInfo,
  BalanceInfo,
  ModelInfo,
  WireEvent,
  TabMeta,
  SessionMeta,
  SettingsView,
  CapabilitiesView,
  ServerView,
  PluginView,
  QuestionAnswer,
  CommandInfo,
  WorkspaceView,
  ProjectNode,
  TopicMeta,
  ContextPanelInfo,
  EffortInfo,
  MemoryView,
  MemorySuggestionsView,
  MemorySuggestion,
  SkillSuggestion,
  FilePreview,
  DirEntry,
  DroppedItem,
  DesktopStartupSettingsView,
  HooksSettingsView,
  HookConfigView,
  ProviderView,
  NetworkView,
  BotSettingsView,
  BotInstallStartResult,
  BotInstallPollResult,
  BotRuntimeStatusView,
  BotConnectionDiagnostic,
  UpdateInfo,
  UpdateDownloadResult,
  PromptHistoryResult,
  SlashArgsResult,
  HistoryPage,
  CheckpointMeta,
  AutoResearchStatusView,
  AutoResearchFindingView,
  AutoResearchEvidenceView,
  MCPToolView,
  MCPServerInput,
  MCPTrustInspectionView,
  MCPCatalogRefreshView,
  SkillsSettingsView,
  CapabilityDiagnosticsReport,
  PluginInstallOptions,
  SubagentProfileInput,
  WorkspaceChangesView,
  GitCommitView,
  GitCommitDetailView,
  ExternalOpenersView,
  JobView,
  WireUsage,
  MemoryDoc,
  MemoryFact,
  MemoryArchive,
} from './types';
import type { InvocationRequest } from './invocationDisplay';
import { settingsStorage } from './settingsStorage';
import { migrateLegacyKeys, readNs, writeNs } from './userScopedStorage';
import { authApi } from './auth';
import {
  answerAggOnAnswer,
  answerAggFlush,
  emptyAnswerAgg,
  type AnswerAggState,
} from './answerAggregator';

// 会结束一个 reasonix answer 段落的帧 kind：出现即 flush 已累积的增量片段（见 onFrame）。
const ANSWER_END_FRAME_KINDS = new Set([
  'tool_call',
  'tool_result',
  'turn_done',
  'task_created',
  'stage_start',
  'stage_finished',
  'report_ready',
]);
// AiSOC 集成：安全运营大脑 API 客户端（严格对齐 docs/frontend-api.md）
import {
  aisocApi,
  generateTaskId,
  generateFindingId,
  createDomainApiClient,
  type CreateTaskInput,
  type TaskDetail,
  type TaskInfo,
  type Finding,
  type ReportDoc,
  type RegistryPart,
  type AgentsStatus,
  type Alarm,
  type AlarmsSummary,
  type MemoryEntryDto,
  type MemoryListResult,
  type ConversationSummaryDto,
  type ConversationMessageDto,
} from './aisoc-api';
import {
  webProjects,
  projectRoot,
  isProjectRoot,
  projectIdFromRoot,
  type WebProject,
  type WebProjectCreateInput,
} from './webProjects';
import { resilientRequest } from './resilientRequest';

// DeepSeek API 配置
// - 浏览器侧：使用同源相对路径 `/deepseek-api/*`，由 Vite dev proxy（开发期）
//   或 Nginx reverse proxy（生产期）转发到 https://api.deepseek.com，绕开 CORS。
// - API Key 和模型名由每个用户在设置面板自行输入，存到 localStorage。
//   服务器侧不保存任何用户的 API Key（多用户共享同一台 VPS 时各自独立）。
const DEEPSEEK_API_BASE = '/deepseek-api';
const DEEPSEEK_API_KEY_FALLBACK = ''; // 不再硬编码到源码；用户必须在前端设置面板输入
const DEEPSEEK_MODEL_DEFAULT = 'deepseek-v4-flash';
const LS_KEY_APIKEY = 'reasonix:web:deepseek_api_key';
const LS_KEY_MODEL = 'reasonix:web:deepseek_model';

/**
 * 附件内联上限（字节）。默认 200KB 防 prompt 膨胀；设备级可调——
 * localStorage `reasonix:web:attachment_inline_max_bytes` 写入十进制字节数后
 * 刷新页面生效（如 524288 = 500KB）。非法值/未设置回退默认。
 */
export const ATTACHMENT_INLINE_MAX_BYTES_DEFAULT = 200_000;
const LS_KEY_ATTACHMENT_INLINE_MAX = 'reasonix:web:attachment_inline_max_bytes';

export function getAttachmentInlineMaxBytes(): number {
  if (typeof localStorage === 'undefined') return ATTACHMENT_INLINE_MAX_BYTES_DEFAULT;
  try {
    const raw = localStorage.getItem(LS_KEY_ATTACHMENT_INLINE_MAX);
    const n = raw ? Number(raw) : NaN;
    return Number.isFinite(n) && n >= 1024 ? Math.floor(n) : ATTACHMENT_INLINE_MAX_BYTES_DEFAULT;
  } catch {
    return ATTACHMENT_INLINE_MAX_BYTES_DEFAULT;
  }
}

export function setAttachmentInlineMaxBytes(bytes: number | null): void {
  if (typeof localStorage === 'undefined') return;
  try {
    if (bytes == null) localStorage.removeItem(LS_KEY_ATTACHMENT_INLINE_MAX);
    else localStorage.setItem(LS_KEY_ATTACHMENT_INLINE_MAX, String(Math.max(1024, Math.floor(bytes))));
  } catch { /* ignore */ }
}

/** 工具：从 localStorage 读字符串（SSR / 无 localStorage 环境返回 fallback） */
function readLS(key: string, fallback: string): string {
  if (typeof localStorage === 'undefined') return fallback;
  try {
    const v = localStorage.getItem(key);
    return v && v.length > 0 ? v : fallback;
  } catch { return fallback; }
}

/** 工具：写 localStorage（异常时静默） */
function writeLS(key: string, value: string): void {
  if (typeof localStorage === 'undefined') return;
  try { localStorage.setItem(key, value); } catch { /* ignore */ }
}

/**
 * DeepSeek API 直接调用类
 * - apiKey / model 在每次请求时从 localStorage 读，方便用户随时切换
 */
class DeepSeekDirectApi {
  private baseUrl: string;

  constructor(baseUrl: string = DEEPSEEK_API_BASE) {
    this.baseUrl = baseUrl;
  }

  /** 当前用户配置的 API Key（来自 localStorage） */
  getApiKey(): string { return readLS(LS_KEY_APIKEY, DEEPSEEK_API_KEY_FALLBACK); }
  /** 设置 API Key（前端设置面板调用） */
  setApiKey(key: string): void { writeLS(LS_KEY_APIKEY, key.trim()); }
  /** 是否已配置 API Key */
  hasApiKey(): boolean { return this.getApiKey().length > 0; }

  /** 当前选择的模型 ID（来自 localStorage） */
  getModel(): string { return readLS(LS_KEY_MODEL, DEEPSEEK_MODEL_DEFAULT); }
  /** 设置模型 ID（前端设置面板调用） */
  setModel(model: string): void { writeLS(LS_KEY_MODEL, model.trim() || DEEPSEEK_MODEL_DEFAULT); }

  async chatCompletion(messages: Array<{ role: string; content: string }>) {
    // 推理模型 (deepseek-v4-flash / deepseek-reasoner) 允许最多 5 分钟
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 300_000);

    try {
      const response = await fetch(`${this.baseUrl}/v1/chat/completions`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${this.getApiKey()}`,
        },
        body: JSON.stringify({
          model: this.getModel(),
          messages,
          temperature: 0.0,
        }),
        signal: controller.signal,
      });

      if (!response.ok) {
        let detail = '';
        try {
          const errBody = await response.text();
          detail = errBody.slice(0, 500);
        } catch { /* ignore */ }
        throw new Error(`DeepSeek API error: ${response.status}${detail ? ` — ${detail}` : ''}`);
      }

      return response.json();
    } catch (error) {
      if (error instanceof Error && error.name === 'AbortError') {
        throw new Error('DeepSeek API request timed out (5 min). The model may be overloaded — please try again.');
      }
      throw error;
    } finally {
      clearTimeout(timeoutId);
    }
  }

  /**
   * Streaming SSE 版本的 chatCompletion（打字机效果）。
   * 对每个收到的 SSE 数据块：
   *   - delta.reasoning_content → onReasoning 增量回调
   *   - delta.content           → onText 增量回调
   * 返回最终拼接的 { reasoning, content } 字符串用于落 history。
   */
  async chatCompletionStream(
    messages: Array<{ role: string; content: string }>,
    onReasoning?: (delta: string) => void,
    onText?: (delta: string) => void,
  ): Promise<{ reasoning: string; content: string; usage?: WireUsage }> {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 600_000);
    let reasoning = '';
    let content = '';
    let usage: WireUsage | undefined;

    try {
      const response = await fetch(`${this.baseUrl}/v1/chat/completions`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${this.getApiKey()}`,
          'Accept': 'text/event-stream',
        },
        body: JSON.stringify({
          model: this.getModel(),
          messages,
          temperature: 0.0,
          stream: true,
        }),
        signal: controller.signal,
      });

      if (!response.ok) {
        let detail = '';
        try {
          const errBody = await response.text();
          detail = errBody.slice(0, 500);
        } catch { /* ignore */ }
        throw new Error(`DeepSeek API error: ${response.status}${detail ? ` — ${detail}` : ''}`);
      }

      if (!response.body) {
        throw new Error('DeepSeek API returned no response body (streaming unavailable)');
      }

      const reader = response.body.getReader();
      const decoder = new TextDecoder('utf-8');
      let buffer = '';

      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        buffer += decoder.decode(value, { stream: true });

        // SSE lines are separated by \n\n
        let sepIdx: number;
        while ((sepIdx = buffer.indexOf('\n\n')) !== -1) {
          const rawChunk = buffer.slice(0, sepIdx);
          buffer = buffer.slice(sepIdx + 2);
          const lines = rawChunk.split('\n');
          for (const line of lines) {
            const trimmed = line.trim();
            if (!trimmed.startsWith('data:')) continue;
            const jsonStr = trimmed.slice(5).trim();
            if (!jsonStr || jsonStr === '[DONE]') continue;
            try {
              const evt = JSON.parse(jsonStr);
              const choice = evt?.choices?.[0];
              const delta = choice?.delta ?? {};

              if (evt.usage) {
                usage = {
                  promptTokens: evt.usage.prompt_tokens ?? 0,
                  completionTokens: evt.usage.completion_tokens ?? 0,
                  totalTokens: evt.usage.total_tokens ?? 0,
                  cacheHitTokens: evt.usage.prompt_cache_hit_tokens ?? 0,
                  cacheMissTokens: evt.usage.prompt_cache_miss_tokens ?? 0,
                  reasoningTokens: evt.usage.reasoning_tokens ?? 0,
                  sessionCacheHitTokens: evt.usage.prompt_cache_hit_tokens ?? 0,
                  sessionCacheMissTokens: evt.usage.prompt_cache_miss_tokens ?? 0,
                };
              }

              if (delta.reasoning_content && typeof delta.reasoning_content === 'string' && delta.reasoning_content) {
                reasoning += delta.reasoning_content;
                try { onReasoning?.(delta.reasoning_content); } catch { /* ignore */ }
              }
              if (delta.content && typeof delta.content === 'string' && delta.content) {
                content += delta.content;
                try { onText?.(delta.content); } catch { /* ignore */ }
              }
            } catch {
              // malformed SSE JSON — skip single chunk, don't fail entire stream
            }
          }
        }
      }
      return { reasoning, content, usage };
    } catch (error) {
      if (error instanceof Error && error.name === 'AbortError') {
        throw new Error('DeepSeek API request timed out (10 min). The model may be overloaded — please try again.');
      }
      throw error;
    } finally {
      clearTimeout(timeoutId);
    }
  }

  async getModels(): Promise<ModelInfo[]> {
    const currentModel = this.getModel();
    try {
      const response = await fetch(`${this.baseUrl}/v1/models`, {
        headers: { 'Authorization': `Bearer ${this.getApiKey()}` },
      });

      if (!response.ok) {
        throw new Error(`DeepSeek API error: ${response.status}`);
      }

      const data = await response.json();
      return data.data.map((model: any) => ({
        ref: `deepseek/${model.id}`,
        provider: 'deepseek',
        model: model.id,
        current: model.id === currentModel,
      }));
    } catch {
      // API 不可用时返回一份默认列表，方便用户在前端切换
      const defaults = ['deepseek-v4-flash', 'deepseek-v4-pro', 'deepseek-chat', 'deepseek-reasoner'];
      return defaults.map(id => ({
        ref: `deepseek/${id}`,
        provider: 'deepseek',
        model: id,
        current: id === currentModel,
      }));
    }
  }
}

/**
 * 完整的Web API代理类
 * 实现所有AppBindings接口方法
 */
export class WebApiProxy {
  private deepSeekApi: DeepSeekDirectApi;
  // 每个 tab 独立维护会话历史，切换/新建 tab 不会清空其他 tab 的历史。
  private histories: Map<string, HistoryMessage[]> = new Map();
  private activeTabId: string = 'web-tab-1';
  private eventListeners: Set<(e: WireEvent) => void> = new Set();
  private tabs: TabMeta[] = [{
    id: 'web-tab-1',
    scope: 'global',
    workspaceRoot: '/',
    workspaceName: 'Web',
    topicId: 'web-topic-1',
    topicTitle: 'Web Chat',
    label: 'Web Chat',
    ready: true,
    running: false,
    mode: 'normal',
    active: true,
    cwd: '/',
  }];
  private settings: SettingsView;
  private nextAttachmentId: number = 1;
  private attachments: Map<string, { name: string; dataUrl: string; bytes?: Uint8Array; serverPath?: string; uploadId?: string; conversationBound?: boolean }> = new Map();

  // 浏览器模式下，reducer compactArchivedToolItems 会在 tool 完成后立即清空 item.output
  // 并把 dataArchived 置 true。ToolCard 展开时通过 app.ToolResultForTab(tabId, id) 拉取完整数据。
  // desktop runtime 有持久化存储；浏览器没有，所以这里维护一个 toolId → {args, output} 的
  // in-memory cache，在 onFrame 的 tool_call / tool_result case 里实时写入，ToolResultForTab
  // 直接读。任务结束清空（避免跨会话泄露）。
  private toolResultCache: Map<string, { args: string; output: string; name: string; updatedAt: number }> = new Map();

  // 手动记忆（MemoryView.facts + docs），localStorage 持久化
  // 每个 tab 当前的流式进度（供 UI 状态条读取，避免把进度数据塞进 WireEvent 破坏兼容）
  private streamStats: Map<string, { receivedChars: number; ttfbMs: number | null; phase: 'idle' | 'waiting_ttfb' | 'streaming' | 'final' }> = new Map();

  // 每个 tab 当前 SSE 连接里最新捕获的 task_id（修复 90秒硬超时后丢失任务上下文问题，
  // catch 分支会用它继续轮询 /api/tasks/<id> 直到状态终态，然后拉报告展示给用户）。
  private _lastStreamTaskId: Map<string, string> = new Map();

  // reasonix answer 帧段落聚合状态（修复"残句冻结 + 完整句另起一条"导致的重复渲染）：
  // answer 帧先累积成完整段落，遇全量帧/终结帧/流结束才 emit 一次 message（见 answerAggregator.ts）。
  private _answerAggByTab: Map<string, AnswerAggState> = new Map();

  // AisocDashboard 流式输出区持久化存储（修复 Bug 1：AisocDashboard 在 viewMode 切换、
  // 或父组件 re-render 时会 unmount/remount，之前的 useState/useRef 都被 GC，丢流式数据。
  // 这里把 items + version 存到 webApiProxy 单例，AisocDashboard remount 时能拉回历史帧，
  // 不会出现"流式输出区只剩一行字符"的残缺态）。
  private _aisocStreamItems: Map<string, { items: unknown[]; version: number }> = new Map();
  private _aisocStreamItemListeners: Set<(streamTabId: string, items: unknown[], version: number) => void> = new Set();

  // 手动记忆（MemoryView.facts + docs），localStorage 持久化
  private memoryState: { docs: MemoryDoc[]; facts: MemoryFact[]; archives: MemoryArchive[] } = {
    docs: [],
    facts: [],
    archives: [],
  };

  // 16 号方案 F1：tabId → 大脑 conversation_id 映射。
  // 收到 conversation_bound 帧时回填并持久化；同 tab 下一轮对话带上，
  // 让消息落库到同一会话（跨刷新续接）。未登录时不产生映射，行为与旧版一致。
  private _conversationIdByTab: Map<string, string> = new Map();

  // 16 号方案 F3：当前 memoryState.facts 中来自服务端 /api/memory 的条目 id 集合。
  // 用于 WriteMemory/DeleteMemory 判定走 PATCH/DELETE 服务端调用还是 localStorage 旧逻辑。
  private _serverMemoryIds: Set<string> = new Set();

  // ==== localStorage keys ====
  // 18 号方案：以下 5 个为用户域 base 键名，实际读写经 userScopedStorage 加 `:{userId|anon}` 命名空间后缀
  private static readonly LS_KEY_HISTORIES = 'reasonix:web:histories';
  private static readonly LS_KEY_TABS = 'reasonix:web:tabs';
  private static readonly LS_KEY_ACTIVE = 'reasonix:web:tab:active';
  private static readonly LS_KEY_MEMORY = 'reasonix:web:memory';
  // 设备级偏好：保持全局键，不命名空间化
  private static readonly LS_KEY_THEME = 'reasonix:web:theme';
  private static readonly LS_KEY_THEME_STYLE = 'reasonix:web:theme-style';
  // 16 号方案 F1：tab → 大脑会话 id 映射（登录用户消息落库 / 跨刷新续接会话）——用户域 base 键
  private static readonly LS_KEY_CONVERSATIONS = 'reasonix:web:conversations';

  constructor() {
    this.deepSeekApi = new DeepSeekDirectApi();
    this.restoreFromStorage();
    if (!this.histories.has(this.activeTabId)) {
      this.histories.set(this.activeTabId, []);
    }
    this.settings = {
      defaultModel: 'deepseek/deepseek-v4-flash',
      plannerModel: '',
      subagentModel: '',
      subagentEffort: 'auto',
      autoPlan: 'off',
      providers: [],
      officialProviders: [],
      providerPresets: [],
      permissions: { mode: 'auto', allow: [], ask: [], deny: [] } as any,
      sandbox: { bash: 'off', network: false, workspaceRoot: '', allowWrite: [], shell: 'auto' } as any,
      network: { httpProxy: '', httpsProxy: '', noProxy: '' } as any,
      agent: { temperature: 0, maxSteps: 0, plannerMaxSteps: 0, systemPrompt: '' } as any,
      bot: {} as any,
      desktopLanguage: '',
      desktopLayoutStyle: 'classic',
      desktopTheme: WebApiProxy.readStoredTheme() ?? 'dark',
      desktopThemeStyle: WebApiProxy.readStoredStyle() ?? 'console',
      closeBehavior: 'quit',
      displayMode: 'standard',
      statusBarStyle: 'icon',
      statusBarItems: [],
      defaultToolApprovalMode: 'auto',
      checkUpdates: false,
      telemetry: false,
      metrics: false,
      memoryCompilerEnabled: false,
      configPath: '',
      providerKinds: ['openai'],
      autoApproveTools: true,
      bypass: false,
    };
  }

  // ==================== 持久化（localStorage）====================

  /** 流结束/终结帧时把尚未 emit 的 answer 增量段落一次发出（见 answerAggregator.ts） */
  private flushPendingAnswer(tabId: string): void {
    const agg = this._answerAggByTab.get(tabId);
    if (!agg || !agg.pending) return;
    const r = answerAggFlush(agg);
    this._answerAggByTab.set(tabId, r.state);
    if (r.emit) this.emitEvent({ kind: 'message', text: r.emit, tabId });
  }

  /** 构造时恢复 tabs/histories/memory。localStorage 不可用时静默回退内存存储 */
  private restoreFromStorage() {
    if (typeof localStorage === 'undefined') return;
    try {
      // 18 号方案：旧全局键 → 当前命名空间的一次性迁移（幂等）
      migrateLegacyKeys();
      const h = readNs<Array<[string, HistoryMessage[]]> | null>(WebApiProxy.LS_KEY_HISTORIES, null);
      if (h) {
        this.histories = new Map(h);
      }
      const t = readNs<TabMeta[] | null>(WebApiProxy.LS_KEY_TABS, null);
      if (t && t.length > 0) {
        this.tabs = t;
      }
      const a = readNs<string | null>(WebApiProxy.LS_KEY_ACTIVE, null);
      if (a && this.tabs.some(tab => tab.id === a)) {
        this.activeTabId = a;
      } else if (this.tabs.length > 0) {
        this.activeTabId = this.tabs.find(tab => tab.active)?.id ?? this.tabs[0].id;
      }
      const m = readNs<{ docs: MemoryDoc[]; facts: MemoryFact[]; archives: MemoryArchive[] } | null>(WebApiProxy.LS_KEY_MEMORY, null);
      if (m) {
        this.memoryState = m;
      }
      // 16 号方案 F1：恢复 tab → conversation 映射（跨刷新续接会话）
      const c = readNs<Array<[string, string]> | null>(WebApiProxy.LS_KEY_CONVERSATIONS, null);
      if (c) {
        this._conversationIdByTab = new Map(c);
      }
    } catch (e) {
      console.warn('[WebApiProxy] restoreFromStorage failed:', e);
    }
  }

  /** 把 tabs + histories + activeTabId + memory 写入 localStorage（当前用户命名空间）。限频 + ignore 异常 */
  private saveToStorage() {
    if (typeof localStorage === 'undefined') return;
    try {
      writeNs(WebApiProxy.LS_KEY_HISTORIES, [...this.histories.entries()]);
      writeNs(WebApiProxy.LS_KEY_TABS, this.tabs);
      writeNs(WebApiProxy.LS_KEY_ACTIVE, this.activeTabId);
      writeNs(WebApiProxy.LS_KEY_MEMORY, this.memoryState);
    } catch (e) {
      console.warn('[WebApiProxy] saveToStorage failed:', e);
    }
  }

  private saveMemoryOnly() {
    if (typeof localStorage === 'undefined') return;
    try {
      writeNs(WebApiProxy.LS_KEY_MEMORY, this.memoryState);
    } catch (e) {
      console.warn('[WebApiProxy] saveMemoryOnly failed:', e);
    }
  }

  /** 16 号方案 F1：只持久化 tab → conversation 映射（conversation_bound 帧到达时调用，高频路径外） */
  private saveConversationsOnly() {
    if (typeof localStorage === 'undefined') return;
    try {
      writeNs(WebApiProxy.LS_KEY_CONVERSATIONS, [...this._conversationIdByTab.entries()]);
    } catch (e) {
      console.warn('[WebApiProxy] saveConversationsOnly failed:', e);
    }
  }

  /** 恢复浏览器模式下持久化的主题偏好（无值返回 null） */
  private static readStoredTheme(): string | null {
    if (typeof localStorage === 'undefined') return null;
    try {
      const v = localStorage.getItem(WebApiProxy.LS_KEY_THEME);
      return v === 'auto' || v === 'light' || v === 'dark' ? v : null;
    } catch {
      return null;
    }
  }

  private static readStoredStyle(): string | null {
    if (typeof localStorage === 'undefined') return null;
    try {
      const v = localStorage.getItem(WebApiProxy.LS_KEY_THEME_STYLE);
      return v && v.trim() ? v : null;
    } catch {
      return null;
    }
  }

  // ==================== 文件引用展开 ====================

  /** 21 号方案：收集本轮输入中已落服务端的附件元数据（name + 服务端相对路径），
   *  随 chat/stream 请求体发出（后端 prompt 只注路径引用，不再内联全文）。
   *  未镜像成功（无 serverPath）的附件不收集，走原有内存内联链路。 */
  private collectServerAttachmentRefs(input: string): Array<{ name: string; path: string }> {
    const displayRefRe = /@\[([^\]]*)\]\(([^)]+)\)/g;
    const normalized = input.replace(displayRefRe, (_m, _name, path) => `@${path}`);
    const refRe = /@([^\s@"']+)/g;
    const out: Array<{ name: string; path: string }> = [];
    const seen = new Set<string>();
    let m: RegExpExecArray | null;
    while ((m = refRe.exec(normalized)) !== null) {
      const att = this.attachments.get(m[1]);
      if (att?.serverPath && !seen.has(att.serverPath)) {
        seen.add(att.serverPath);
        out.push({ name: att.name, path: att.serverPath });
      }
    }
    return out;
  }

  /**
   * 解析用户输入中的 @文件引用，读取本地文件内容并内联展开。
   * 支持格式：
   *   @路径    — workspace引用（Composer生成的 refs 格式）
   *   @[显示名](路径) — attachment显示引用（Composer生成的 displayRefs 格式）
   */
  private async expandFileReferences(input: string): Promise<string> {
    // 1. 先提取 @[name](path) 形式，替换为 @path 占位，统一处理
    const displayRefRe = /@\[([^\]]*)\]\(([^)]+)\)/g;
    const normalized = input.replace(displayRefRe, (_m, _name, path) => `@${path}`);

    // 2. 解析所有 @路径 引用（路径可含空格/中文，直到遇到空白或行尾）
    const refRe = /@([^\s@"']+)/g;
    const refs: Array<{ full: string; path: string }> = [];
    let m: RegExpExecArray | null;
    while ((m = refRe.exec(normalized)) !== null) {
      refs.push({ full: m[0], path: m[1] });
    }
    if (refs.length === 0) return input;

    // 3. 逐个展开：内存附件（web-attachment://）从 Map 读取；工作区路径通过 Vite dev server
    //    中间件 /__workspace_file__?path=xxx 读取（由 vite.config.ts workspaceFileServer() 提供，
    //    直接读文件系统，绕过 SPA fallback）
    const chunks: string[] = [];
    for (const ref of refs) {
      let body = "";
      let truncated = false;
      let isBinary = false;
      let isImage = false;
      let serverPath: string | undefined;
      const displayName = ref.path;
      try {
        const memAtt = this.attachments.get(ref.path);
        if (memAtt) {
          serverPath = memAtt.serverPath;
          // 21 号方案：已绑定会话目录的附件不再内联全文——prompt 只带路径引用，
          // 大脑/部件按路径从共享存储读原始字节（避免 200KB 截断与上下文膨胀）。
          if (memAtt.conversationBound && memAtt.serverPath) {
            const sizeNote = memAtt.bytes && memAtt.bytes.length > 0 ? `（${Math.ceil(memAtt.bytes.length / 1024)} KB）` : "";
            chunks.push(`\n\n[附件] ${memAtt.name} → ${memAtt.serverPath}${sizeNote}，可用工具按路径读取\n`);
            continue;
          }
          // 从内存附件取字节 -> UTF-8 文本
          if (memAtt.bytes && memAtt.bytes.length > 0) {
            const MAX_BYTES = getAttachmentInlineMaxBytes();
            const slice = memAtt.bytes.length > MAX_BYTES ? memAtt.bytes.subarray(0, MAX_BYTES) : memAtt.bytes;
            try {
              body = new TextDecoder("utf-8", { fatal: false }).decode(slice);
            } catch {
              body = "";
              isBinary = true;
            }
            if (memAtt.bytes.length > MAX_BYTES) truncated = true;
          } else if (memAtt.dataUrl.startsWith("data:")) {
            // 没有 bytes 时回退：从 dataUrl 解码
            try {
              const comma = memAtt.dataUrl.indexOf(",");
              const head = comma === -1 ? memAtt.dataUrl : memAtt.dataUrl.slice(0, comma);
              const bodyPart = comma === -1 ? "" : memAtt.dataUrl.slice(comma + 1);
              if (/base64/i.test(head)) {
                const bin = atob(bodyPart);
                const MAX_BYTES = getAttachmentInlineMaxBytes();
                const decoded = bin.length > MAX_BYTES ? bin.slice(0, MAX_BYTES) : bin;
                const buf = new Uint8Array(decoded.length);
                for (let i = 0; i < decoded.length; i++) buf[i] = decoded.charCodeAt(i);
                body = new TextDecoder("utf-8", { fatal: false }).decode(buf);
                if (bin.length > MAX_BYTES) truncated = true;
              } else {
                body = decodeURIComponent(bodyPart);
              }
              if (/^data:(image|video|audio|application\/(pdf|octet|zip|gzip|msdownload)|font)/i.test(head)) {
                isBinary = true;
                if (/^data:image\//i.test(head)) isImage = true;
              }
            } catch {
              body = "";
              isBinary = true;
            }
          }
          if (!body && !isBinary) isBinary = true;
        } else {
          const cleanPath = ref.path.replace(/\\/g, "/");
          const endpoint = `/__workspace_file__?path=${encodeURIComponent(cleanPath)}`;
          const resp = await fetch(endpoint, { method: "GET" });
          if (resp.ok) {
            const contentType = resp.headers.get("content-type") || "";
            const text = await resp.text();
            const MAX_BYTES = getAttachmentInlineMaxBytes();
            if (text.length > MAX_BYTES) {
              body = text.slice(0, MAX_BYTES);
              truncated = true;
            } else {
              body = text;
            }
            isBinary = /^(image|video|audio|application\/(pdf|octet|zip|gzip|msdownload)|font)/i.test(contentType);
            isImage = /^image\//i.test(contentType);
          } else {
            body = `[文件无法读取：${ref.path}（HTTP ${resp.status}）${resp.status === 404 ? "；文件不存在于工作区根目录" : ""}]`;
          }
        }
      } catch (e) {
        body = `[文件读取失败：${e instanceof Error ? e.message : String(e)}]`;
      }

      // 对内容做代码块包裹；二进制/图片类直接跳过展开，保留引用。
      // 图片单独标注：避免模型幻觉"看到了图片内容"（当前 Web 模式无视觉链路）。
      // 19 号方案：附件已镜像到大脑时附服务端副本路径，部件工具可按路径读原始字节。
      const serverNote = serverPath ? `\n[服务端副本: ${serverPath}，部件工具可按此路径读取原始字节]\n` : "";
      if (isBinary || body.length === 0) {
        if (isImage) {
          chunks.push(`\n\n--- 图片附件: ${displayName}（当前 Web 模式不支持图像理解，模型无法看到图片内容，请勿臆测图中信息）---${serverNote}\n`);
        } else {
          chunks.push(`\n\n--- 文件: ${displayName} (二进制/不支持内联) ---${serverNote}\n`);
        }
      } else {
        const ext = displayName.split(".").pop()?.toLowerCase() ?? "";
        const fenceLang = /^(md|markdown|txt|json|yaml|yml|csv|xml|html|css|js|ts|tsx|jsx|py|go|rs|java|c|cpp|h|sh|bash|sql|proto|toml|ini|conf)$/i.test(ext) ? ext : "";
        const warn = truncated ? `\n[注意：文件过大，仅展示前 ${body.length} 字符]\n` : "";
        chunks.push(`\n\n--- 文件: ${displayName} ---\n\`\`\`${fenceLang}\n${body}\n\`\`\`${warn}${serverNote}\n`);
      }
    }

    // 4. 拼接：保留原始输入（去掉 displayRef 包装），在末尾追加展开的文件内容
    // 这样模型既能看到用户原本的问题描述，也能看到文件正文
    const userPrompt = normalized.replace(refRe, "").trim() || input.trim();
    return `${userPrompt}\n\n以下是引用的文件内容：${chunks.join("")}`;
  }

  // ==================== 核心API方法 ====================

  async Submit(input: string): Promise<void> {
    await this.submitForTab(this.activeTabId, input);
  }

  /**
   * AisocDashboard 复用聊天接口：暴露给外部组件，传入自有 tabId 即可触发与聊天一致的流式管线。
   * 区别于 Submit(input)（使用 activeTabId）：这里 tabId 是参数。
   * 走同一套 chatStream + onFrame → emitEvent → onEvent 数据通道，
   * AisocDashboard 通过 onEvent(cb) 订阅后即可用 AssistantMessage / ToolCard 原样渲染（和聊天 Transcript 视觉一致）。
   *
   * @param tabId       - 订阅方 tabId，过滤用（不能与聊天 tab 冲突，建议前缀 `aisoc-task-`）
   * @param input       - 用户消息 / 任务描述
   * @param opts.passThrough - true 透传部件帧（任务流默认 true）
   * @param opts.sessionId   - 前端会话 ID（透传大脑，与部件会话隔离配套）。默认 = tabId。
   *                           同一 tab 内的多个任务共用一个 sessionId → 大脑复用部件会话保留上下文；
   *                           换 tab → 不同 sessionId → 大脑调 /new 清上下文。
   */
  async AisocSubmitForTab(tabId: string, input: string, opts: { passThrough?: boolean; sessionId?: string; pipeline?: string; domain?: string; target?: string } = {}): Promise<void> {
    await this.submitForTab(tabId, input, {
      passThrough: opts.passThrough ?? true,
      sessionId: opts.sessionId ?? tabId,
      pipeline: opts.pipeline,
      domain: opts.domain,
      target: opts.target,
    });
  }

  /**
   * 查 Aisoc 流式 tab 对应的 brain 任务 ID。
   *
   * AisocDashboard 创建任务时用 `aisoc-task-${Date.now()}` 作为临时 tabId（前端 local ID），
   * 后端 chat/stream 接单后会在首个 task_created frame 里推 brain task_id（`T...`）。
   * webApiProxy 内部已经把映射存到 _lastStreamTaskId。这个 getter 暴露给 AisocDashboard，
   * 让"查看详情"按钮能反查 tabId → brain task_id → 再去 tasks 列表里找到对应任务。
   *
   * @returns brain task_id（如 `T20260903-042326499`），未下发则返回 null。
   */
  getBrainTaskIdForStreamTab(streamTabId: string): string | null {
    return this._lastStreamTaskId.get(streamTabId) ?? null;
  }

  /**
   * 返回当前已知的所有 streamTabId（修复 Bug 1）。
   *
   * AisocDashboard mount 时调用本方法获取历史 streamTabId 列表，然后逐个调
   * getAisocStreamItems 拉回持久化的 items + version，恢复 remount 后的流式输出区。
   */
  getKnownStreamTabIds(): string[] {
    return Array.from(this._lastStreamTaskId.keys());
  }

  /**
   * 写入 Aisoc 流式输出区 items（修复 Bug 1）。
   *
   * AisocDashboard.applyWireEvent 每次计算出新 items + version 后调用本方法，
   * webApiProxy 把它们存到单例 _aisocStreamItems，并通过 _aisocStreamItemListeners
   * 通知所有订阅者。AisocDashboard 即使 unmount/remount 也能从单例拉回历史 items。
   */
  setAisocStreamItems(streamTabId: string, items: unknown[], version: number): void {
    this._aisocStreamItems.set(streamTabId, { items, version });
    this._aisocStreamItemListeners.forEach(cb => {
      try { cb(streamTabId, items, version); } catch (e) { console.error('aisoc stream listener error:', e); }
    });
  }

  /**
   * 读取 Aisoc 流式输出区 items（修复 Bug 1）。
   *
   * AisocDashboard mount / remount 时调用本方法拉回持久化的 items + version，
   * 保证 Remount 后流式输出区不会清空（不像之前 useState 那样 unmount 即丢）。
   */
  getAisocStreamItems(streamTabId: string): { items: unknown[]; version: number } | undefined {
    return this._aisocStreamItems.get(streamTabId);
  }

  /**
   * 订阅 Aisoc 流式输出区 items 变化（修复 Bug 1）。
   *
   * 返回取消订阅函数。任何 webApiProxy.setAisocStreamItems 调用都会触发 cb。
   */
  subscribeAisocStreamItems(cb: (streamTabId: string, items: unknown[], version: number) => void): () => void {
    this._aisocStreamItemListeners.add(cb);
    return () => {
      this._aisocStreamItemListeners.delete(cb);
    };
  }

  private async submitForTab(tabId: string, input: string, opts: { passThrough?: boolean; sessionId?: string; pipeline?: string; domain?: string; target?: string; conversationId?: string; projectId?: string } = {}): Promise<void> {
    console.log(`🌐 Web API: Submit to tab=${tabId}, input length=${input.length}`);

    // 用户消息：先落事件，再立即写 history + localStorage（避免网络中断丢用户输入）
    this.emitEvent({ kind: 'text', text: input, tabId });

    // 为 UI 思考动画 + 打字机效果发射事件序列
    this.emitEvent({ kind: 'turn_started', tabId });

    // 重置流式进度（进入等待首字节阶段）
    const requestStartAt = Date.now();
    this.streamStats.set(tabId, { receivedChars: 0, ttfbMs: null, phase: 'waiting_ttfb' });

    const expandedInput = await this.expandFileReferences(input);
      if (expandedInput !== input) {
        console.log('🌐 Web API: Expanded file references, new length:', expandedInput.length);
      }

      const history = this.histories.get(tabId) ?? [];
      const turnBase = history.length;
      // 用户消息先立即落库（避免长时间推理失败丢消息）
      history.push({ role: 'user', content: input, createdAt: Date.now(), checkpointTurn: turnBase + 1 });
      this.histories.set(tabId, history);
      this.saveToStorage();

      console.log('🌐 Web API: Calling AiSOC brain /api/chat/stream ...');

      // 打字机人工节流：把 SSE 返回的 delta 切成 1-2 个字幅小份，逐份 emit，贴近真打字机节奏。
      // 修复：之前每次 onDelta 都创建独立 typewriter 实例（多个 setTimeout 并行），
      // 会出现字符顺序错乱（emit 顺序不等于 SSE 帧顺序）。现在用串行队列：同一时刻只跑一个 chunk，
      // 跑完再处理下一个，保证字符顺序与网络一致。
      const typewriterId = `tw-${tabId}-${Date.now()}`;
      const pendingTimers: Set<ReturnType<typeof setTimeout>> = new Set();
      (this as any)._typewriterTimers = (this as any)._typewriterTimers ?? new Map();
      (this as any)._typewriterTimers.set(typewriterId, pendingTimers);
      const chunkQueue: string[] = [];
      let typewriterRunning = false;

      const pumpTypewriter = (type: 'text' | 'reasoning', runningReasoningRef?: { value: string }) => {
        if (typewriterRunning) return;
        const chunk = chunkQueue.shift();
        if (!chunk) return;
        typewriterRunning = true;
        const codePoints = Array.from(chunk);
        let pos = 0;
        let currentTimer: ReturnType<typeof setTimeout> | null = null;
        const emitOne = () => {
          // 跑完上一帧后清掉上一帧的 timer，避免 pendingTimers 永远增长
          if (currentTimer !== null) {
            pendingTimers.delete(currentTimer);
            currentTimer = null;
          }
          if ((this as any)._typewriterTimers?.get(typewriterId) !== pendingTimers) {
            typewriterRunning = false;
            return;
          }
          // 修复：step ∈ {1,2} 随机，delay 35~65ms，贴近真人打字节奏（之前 8~15ms 太快）。
          const step = 1 + (Math.random() < 0.5 ? 1 : 0);
          const slice = codePoints.slice(pos, pos + step).join('');
          if (!slice) {
            typewriterRunning = false;
            pumpTypewriter(type, runningReasoningRef);
            return;
          }
          pos += step;
          if (type === 'text') {
            this.emitEvent({ kind: 'text', text: slice, tabId });
          } else {
            runningReasoningRef!.value += slice;
            this.emitEvent({ kind: 'reasoning', reasoning: runningReasoningRef!.value, tabId });
          }
          if (pos < codePoints.length) {
            const delay = 35 + Math.floor(Math.random() * 30); // 35~65 ms
            currentTimer = setTimeout(emitOne, delay);
            pendingTimers.add(currentTimer);
          } else {
            // 本 chunk 跑完，调度下一个
            typewriterRunning = false;
            pumpTypewriter(type, runningReasoningRef);
          }
        };
        currentTimer = setTimeout(emitOne, 1);
        pendingTimers.add(currentTimer);
      };

      const scheduleTypewriter = (chunk: string, type: 'text' | 'reasoning', runningReasoningRef?: { value: string }) => {
        if (!chunk) return;
        chunkQueue.push(chunk);
        pumpTypewriter(type, runningReasoningRef);
      };

      const stopTypewriter = () => {
        const timers: Set<number> | undefined = (this as any)._typewriterTimers?.get(typewriterId);
        if (timers) timers.forEach(t => clearTimeout(t));
        (this as any)._typewriterTimers?.delete(typewriterId);
      };

      let hadAnyOutput = false;
      let turnDoneEmitted = false;
      const emitTurnDoneSafe = () => {
        if (!turnDoneEmitted) {
          turnDoneEmitted = true;
          this.emitEvent({ kind: 'turn_done', tabId });
        }
      };
      let finalText = '';

      // 任务持续推帧时只重置“空闲超时”，不限制任务总时长。
      // 修复：原来 IDLE_TIMEOUT_MS=300_000 (5 分钟)，brain 跑长 bash 工具/慢端口扫描时中间可能 5 分钟以上无任何 frame，
      // 达到阈值后前端 abort 把流折断，导致“过了 5 分钟就断开连接”。
      // 改为 3_600_000 (1 小时)，与上游代理 HTTPConnection timeout=3600s 一致；
      // brain 单个部件超时由部件自己控制（超时则后端主动 turn_done），前端不应该替部件踩刹车。
      const IDLE_TIMEOUT_MS = 3_600_000;
      let idleTimer: ReturnType<typeof setTimeout> | null = null;

      try {
        // 修复 Bug：idleTimer 声明在 try 外，finally 可安全清理。
        const abortCtrl = new AbortController();
        const armIdleTimer = () => {
          if (idleTimer) clearTimeout(idleTimer);
          idleTimer = setTimeout(() => abortCtrl.abort(), IDLE_TIMEOUT_MS);
        };
        armIdleTimer(); // 首次启动——若从此再无任何 frame，5 分钟后自动 abort

        // AiSOC 接力流全帧处理（aisoc-docs/07-chat-stream-adaptive-relay.md §5.1）：
        // 后端 chat/stream 在识别为任务意图后会持续透传部件 thinking / tool_call / tool_result /
        // answer 等帧；前端旧实现只读 delta，导致推理过程看不到。现在在 onFrame 里把接力流帧
        // 转换为 reducer 现有事件（reasoning / tool_dispatch / tool_result / phase / notice / message），
        // 不动 useController reducer，复用 Composer 现有渲染逻辑。
        // - tool_call 帧没有 id，需生成稳定 id `aisoc-tool-${tabId}-${taskId}-${counter}`，
        //   让同 task_id 的 tool_result 帧能按 id 合并到 reducer 的 tool card 上。
        let toolCallCounter = 0;
        const lastToolCallIdByTab = new Map<string, string>();
        // 默认走透传模式（pass_through=true）。
        // 2026-09-28 抓流实证：大脑的 07 协议适配器（pass_through=false）会把部件接力帧
        // 的工具数据全部丢失——tool_call.args 恒为 {}、tool_result.output 恒为空串，
        // 导致 bash 卡片只显示一个 "{}" 且永远没有输出（前端无米下炊）。
        // 透传模式下：普通问答大脑返回裸键帧 {reasoning}/{text}/{message}，
        // 任务接力到部件（reasonix serve）时返回 kind 包装帧（含完整 args/增量 output）。
        // aisoc-api.chatStream 的 flush 对两种帧格式均已解析。
        const passThrough = opts.passThrough ?? true;
        // 16 号方案 F1/B3：登录用户带上已绑定的会话 id（消息落库/续接）与记忆召回开关。
        // conversationId 优先取该 tab 已回填的 id，其次用调用方显式传入的。
        // useMemory 直传前端记忆开关（后端 runtime memoryCompilerEnabled 仍是全局闸）。
        const requestConversationId = this._conversationIdByTab.get(tabId) ?? opts.conversationId;
        // 17 号方案：tab 挂在评估项目下（workspaceRoot=project://<id>）时，本轮请求带 project_id，
        // 后端把自动建/续接的会话及任务/发现归属到该项目。项目 target 作为任务目标默认值。
        const tabRoot = this.tabs.find((t) => t.id === tabId)?.workspaceRoot;
        const requestProjectId = opts.projectId
          ?? (isProjectRoot(tabRoot) ? (projectIdFromRoot(tabRoot) ?? undefined) : undefined);
        const requestProject = requestProjectId ? webProjects.getById(requestProjectId) : undefined;
        // 21 号方案：已落服务端会话目录的附件随请求体发元数据（name+path），
        // 后端 prompt 只注路径引用；未上线后端会静默丢弃该字段（Pydantic 忽略未声明字段）。
        const serverAttachments = this.collectServerAttachmentRefs(input);
        const chatStreamPromise = aisocApi.chatStream(expandedInput, {
          signal: abortCtrl.signal,
          passThrough,
          sessionId: opts.sessionId,
          pipeline: opts.pipeline,
          domain: opts.domain,
          target: opts.target ?? requestProject?.target,
          conversationId: requestConversationId,
          useMemory: this.settings.memoryCompilerEnabled,
          projectId: requestProjectId,
          attachments: serverAttachments.length > 0 ? serverAttachments : undefined,
          onDelta: (delta) => {
            hadAnyOutput = true;
            armIdleTimer(); // 收到任何输出都重置空闲计时器（防止长任务被腰斩）
            // 收到首个 delta 时记录 TTFB，并切到 streaming phase；之后累加字符数。
            const stats = this.streamStats.get(tabId);
            if (stats) {
              if (stats.phase === 'waiting_ttfb') {
                stats.ttfbMs = Date.now() - requestStartAt;
                stats.phase = 'streaming';
              }
              stats.receivedChars += delta.length;
            }
            // 修复 Bug【字符级 2x 重复】：在 pass_through=true 模式下，aisocApi.chatStream 会同时调 onDelta 和 onFrame case 'text'，
            // 两个都调会导致同一个字符被切两次走 typewriter → reducer append 累积 2 次 → 出现 "workingworking" "目标目标" 等重复。
            // 这里在透传模式下跳过 typewriter 文本路径（onFrame case 'text' 会负责），但 stats 累加仍保留。
            // pass_through=false 模式（07 协议）下 onDelta 是唯一的文本路径，必须走 typewriter。
            if (passThrough) return;
            scheduleTypewriter(delta, 'text');
          },
          onFrame: (frame) => {
            armIdleTimer(); // 收到任何 frame 都重置空闲计时器（reasoning/tool/turn_done/usage 等同样计活）
            // [DEBUG] 临时抓包：记录所有帧到 window.__debugAllFrames
            if (typeof window !== 'undefined') {
              (window as any).__debugAllFrames = (window as any).__debugAllFrames || [];
              (window as any).__debugAllFrames.push({ kind: frame.kind, frame: JSON.parse(JSON.stringify(frame)), ts: Date.now() });
              if ((window as any).__debugAllFrames.length > 500) (window as any).__debugAllFrames.shift();
            }
            // 修复 Bug 2：pass_through=true 模式下大脑只透传 reasonix 帧，不发 task_created 元事件
            // （看 aisoc-docs/10-chat-stream-原模原样透传.md §3，10 协议透传模式不含 task_created）。
            // 但 reasonix 自己的帧（turn_started/text/reasoning/tool_dispatch/turn_done/...）都带
            // task_id 字段。这里统一记录映射，确保前端 "查看详情" 按钮能反查 tabId → brain task_id。
            if (frame.task_id && tabId) {
              this._lastStreamTaskId.set(tabId, frame.task_id);
            }
            // 段落聚合：reasonix 的 answer 帧是"增量 N 片 + 1 全量（=增量拼接）"，
            // 全量帧与增量之间常夹 tool_call 等帧。此处对明确的段落终结帧先 flush 一次：
            // 把已累积的增量片段作为一条完整 message 发出（避免残句冻结/全量另起一条的重复）。
            // thinking/text/delta/turn_started 等不终结段落（reasonix 可能边想边输出）。
            if (frame.kind !== 'answer' && ANSWER_END_FRAME_KINDS.has(frame.kind)) {
              this.flushPendingAnswer(tabId);
            }
            switch (frame.kind) {
              case 'delta':
                // delta 已在 onDelta 里走 typewriter，不再重复 emit（避免字符双倍）
                break;
              // === 16 号方案 B3：会话绑定与记忆召回帧（登录用户，首条 delta 前下发）===
              case 'conversation_bound':
                // 回填 tab → conversation 映射并持久化：下一轮对话请求体携带 conversation_id，
                // 消息落库到同一会话（跨刷新续接）。未登录时大脑不下发此帧，行为不变。
                if (frame.conversationId) {
                  this._conversationIdByTab.set(tabId, frame.conversationId);
                  this.saveConversationsOnly();
                  // 21 号方案：会话建立后，把此前落在 _pending 的附件绑定进会话目录
                  void this.bindPendingAttachments(frame.conversationId);
                }
                break;
              case 'memory_retrieved':
                // 透明展示"本轮参考了哪些记忆"：转成 notice 事件渲染在回答上方。
                // 无条目（injected=false）不打扰用户。
                if (frame.entries.length > 0) {
                  const preview = frame.entries
                    .slice(0, 2)
                    .map((e) => e.content.length > 40 ? `${e.content.slice(0, 40)}…` : e.content)
                    .join('；');
                  const more = frame.entries.length > 2 ? ` 等 ${frame.entries.length} 条` : '';
                  this.emitEvent({
                    kind: 'notice',
                    level: 'info',
                    text: `🧠 已参考${frame.entries.length > 2 ? '' : ` ${frame.entries.length} 条`}记忆：${preview}${more}`,
                    tabId,
                  });
                }
                break;
              // === 10 协议透传模式 text/turn_started/turn_done（补齐 UI 接线 2026-09-02）===
              // 之前只补齐 reasoning/tool_dispatch/tool_progress/message/usage 等 kind，
              // text/turn_started/turn_done 被遗漏，导致 pass_through=true 时打字机没输入，
              // 用户看到的是 message 一整段直接渲染（"按行换行"），不是逐字打字机。
              case 'text':
                // 透传模式：reasonix 文本增量，等价于 07 的 delta
                // 实测 reasonix 10 协议透传模式下 text 帧的 text 字段是【字符/短语级增量】（实测帧拼接后得到完整文本，但不是累计值）。
                // 走 typewriter 字符级 emit，AisocDashboard reducer case 'text' append 累积得到正确文本。
                scheduleTypewriter(frame.text, 'text');
                break;
              case 'turn_started':
                // 透传模式：reasonix 一轮 turn 开始，发 notice 让用户看到阶段切换
                this.emitEvent({
                  kind: 'notice',
                  level: 'info',
                  text: `▶ turn 开始（${frame.task_id ?? 'unknown'}）`,
                  tabId,
                });
                break;
              case 'turn_done':
                // 透传模式：reasonix 一轮 turn 结束，关闭 typewriter（与 07 answer 后逻辑同构）
                emitTurnDoneSafe();
                break;
              case 'thinking':
                // 部件推理 → emit reasoning 事件，reducer 会追加到 live.reasoning
                this.emitEvent({ kind: 'reasoning', reasoning: frame.thinking, tabId });
                break;
              case 'tool_call': {
                // 生成稳定 id；同 task_id 的 tool_result 帧用相同 id 合并
                toolCallCounter += 1;
                const toolId = `aisoc-tool-${tabId}-${frame.task_id ?? 'unknown'}-${toolCallCounter}`;
                if (frame.task_id) lastToolCallIdByTab.set(`${tabId}:${frame.task_id}:${toolCallCounter}`, toolId);
                // 写入工具结果 cache：tool_call 时只存 args（output 等 tool_result）
                // 注意：args 可能已经是 JSON 字符串（如 '{"command":"whoami"}'），
                // 此时直接使用，不要再 JSON.stringify（否则双重编码导致 subjectOf 取不到 command）。
                const toolArgs = (() => {
                  if (typeof frame.args === 'string') return frame.args;
                  if (frame.args == null) return '';
                  try { return JSON.stringify(frame.args); } catch { return String(frame.args); }
                })();
                this.toolResultCache.set(toolId, { args: toolArgs, output: '', name: frame.tool, updatedAt: Date.now() });
                // emit tool_dispatch 事件，reducer tool_dispatch case 会 upsert tool card (status:running)
                this.emitEvent({
                  kind: 'tool_dispatch',
                  tabId,
                  tool: {
                    id: toolId,
                    name: frame.tool,
                    args: toolArgs,
                    readOnly: false,
                  },
                });
                break;
              }
              case 'tool_result': {
                // 透传模式：frame.toolId 是部件真实 call id（同一 turn 可能并发多个 bash，
                // 必须按 id 精确合并）。07 协议无真实 id，退化为按 task_id + counter 猜最近一张卡；
                // reducer 自身还有"同名 + running"兜底，保证结果不丢。
                let toolId: string | undefined;
                if (typeof (frame as { toolId?: string }).toolId === 'string' && (frame as { toolId?: string }).toolId) {
                  toolId = (frame as { toolId: string }).toolId;
                } else if (frame.task_id) {
                  // 取最近一个属于这个 task_id 的 toolId
                  const key = `${tabId}:${frame.task_id}:`;
                  let latestCounter = -1;
                  for (const k of lastToolCallIdByTab.keys()) {
                    if (k.startsWith(key)) {
                      const n = parseInt(k.slice(key.length), 10);
                      if (Number.isFinite(n) && n > latestCounter) latestCounter = n;
                    }
                  }
                  if (latestCounter >= 0) toolId = lastToolCallIdByTab.get(`${key}${latestCounter}`);
                }
                // 写入工具结果 cache：覆盖 args（tool_call 时已存过，这里刷新）+ 存 output
                const rawOutput = typeof frame.output === 'string' ? frame.output : '';
                const toolOutput = rawOutput.slice(0, 8000); // 防止撑爆 DOM；reducer 仍会 truncate
                // result 帧自带 args（部分调用没有 dispatch，只有 progress+result）：
                // 归一化为字符串，仅在 cache 缺 args 时补齐，不覆盖已有命令。
                const resultArgs = (() => {
                  const a = (frame as { args?: unknown }).args;
                  if (typeof a === 'string') return a;
                  if (a == null) return '';
                  try { return JSON.stringify(a); } catch { return String(a); }
                })();
                const errMsg = typeof frame.exit_code === 'number' && frame.exit_code !== 0 ? `exit_code=${frame.exit_code}` : undefined;
                let emitArgs = '';
                if (toolId) {
                  const existing = this.toolResultCache.get(toolId);
                  emitArgs = existing?.args || resultArgs;
                  this.toolResultCache.set(toolId, {
                    args: emitArgs,
                    output: toolOutput,
                    name: frame.tool,
                    updatedAt: Date.now(),
                  });
                } else {
                  emitArgs = resultArgs;
                }
                this.emitEvent({
                  kind: 'tool_result',
                  tabId,
                  tool: {
                    id: toolId,
                    name: frame.tool,
                    args: emitArgs || undefined,
                    output: toolOutput,
                    err: errMsg,
                    readOnly: false,
                    truncated: rawOutput.length > 8000,
                  },
                });
                break;
              }
              case 'stage_start':
                // 阶段开始 → emit phase 事件，reducer phase case 会插入一条 phase item
                this.emitEvent({ kind: 'phase', text: `[stage] ${frame.stage} 开始`, tabId });
                break;
              case 'stage_finished':
                // 阶段完成 → emit phase 事件
                this.emitEvent({
                  kind: 'phase',
                  text: `[stage] ${frame.stage} ${frame.ok ? '完成' : '失败'}`,
                  tabId,
                });
                break;
              case 'task_created':
                // 任务已下发 → emit notice 事件，reducer notice case 会追加一条 notice item
                this.emitEvent({
                  kind: 'notice',
                  level: 'info',
                  text: `任务 ${frame.task_id} 已下发到 ${frame.domain} 子智能体…`,
                  tabId,
                });
                // 修复：90秒硬超时分支需要 task_id 才能继续轮询任务状态，
                // 这里缓存到类成员 _lastStreamTaskId（按 tabId）。
                if (frame.task_id) {
                  this._lastStreamTaskId.set(tabId, frame.task_id);
                }
                break;
              case 'answer':
                // answer 帧（10 协议透传）→ 段落聚合后 emit message。reducer case message
                // 以 frame.text 覆盖/新建 assistant 消息。
                //
                // 修复历程（2026-09-03 抓流实证）：
                // reasonix 输出一段完整回答 = "增量 N 帧（相邻连续，拼接=完整段）+ 1 全量帧
                // （=增量拼接）"，且 tool_call 常插在增量与全量之间。曾试过两种都失败的方案：
                //   1) "上一帧 text 相同则跳过"的 Map 去重 —— 全量帧 ≠ 最后增量帧，永不命中；
                //   2) 每帧直接 emit —— reducer 覆盖式语义下增量把 assistant 覆盖成残句，
                //      tool_call 插入后全量帧又 push 一条新 assistant → "残句 + 完整句"重复。
                // 现在改为段落聚合：增量帧累积，全量帧（text===累积）或终结帧（tool_call 等，
                // 见 ANSWER_END_FRAME_KINDS + onFrame 入口 flush）到达时只 emit 一次完整段落。
                {
                  const agg = this._answerAggByTab.get(tabId) ?? emptyAnswerAgg();
                  const r = answerAggOnAnswer(agg, frame.text ?? '');
                  this._answerAggByTab.set(tabId, r.state);
                  if (r.emit) this.emitEvent({ kind: 'message', text: r.emit, tabId });
                }
                break;
              case 'report_ready':
                this.emitEvent({
                  kind: 'notice',
                  level: 'info',
                  text: `报告已生成，可通过 /api/tasks/${frame.task_id}/export 下载`,
                  tabId,
                });
                break;
              // === 10 协议透传模式新增 kind（webApiProxy onFrame 接线，补齐数据通道→UI 渲染层）===
              // 上一轮只到 §5 数据通道（types/options/requestBody/flush）就收工，UI 接线未做，
              // 导致 6 个 kind（reasoning/tool_dispatch/tool_progress/message/usage/stream_error）
              // 到前端被静默丢弃。这一轮补齐为 reducer 事件，跟 07 协议同等可见。
              case 'reasoning':
                // 透传模式：reasonix 思考链帧（与 07 thinking 互斥，但 reducer 都吃 reasoning）
                if (frame.text) {
                  this.emitEvent({ kind: 'reasoning', reasoning: frame.text, tabId });
                }
                break;
              case 'tool_dispatch': {
                // 透传模式：reasonix 工具调用开始。frame.tool 是 {id,name,args,readOnly,...}。
                // 复用 tool_call 的稳定 id 策略（toolCallCounter + lastToolCallIdByTab），
                // 让透传模式下产生的 tool_progress / tool_result 能被 reducer tool_result case
                // 合并到同一张 tool card。
                toolCallCounter += 1;
                const tdTool = frame.tool as Record<string, unknown>;
                const tdToolIdRaw = typeof tdTool.id === 'string' ? tdTool.id : '';
                const tdId = tdToolIdRaw || `aisoc-tool-${tabId}-${frame.task_id ?? 'unknown'}-${toolCallCounter}`;
                if (frame.task_id) lastToolCallIdByTab.set(`${tabId}:${frame.task_id}:${toolCallCounter}`, tdId);
                const tdArgs = (() => {
                  if (typeof tdTool.args === 'string') return tdTool.args;
                  if (tdTool.args == null) return '';
                  try { return JSON.stringify(tdTool.args); } catch { return String(tdTool.args ?? ''); }
                })();
                const tdName = typeof tdTool.name === 'string' && tdTool.name ? tdTool.name : 'unknown';
                const tdPartial = tdTool.partial === true;
                // partial 早到帧不应用空 args 覆盖 cache 里可能已有的内容；
                // 完整帧（含 args）到达时才写入命令参数。
                if (tdArgs) {
                  this.toolResultCache.set(tdId, { args: tdArgs, output: this.toolResultCache.get(tdId)?.output ?? '', name: tdName, updatedAt: Date.now() });
                }
                this.emitEvent({
                  kind: 'tool_dispatch',
                  tabId,
                  tool: {
                    id: tdId,
                    name: tdName,
                    args: tdArgs,
                    readOnly: tdTool.readOnly === true,
                    // 透传 partial 标记与 argChars：让 reducer 把"仅名字的早到帧"与随后的
                    // 完整 dispatch 按 id 合并为同一张卡（实测同一 id 会来 partial + full 两帧）。
                    partial: tdPartial || undefined,
                    argChars: typeof tdTool.argChars === 'number' ? tdTool.argChars : undefined,
                  },
                });
                break;
              }
              case 'tool_progress': {
                // 透传模式：reasonix 工具流式 partial 输出（不是最终结果，仍在跑）。
                // 复用 tool_dispatch 留下的 id（在 toolResultCache 里），追加 output 并 emit tool_result(partial=true)，
                // reducer tool_result case 会刷新同一张 tool card 的 output，避免双卡片。
                const tpTool = frame.tool as Record<string, unknown>;
                const tpIdRaw = typeof tpTool.id === 'string' ? tpTool.id : '';
                let tpId: string | undefined = tpIdRaw || undefined;
                if (!tpId && frame.task_id) {
                  // 拿同一 task 最近一个 toolCallCounter 对应的 toolId
                  const key = `${tabId}:${frame.task_id}:`;
                  let latestCounter = -1;
                  for (const k of lastToolCallIdByTab.keys()) {
                    if (k.startsWith(key)) {
                      const n = parseInt(k.slice(key.length), 10);
                      if (Number.isFinite(n) && n > latestCounter) latestCounter = n;
                    }
                  }
                  if (latestCounter >= 0) tpId = lastToolCallIdByTab.get(`${key}${latestCounter}`);
                }
                const tpName = typeof tpTool.name === 'string' && tpTool.name
                  ? tpTool.name
                  : (tpId ? this.toolResultCache.get(tpId)?.name ?? 'unknown' : 'unknown');
                const tpChunk = typeof frame.output === 'string' ? frame.output : '';
                // tool_progress 是增量分片：同一命令的输出会分多条帧推送，
                // 前端必须逐条累积而非覆盖，否则只能看到最后一帧。
                // 在 cache 中累积完整输出，然后 emit 累积后的全文，
                // 这样 reducer 的 tool_result case 安全覆盖也能拿到完整内容。
                let tpAccumulated = tpChunk;
                if (tpId) {
                  const existing = this.toolResultCache.get(tpId);
                  tpAccumulated = (existing?.output ?? '') + tpChunk;
                  this.toolResultCache.set(tpId, {
                    args: existing?.args ?? '',
                    output: tpAccumulated,
                    name: tpName,
                    updatedAt: Date.now(),
                  });
                }
                this.emitEvent({
                  kind: 'tool_result',
                  tabId,
                  tool: {
                    id: tpId,
                    name: tpName,
                    output: tpAccumulated,
                    err: undefined,
                    readOnly: tpTool.readOnly === true,
                    // adapter 侧 output 上限 1000 字符，超出即截断
                    truncated: tpAccumulated.length >= 1000,
                    partial: true,
                  },
                });
                break;
              }
              case 'message':
                // 透传模式：reasonix 一轮 turn 结束时的合并消息（含 reasoning）。
                // 与 07 answer 处理同构——合并 live.text → assistant；reasoning 合并到推理面板。
                if (frame.text) {
                  this.emitEvent({ kind: 'message', text: frame.text, tabId });
                }
                if (frame.reasoning) {
                  this.emitEvent({ kind: 'reasoning', reasoning: frame.reasoning, tabId });
                }
                break;
              case 'usage':
                // 透传模式：token 统计（reasonix usage 帧：prompt_tokens / completion_tokens / total_tokens / reasoning_tokens）
                if (frame.usage && typeof frame.usage === 'object') {
                  const u = frame.usage as Record<string, unknown>;
                  const prompt = typeof u.prompt_tokens === 'number' ? u.prompt_tokens : 0;
                  const completion = typeof u.completion_tokens === 'number' ? u.completion_tokens : 0;
                  const total = typeof u.total_tokens === 'number' ? u.total_tokens : (prompt + completion);
                  const rTokens = typeof (u.completion_tokens_details as Record<string, unknown> | undefined)?.reasoning_tokens === 'number'
                    ? (u.completion_tokens_details as Record<string, unknown>).reasoning_tokens as number
                    : 0;
                  const tokenText = rTokens > 0
                    ? `token 用量：prompt ${prompt} / completion ${completion} (含推理 ${rTokens}) / 总计 ${total}`
                    : `token 用量：prompt ${prompt} / completion ${completion} / 总计 ${total}`;
                  this.emitEvent({
                    kind: 'notice',
                    level: 'info',
                    text: tokenText,
                    tabId,
                  });
                }
                break;
              case 'memory_compiler_stats':
                // 透传模式：reasonix memory_compiler 统计（reasonix 端暂未启用，但接口已留）
                if (frame.memoryCompiler && typeof frame.memoryCompiler === 'object') {
                  this.emitEvent({
                    kind: 'notice',
                    level: 'info',
                    text: `记忆编译器统计：${JSON.stringify(frame.memoryCompiler)}`,
                    tabId,
                  });
                }
                break;
              case 'stream_error':
                // 实证补充：reasonix 错误帧（kind:"stream_error" 或 "error"），以 warn 级别文字提示
                this.emitEvent({
                  kind: 'text',
                  text: `[stream_error] ${frame.err}`,
                  level: 'warn',
                  tabId,
                });
                break;
            }
          },
        });
        // 注：实际空闲超时由 armIdleTimer 控制（每帧 armIdleTimer 续命），timeoutPromise 仅
        // 作为冗余兜底。正常情况下 reasonix 持续推帧，IDLE_TIMEOUT_MS 永远不会到期；
        // 仅在 SSE 僵死且 last frame 已超过 5 分钟时 abort，chatStreamPromise reject 触发 race
        // 立即结算（timedOut 设为 true），走下方 catch 路径的 pollTaskUntilDone 兜底。
        let timedOut = false;
        const timeoutPromise = new Promise<never>((_, reject) => {
          setTimeout(() => {
            timedOut = true;
            abortCtrl.abort();
            reject(new Error(`chatStream 空闲超时（${IDLE_TIMEOUT_MS / 1000}s 内无任何 frame）`));
          }, IDLE_TIMEOUT_MS);
        });
        finalText = await Promise.race([chatStreamPromise, timeoutPromise]).catch((err) => {
          // 超时分支会以 abort 跳过 reader.read()，最终走到这里。但只要收到过 delta，
          // 保留已累加的 receivedChars（streamStats 不会重置），finalText 可能是部分返回。
          if (timedOut) {
            console.warn(`⚠️ Web API: chatStream idle timed out after ${IDLE_TIMEOUT_MS / 1000}s, returning partial text`);
            return '';
          }
          throw err;
        });

        // 等待所有 pending 打字机 tick 跑完（最多 5s 保护），然后再发完整 text/turn_done
        await new Promise<void>((resolve) => {
          const startTs = Date.now();
          const check = () => {
            const timers: Set<number> | undefined = (this as any)._typewriterTimers?.get(typewriterId);
            if (!timers || timers.size === 0 || Date.now() - startTs > 5000) resolve();
            else setTimeout(check, 30);
          };
          check();
        });

        if (!hadAnyOutput && !finalText) {
          throw new Error('大脑聊天接口返回空内容');
        }

        history.push({
          role: 'assistant',
          content: finalText,
          createdAt: Date.now(),
          checkpointTurn: turnBase + 2,
        });
        this.histories.set(tabId, history);

        // 不再 emit kind:'message'(text=finalText) —— 否则 reducer case "message" 会因
        // currentAssistant 已被清空（answer 帧 message 已合并过一次）而走 ensureAssistant
        // 创建新 assistant item，把 reasoning 弄丢。改为依赖：
        //   - answer 帧的 message(text=frame.text) 合并 live 到 assistant（保留完整 reasoning）
        //   - 纯 chat-only 任务靠 reducer turn_done 合并 live.text 到 assistant.text
        // finalText 仍记录到 history（用于回放），但不触发 reducer 重复合并。

        // 兜底：若流在 answer 增量中途结束（无终结帧），把最后一段 flush 出去
        this.flushPendingAnswer(tabId);

        emitTurnDoneSafe();
        this.saveToStorage();
        console.log('✅ Web API: brain chat streamed, final length:', finalText.length);
        // chatStream 完成 → 标记 final；turn_done 后才彻底清掉 stats（让 UI 还能看到最终字符数）
        const okStats = this.streamStats.get(tabId);
        if (okStats) okStats.phase = 'final';
      } catch (error) {
        stopTypewriter();
        console.error('❌ Web API: Error calling brain chat:', error);

        // 修复：前端 SSE 中断不应被误读成“任务失败”。后端可能仍在执行，必须在
        // GET /api/tasks/<id> 进入终态并拉取报告后，才允许 turn_done 把运行标识变成箭头。
        const cachedTaskId = this._lastStreamTaskId.get(tabId);
        const completeFallback = () => {
          const stats = this.streamStats.get(tabId);
          if (stats) stats.phase = 'final';
          this.flushPendingAnswer(tabId); // 兜底 flush 未完成的 answer 段落
          emitTurnDoneSafe();
        };
        if (cachedTaskId) {
          this.emitEvent({
            kind: 'notice',
            level: 'warn',
            text: `⚠️ 前端 SSE 连接已断开（空闲 ${IDLE_TIMEOUT_MS / 1000}s 无响应）\n   但后端任务 ${cachedTaskId} 仍在后台运行，前端将轮询直到完成并自动输出完整报告。`,
            tabId,
          });
          // 轮询期间保持 running=true；仅 completeFallback 会在任务终态/报告写回后结束 turn。
          await this.pollTaskUntilDone(cachedTaskId, tabId, completeFallback);
        } else {
          // 没有 task_id：没有可恢复的后端任务，按失败路径结束。
          this.emitEvent({
            kind: 'text',
            text: `Error: ${error instanceof Error ? error.message : 'Unknown error'}\n\n请确认大脑服务（:6657）已启动。`,
            level: 'warn',
            tabId,
          });
          completeFallback();
        }
      } finally {
        stopTypewriter();
        // 清理空闲计时器，避免组件卸载/重提交后旧 timer 继续走 abort。
        if (idleTimer) { clearTimeout(idleTimer); idleTimer = null; }
        // submit 流程结束，延迟 200ms 清空 stats（让 runTicker 读完最终字符数后再清，避免闪烁）
        setTimeout(() => {
          const cur = this.streamStats.get(tabId);
          if (cur?.phase === 'final') {
            this.streamStats.set(tabId, { receivedChars: 0, ttfbMs: null, phase: 'idle' });
          }
        }, 200);
      }
  }

  /**
   * 轮询后端任务状态（SSE 超时后的只读恢复路径）。
   * - 任务进入终态后拉 /api/reports/<id>，把完整 Markdown 报告写回聊天/实时输出。
   * - onComplete 只在报告已写回（报告拉取失败也会给出明确错误）后调用，避免用户看到
   *   红色“运行中”先变箭头、但最终内容仍未返回的竞态。
   * - 多次调用会按 tabId 停止旧轮询，防止旧任务回调污染当前流式输出。
   */
  private _pollTimers: Map<string, ReturnType<typeof setInterval>> = new Map();

  private async pollTaskUntilDone(taskId: string, tabId: string, onComplete?: () => void): Promise<void> {
    const existing = this._pollTimers.get(tabId);
    if (existing) {
      clearInterval(existing);
      this._pollTimers.delete(tabId);
    }

    const POLL_INTERVAL_MS = 2_000;
    const MAX_POLLS = 900;  // 2s × 900 = 30 分钟上限（防止轮询永远跑下去）

    let polls = 0;
    let finished = false;
    let resolvePoll: (() => void) | undefined;
    const pollCompleted = new Promise<void>((resolve) => { resolvePoll = resolve; });
    const finish = () => {
      if (finished) return;
      finished = true;
      resolvePoll?.();
    };
    const tick = async () => {
      polls += 1;
      try {
        const task = await aisocApi.getTask(taskId);
        const status = task?.status ?? 'unknown';
        const terminal = status === 'completed' || status === 'failed' || status === 'cancelled' || status === 'archived';
        if (terminal) {
          const interval = this._pollTimers.get(tabId);
          if (interval) { clearInterval(interval); this._pollTimers.delete(tabId); }

          const verdictLabel = task?.verdict ? ` (verdict=${task.verdict})` : '';
          this.emitEvent({
            kind: 'notice',
            level: status === 'completed' ? 'info' : 'warn',
            text: `🔚 任务 ${taskId} 后台完成，状态=${status}${verdictLabel}，正在拉报告…`,
            tabId,
          });
          try {
            const reportDoc = await aisocApi.getReport(taskId);
            const report = reportDoc?.report ?? '';
            if (report) {
              // message 会把此前不完整/缺失的实时增量替换为后端最终完整报告。
              const finalReport = `\n\n## 📄 任务 ${taskId} 最终报告\n\n${report}\n`;
              this.emitEvent({ kind: 'message', text: finalReport, tabId });
              // 兜底报告也写进聊天历史；否则页面刷新/重新打开会话时仍只剩实时流中的少量内容。
              const history = this.histories.get(tabId) ?? [];
              history.push({ role: 'assistant', content: finalReport, createdAt: Date.now(), checkpointTurn: history.length + 1 });
              this.histories.set(tabId, history);
              this.saveToStorage();
            } else {
              this.emitEvent({ kind: 'text', text: `\n\n任务 ${taskId} 报告为空`, tabId });
            }
          } catch (reportError) {
            this.emitEvent({
              kind: 'text',
              text: `\n\n[报告拉取失败] ${reportError instanceof Error ? reportError.message : String(reportError)}`,
              level: 'warn',
              tabId,
            });
          }
          finish();
          onComplete?.();
          return;
        }
        if (polls >= MAX_POLLS) {
          const interval = this._pollTimers.get(tabId);
          if (interval) { clearInterval(interval); this._pollTimers.delete(tabId); }
          this.emitEvent({
            kind: 'notice',
            level: 'warn',
            text: `⏱️ 轮询任务 ${taskId} 超 ${MAX_POLLS * POLL_INTERVAL_MS / 1000}s 仍非终态，已停止自动恢复。可稍后重新打开任务详情。`,
            tabId,
          });
          finish();
          onComplete?.();
        }
      } catch (pollError) {
        // 单次网络抖动不终止恢复路径，下一轮继续 GET。
        console.warn(`[pollTaskUntilDone] ${taskId} tick err:`, pollError);
      }
    };

    void tick();
    const interval = setInterval(() => { void tick(); }, POLL_INTERVAL_MS);
    this._pollTimers.set(tabId, interval);
    await pollCompleted;
  }

  async History(): Promise<HistoryMessage[]> {
    return this.histories.get(this.activeTabId) ?? [];
  }

  private historyPageForTab(tabID: string, beforeTurn: number, limit: number): HistoryPage {
    const all = this.histories.get(tabID) ?? [];
    const totalTurns = all.length;
    // beforeTurn = 0 表示从最新开始；> 0 表示加载 checkpointTurn < beforeTurn 的更早消息
    const startIndex = beforeTurn > 0
      ? Math.max(0, all.findIndex(m => (m.checkpointTurn ?? 0) >= beforeTurn))
      : 0;
    // 倒序取 limit 条，再正序返回
    const slice = all.slice(startIndex, startIndex + limit);
    const endTurn = slice.length > 0 ? (slice[slice.length - 1].checkpointTurn ?? slice.length) : 0;
    const startTurn = slice.length > 0 ? (slice[0].checkpointTurn ?? 1) : 0;
    return {
      messages: slice,
      startTurn,
      endTurn,
      totalTurns,
      hasOlder: startIndex + slice.length < totalTurns,
    };
  }

  async Meta(): Promise<Meta> {
    return {
      label: 'AiSOC 大脑',
      ready: true,
      eventChannel: 'agent:event',
      cwd: '/',
      workspaceName: 'Web Chat',
      collaborationMode: 'normal',
      toolApprovalMode: 'auto',
      tokenMode: 'full',
      autoApproveTools: true,
      imageInputEnabled: false,
    };
  }

  async Models(): Promise<ModelInfo[]> {
    return await this.deepSeekApi.getModels();
  }

  async Balance(): Promise<BalanceInfo> {
    return {
      available: true,
      display: 'Web mode (no billing)',
    };
  }

  async ContextUsage(): Promise<ContextInfo> {
    const used = (this.histories.get(this.activeTabId) ?? []).length * 1000;
    return {
      used,
      window: 128000,
      sessionTokens: used,
    };
  }

  async Commands(): Promise<CommandInfo[]> {
    return [
      {
        name: 'help',
        description: 'Show available commands',
        kind: 'builtin',
      },
      {
        name: 'clear',
        description: 'Clear the current session',
        kind: 'builtin',
      },
    ];
  }

  async Capabilities(): Promise<CapabilitiesView> {
    return {
      servers: [],
      skills: [],
      skillRoots: [],
      plugins: [],
    };
  }

  async Settings(): Promise<SettingsView> {
    this.hydrateSettingsFromStorage();
    // 16 号方案 F5：后端 /api/settings/runtime 就绪后作为运行时行为字段权威值。
    // 拉取成功 → 覆盖 localStorage 回填结果；失败 → 静默降级（docs/runtime-settings-api.md Source of Truth 约定）。
    await this.hydrateRuntimeFromBackend();
    return this.settings;
  }

  /**
   * 16 号方案 F5：从大脑拉取运行时行为字段（7 字段）覆盖内存设置。
   * 任何失败（未实现/网络/401）静默忽略，保留 localStorage 回填值，不阻塞设置面板。
   */
  private async hydrateRuntimeFromBackend(): Promise<void> {
    try {
      const rt = await aisocApi.getRuntimeSettings();
      const s = this.settings;
      if (typeof rt.defaultToolApprovalMode === 'string') s.defaultToolApprovalMode = rt.defaultToolApprovalMode;
      if (typeof rt.autoPlan === 'string') s.autoPlan = rt.autoPlan;
      if (typeof rt.memoryCompilerEnabled === 'boolean') s.memoryCompilerEnabled = rt.memoryCompilerEnabled;
      if (typeof rt.subagentEffort === 'string') s.subagentEffort = rt.subagentEffort;
      if (typeof rt.maxSubagentDepth === 'number') s.agent.maxSubagentDepth = rt.maxSubagentDepth;
      if (typeof rt.coldResumePrune === 'boolean') s.agent.coldResumePrune = rt.coldResumePrune;
      if (typeof rt.reasoningLanguage === 'string') s.agent.reasoningLanguage = rt.reasoningLanguage;
    } catch {
      // 静默降级：后端不可达时以 localStorage 值继续
    }
  }

  /**
   * 用 localStorage 持久值回填设置（L1 闭环关键）：
   * - 内存默认值只作为 fallback，持久值优先；
   * - 补齐 agent 缺省字段（maxSubagentDepth / coldResumePrune / reasoningLanguage），
   *   修复 SettingsPanel 因字段缺失导致「两按钮都不选中」的问题。
   */
  private hydrateSettingsFromStorage(): void {
    if (typeof localStorage === 'undefined') return;
    const s = this.settings;
    s.defaultToolApprovalMode = settingsStorage.get<string>('defaultToolApprovalMode', s.defaultToolApprovalMode);
    s.autoPlan = settingsStorage.get<string>('autoPlan', s.autoPlan);
    s.memoryCompilerEnabled = settingsStorage.get<boolean>('memoryCompilerEnabled', s.memoryCompilerEnabled);
    s.displayMode = settingsStorage.get<string>('displayMode', s.displayMode);
    s.desktopLanguage = settingsStorage.get<string>('desktopLanguage', s.desktopLanguage);
    s.closeBehavior = settingsStorage.get<string>('closeBehavior', s.closeBehavior);
    s.statusBarStyle = settingsStorage.get<string>('statusBarStyle', s.statusBarStyle);
    s.statusBarItems = settingsStorage.get<string[]>('statusBarItems', s.statusBarItems);
    s.desktopLayoutStyle = settingsStorage.get<string>('desktopLayoutStyle', s.desktopLayoutStyle);
    s.subagentEffort = settingsStorage.get<string>('subagentEffort', s.subagentEffort);
    s.agent = {
      ...s.agent,
      maxSubagentDepth: settingsStorage.get<number>('agent.maxSubagentDepth', 2),
      coldResumePrune: settingsStorage.get<boolean>('agent.coldResumePrune', true),
      reasoningLanguage: settingsStorage.get<string>('agent.reasoningLanguage', 'auto'),
    };
  }

  // ==================== 平台和窗口方法 ====================

  async Platform(): Promise<string> {
    return navigator.platform || 'web';
  }

  async MinimiseMainWindow(): Promise<void> {
    console.log('Minimise not supported in web');
  }

  async ToggleMaximiseMainWindow(): Promise<void> {
    console.log('Maximise not supported in web');
  }

  async IsMainWindowMaximised(): Promise<boolean> {
    return false;
  }

  async CloseMainWindow(): Promise<void> {
    console.log('Close not supported in web');
  }

  // ==================== 标签页管理方法 ====================

  async ListTabs(): Promise<TabMeta[]> {
    return this.tabs;
  }

  async OpenProjectTab(workspaceRoot: string, topicID: string): Promise<TabMeta> {
    return this.openScopedTab('project', workspaceRoot, topicID);
  }

  async OpenGlobalTab(topicID: string): Promise<TabMeta> {
    return this.openScopedTab('global', '/', topicID);
  }

  /** 服务端会话 id 形如 uuid（树节点点击历史会话）；本地生成的 topic id 走新建分支 */
  private static isServerConversationId(id: string): boolean {
    return /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(id);
  }

  /** 会话标题缓存（ListProjectTree 填充，打开 tab 时读，避免再多一次列表请求） */
  private _conversationTitleById: Map<string, string> = new Map();

  /**
   * 统一的 scoped tab 打开逻辑（17 号方案）：
   * - topicID 是服务端会话 uuid：复用已映射 tab 或新建 + 拉历史消息回填；
   * - 否则：在该 scope 下新建空白会话 tab（项目根必须是 project://<id>）。
   */
  private async openScopedTab(scope: 'project' | 'global', workspaceRoot: string, topicID: string): Promise<TabMeta> {
    const root = scope === 'project' ? workspaceRoot : '/';
    const isServerConv = WebApiProxy.isServerConversationId(topicID);

    // 复用：该会话已经在某个 tab 里打开
    if (isServerConv) {
      const existing = this.tabs.find((t) => this._conversationIdByTab.get(t.id) === topicID);
      if (existing) {
        this.tabs = this.tabs.map((t) => ({ ...t, active: t.id === existing.id }));
        this.activeTabId = existing.id;
        this.saveToStorage();
        return existing;
      }
    }

    const project = scope === 'project' ? webProjects.getByRoot(root) : undefined;
    const workspaceName = scope === 'project'
      ? (project?.name ?? root.split('/').filter(Boolean).pop() ?? root)
      : 'Web';
    const title = isServerConv
      ? (this._conversationTitleById.get(topicID) || '历史会话')
      : '新会话';

    const newTab: TabMeta = {
      id: `tab-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`,
      scope,
      workspaceRoot: root,
      workspaceName,
      topicId: topicID,
      topicTitle: title,
      label: title,
      ready: true,
      running: false,
      mode: 'normal',
      active: true,
      cwd: root,
    };
    this.tabs.push(newTab);
    this.tabs.forEach((t) => { t.active = t.id === newTab.id; });
    this.activeTabId = newTab.id;

    if (isServerConv) {
      this._conversationIdByTab.set(newTab.id, topicID);
      this.saveConversationsOnly();
      this.histories.set(newTab.id, []);
      // 先回填历史消息再返回：调用方随即调 HistoryForTab 播种 reducer，
      // 不能让它拿到空数组（拉取失败时静默保留空会话，不阻断打开）。
      await this.loadConversationHistory(newTab.id, topicID);
    } else {
      this.histories.set(newTab.id, []);
    }
    this.saveToStorage();
    return newTab;
  }

  /** 拉取服务端会话消息并写入 tab 历史（失败静默保留空会话，不阻断打开） */
  private async loadConversationHistory(tabId: string, conversationId: string): Promise<void> {
    if (!aisocApi.hasAuthToken()) return;
    try {
      const res = await aisocApi.getConversationMessages(conversationId);
      const msgs: HistoryMessage[] = (res.items ?? [])
        .slice()
        .sort((a, b) => (a.sequenceNum ?? 0) - (b.sequenceNum ?? 0))
        .map((m: ConversationMessageDto) => ({
          role: m.role,
          content: m.content,
          reasoning: m.reasoning ?? undefined,
          toolName: m.toolName ?? undefined,
          createdAt: m.createdAt ? Date.parse(m.createdAt) || undefined : undefined,
        }));
      this.histories.set(tabId, msgs);
      this.saveToStorage();
    } catch (e) {
      console.warn('[WebApiProxy] loadConversationHistory failed:', conversationId, e);
    }
  }

  async SetActiveTab(tabID: string): Promise<void> {
    this.tabs = this.tabs.map(tab => ({ ...tab, active: tab.id === tabID }));
    this.activeTabId = tabID;
    this.saveToStorage();
  }

  async CloseTab(tabID: string): Promise<void> {
    this.tabs = this.tabs.filter(tab => tab.id !== tabID);
    this.histories.delete(tabID);
    if (this.activeTabId === tabID) {
      this.activeTabId = this.tabs[0]?.id ?? 'web-tab-1';
      if (this.tabs.length === 0) {
        const defaultTab: TabMeta = {
          id: 'web-tab-1',
          scope: 'global',
          workspaceRoot: '/',
          workspaceName: 'Web',
          topicId: `topic-${Date.now()}`,
          topicTitle: 'Web Chat',
          label: 'Web Chat',
          ready: true,
          running: false,
          mode: 'normal',
          active: true,
          cwd: '/',
        };
        this.tabs.push(defaultTab);
        this.histories.set(defaultTab.id, []);
        this.activeTabId = defaultTab.id;
      }
    }
    this.saveToStorage();
  }

  async ReorderTabs(tabIDs: string[]): Promise<void> {
    const tabMap = new Map(this.tabs.map(tab => [tab.id, tab]));
    this.tabs = tabIDs.map(id => tabMap.get(id)).filter(Boolean) as TabMeta[];
    this.saveToStorage();
  }

  // ==================== 会话管理方法 ====================

  async NewSession(): Promise<void> {
    this.histories.set(this.activeTabId, []);
    this.saveToStorage();
    this.emitEvent({ kind: 'text', text: 'New session created' });
  }

  async ClearSession(): Promise<void> {
    this.histories.set(this.activeTabId, []);
    this.saveToStorage();
    this.emitEvent({ kind: 'text', text: 'Session cleared' });
  }

  async ListSessions(): Promise<SessionMeta[]> {
    const now = Date.now();
    const activeHistory = this.histories.get(this.activeTabId) ?? [];
    return [
      {
        path: 'current',
        preview: 'Current Session',
        title: 'Current Session',
        turns: activeHistory.length,
        createdAt: now,
        lastActivityAt: now,
        modTime: now,
        current: true,
        open: true,
      },
    ];
  }

  // ==================== 工作区和项目管理方法（17 号方案 · 方案 B）====================

  async ListWorkspaces(): Promise<WorkspaceView[]> {
    return [];
  }

  /**
   * 左栏项目树（Web 形态）：
   *   项目文件夹（/api/projects，404 时降级 localStorage）
   *     └─ 会话（/api/conversations 按 projectId 归类 + 当前尚未绑定的本地空白 tab）
   *   未归类会话（projectId 为空的服务端会话）→ global_folder
   */
  async ListProjectTree(): Promise<ProjectNode[]> {
    const projects = await webProjects.ensureLoaded();

    // 1) 服务端会话（登录用户）。拉取失败则只有本地 tab 节点。
    let conversations: ConversationSummaryDto[] = [];
    if (aisocApi.hasAuthToken()) {
      try {
        const res = await aisocApi.listConversations({ pageSize: 200 });
        conversations = res.items ?? [];
      } catch {
        conversations = [];
      }
    }
    const serverConvIds = new Set(conversations.map((c) => c.id));
    // 标题缓存供 openScopedTab 使用（避免打开会话时再发一次列表请求）
    conversations.forEach((c) => this._conversationTitleById.set(c.id, c.title || '未命名会话'));

    // 2) 尚未与服务端会话绑定的本地 tab（刚新建还没发消息的会话）
    const localTabs: Array<{ tab: TabMeta; projectId: string | null }> = [];
    for (const tab of this.tabs) {
      const boundCid = this._conversationIdByTab.get(tab.id);
      if (boundCid && serverConvIds.has(boundCid)) continue;
      if (tab.scope === 'project' && isProjectRoot(tab.workspaceRoot)) {
        localTabs.push({ tab, projectId: projectIdFromRoot(tab.workspaceRoot) });
      } else if (tab.scope !== 'project') {
        localTabs.push({ tab, projectId: null });
      }
    }

    const activeTab = this.tabs.find((t) => t.id === this.activeTabId);
    const toMs = (iso?: string | null): number | undefined => {
      if (!iso) return undefined;
      const ms = Date.parse(iso);
      return Number.isFinite(ms) ? ms : undefined;
    };

    const conversationTopicNode = (
      c: ConversationSummaryDto,
      scope: 'project' | 'global',
      root: string | undefined,
    ): ProjectNode => ({
      key: scope === 'project' ? `project:${root ?? ''}:topic:${c.id}` : `global:topic:${c.id}`,
      kind: scope === 'project' ? 'topic' : 'global_topic',
      root,
      topicId: c.id,
      label: c.title || '未命名会话',
      turns: c.messageCount,
      pinned: c.pinned ?? false,
      createdAt: toMs(c.createdAt),
      lastActivityAt: toMs(c.updatedAt),
      running: Boolean(activeTab && this._conversationIdByTab.get(activeTab.id) === c.id && activeTab.running),
      open: Boolean(activeTab && this._conversationIdByTab.get(activeTab.id) === c.id),
    });

    // 3) 项目文件夹
    const nodes: ProjectNode[] = projects
      .filter((p) => (p.status ?? 'active') === 'active')
      .map((p) => {
        const root = projectRoot(p.id);
        const topics = conversations
          .filter((c) => {
            const cid = c.projectId ? (webProjects.resolveId(c.projectId) ?? c.projectId) : null;
            return cid === p.id;
          })
          .map((c) => conversationTopicNode(c, 'project', root));
        // 补入该项目下尚未绑定的本地 tab（避免新会话发第一条消息前在树里消失）
        for (const { tab } of localTabs.filter((x) => x.projectId === p.id)) {
          if (topics.some((n) => n.topicId === tab.topicId)) continue;
          topics.push({
            key: `project:${p.id}:tab:${tab.id}`,
            kind: 'topic',
            root,
            topicId: tab.topicId,
            label: tab.topicTitle || '新会话',
            pinned: false,
            running: Boolean(tab.running),
            open: activeTab?.id === tab.id,
            lastActivityAt: Date.now(),
          });
        }
        topics.sort((a, b) => (b.lastActivityAt ?? 0) - (a.lastActivityAt ?? 0));
        const last = topics[0]?.lastActivityAt ?? toMs(p.updatedAt);
        return {
          key: `project:${p.id}`,
          kind: 'project',
          root,
          label: p.name,
          projectColor: p.color || undefined,
          pinned: p.pinned ?? false,
          children: topics,
          lastActivityAt: last,
        } as ProjectNode;
      });

    // 4) 未归类会话 → 全局文件夹
    const unassigned = conversations.filter((c) => !c.projectId);
    const globalLocalTabs = localTabs.filter((x) => x.projectId === null);
    if (unassigned.length > 0 || globalLocalTabs.length > 0) {
      const children = unassigned.map((c) => conversationTopicNode(c, 'global', undefined));
      for (const { tab } of globalLocalTabs) {
        if (children.some((n) => n.topicId === tab.topicId)) continue;
        children.push({
          key: `global:tab:${tab.id}`,
          kind: 'global_topic',
          topicId: tab.topicId,
          label: tab.topicTitle || '新会话',
          pinned: false,
          running: Boolean(tab.running),
          open: activeTab?.id === tab.id,
          lastActivityAt: Date.now(),
        });
      }
      children.sort((a, b) => (b.lastActivityAt ?? 0) - (a.lastActivityAt ?? 0));
      nodes.push({
        key: 'global:unassigned',
        kind: 'global_folder',
        label: '未归类会话',
        children,
        lastActivityAt: children[0]?.lastActivityAt,
      });
    }

    return nodes;
  }

  /** 新建评估项目（CreateProjectDialog 提交后调用；随后 App 会 SwitchWorkspace + 开空白会话） */
  async CreateProject(input: WebProjectCreateInput): Promise<WebProject> {
    return webProjects.create(input);
  }

  async ContextPanel(tabID: string): Promise<ContextPanelInfo> {
    const used = (this.histories.get(tabID) ?? []).length * 1000;
    return {
      usedTokens: used,
      windowTokens: 128000,
      promptTokens: used,
      completionTokens: 0,
      totalTokens: used,
      reasoningTokens: 0,
      cacheHitTokens: 0,
      cacheMissTokens: used,
      sessionCacheHitTokens: 0,
      sessionCacheMissTokens: used,
      sessionCompletionTokens: 0,
      readFiles: [],
      changedFiles: [],
    };
  }

  // ==================== MCP和插件管理方法 ====================

  async MCPServers(): Promise<ServerView[]> {
    return [];
  }

  async Plugins(): Promise<PluginView[]> {
    return [];
  }

  // ==================== 心跳方法 ====================

  async HeartbeatListTasks(): Promise<unknown> {
    return [];
  }

  async HeartbeatReloadTasks(): Promise<unknown> {
    return [];
  }

  async HeartbeatSaveTasks(tasks: unknown): Promise<void> {
    console.log('Heartbeat tasks saved:', tasks);
  }

  async HeartbeatTriggerNow(id: string): Promise<void> {
    console.log('Heartbeat triggered:', id);
  }

  async HeartbeatGenerateID(): Promise<string> {
    return `heartbeat-${Date.now()}`;
  }

  // ==================== 模型和设置方法 ====================

  async SetModel(name: string): Promise<void> {
    // 兼容 EduShield 桌面端的 ref 格式 "deepseek/deepseek-v4-flash"，
    // 提取最后一段作为 DeepSeek API 的 model id
    const modelId = name.includes('/') ? name.split('/').pop()! : name;
    this.deepSeekApi.setModel(modelId);
    this.settings.defaultModel = name;
  }

  /**
   * 设置 DeepSeek API Key（前端设置面板调用）。
   * Key 只写入当前浏览器的 localStorage，不上传到服务器，
   * 多用户共享同一台 VPS 时各自独立。
   */
  async SetApiKey(key: string): Promise<void> {
    this.deepSeekApi.setApiKey(key);
  }

  /** 返回当前 API Key 是否已配置（不返回明文，避免泄露到 UI 日志） */
  async HasApiKey(): Promise<boolean> {
    return this.deepSeekApi.hasApiKey();
  }

  /** 返回 API Key 的掩码字符串（前 6 位 + **** + 后 4 位），用于 UI 展示 */
  async GetApiKeyMasked(): Promise<string> {
    const k = this.deepSeekApi.getApiKey();
    if (!k) return '';
    if (k.length <= 12) return '****';
    return `${k.slice(0, 6)}****${k.slice(-4)}`;
  }

  /** 返回当前选中的模型 id（前端设置面板用） */
  async GetCurrentModel(): Promise<string> {
    return this.deepSeekApi.getModel();
  }

  async Effort(): Promise<EffortInfo> {
    return {
      supported: true,
      current: 'auto',
      default: 'auto',
      levels: ['auto', 'low', 'medium', 'high'],
    };
  }

  async SetEffort(level: string): Promise<void> {
    console.log('Effort set to:', level);
  }

  async Memory(): Promise<MemoryView> {
    // 16 号方案 F3：登录用户以服务端 /api/memory 为数据源（localStorage 仅作缓存快照与降级兜底）。
    // 拉取失败（网络/未登录/401）时静默降级到 memoryState 现值，不阻塞面板。
    if (aisocApi.hasAuthToken()) {
      await this.loadServerMemoryIntoState();
    }
    return {
      docs: this.memoryState.docs,
      facts: this.memoryState.facts,
      archives: this.memoryState.archives,
      scopes: [
        { scope: 'user', path: 'web://memory/user' },
        { scope: 'project', path: 'web://memory/project' },
      ],
      storeDir: aisocApi.hasAuthToken() ? 'server://memory' : 'web://memory',
      available: true,
    };
  }

  /**
   * 16 号方案 F3：拉取服务端长期记忆并适配为 MemoryFact 写入 memoryState.facts。
   * 映射：name=条目 id（删除/更新用它定位）、title=content 截断、description/body=content、
   * type=后端 type（fact/preference/goal/entity/skill）。
   * 返回是否成功；失败时保留 memoryState 现值（localStorage 降级）。
   */
  private async loadServerMemoryIntoState(): Promise<boolean> {
    try {
      const res: MemoryListResult = await aisocApi.listMemory({ pageSize: 200 });
      const facts: MemoryFact[] = (res.items ?? []).map((e: MemoryEntryDto) => ({
        name: e.id,
        title: e.content.length > 30 ? `${e.content.slice(0, 30)}…` : e.content,
        description: e.content,
        type: e.type || 'user',
        body: e.content,
      }));
      this.memoryState.facts = facts;
      this._serverMemoryIds = new Set((res.items ?? []).map((e) => e.id));
      this.saveMemoryOnly();
      return true;
    } catch {
      // 未登录 / 网络失败 / 401：保留现有 localStorage 数据（F3 纪律：在线验证通过前不删本地兜底）
      return false;
    }
  }

  async MemorySuggestions(): Promise<MemorySuggestionsView> {
    const memories: MemorySuggestion[] = this.memoryState.facts.map((f, i) => ({
      id: `mem-suggest-${Date.now()}-${i}`,
      name: f.name,
      title: f.title ?? f.name,
      description: f.description,
      type: f.type,
      body: f.body,
      reason: '已保存的记忆项',
      evidence: [],
    }));
    return {
      memories,
      skills: [],
      generatedAt: new Date().toISOString(),
      available: true,
      source: 'web',
    };
  }

  // ==================== 控制方法 ====================

  async Cancel(): Promise<void> {
    this.emitEvent({
      kind: 'text',
      text: 'Request cancelled',
    });
  }

  async Approve(id: string, allow: boolean, _session: boolean = false, _persist: boolean = false): Promise<void> {
    console.log(`Approval ${id}: ${allow ? 'approved' : 'rejected'}`);
  }

  async AnswerQuestion(id: string, answers: QuestionAnswer[]): Promise<void> {
    console.log(`Question ${id} answered:`, answers);
  }

  async ReplayPendingPrompts(): Promise<void> {
    console.log('Replaying pending prompts');
  }

  async SetPlanMode(on: boolean): Promise<void> {
    console.log(`Plan mode: ${on ? 'enabled' : 'disabled'}`);
  }

  async SetMode(mode: string): Promise<void> {
    console.log('Mode set to:', mode);
  }

  async SetAutoApproveTools(on: boolean): Promise<void> {
    this.settings.autoApproveTools = on;
  }

  // ==================== 通用占位方法 ====================

  private async placeholderMethod(methodName: string, ...args: unknown[]): Promise<any> {
    console.log(`🌐 Web API: ${methodName} called with args:`, args);
    return undefined;
  }

  // 为所有其他方法提供占位符实现
  async SubmitToTab(tabID: string, input: string): Promise<void> { return this.submitForTab(tabID, input); }
  async SubmitDisplay(_display: string, input: string): Promise<void> { return this.placeholderMethod('SubmitDisplay', _display, input); }
  async SubmitDisplayToTab(tabID: string, _display: string, input: string): Promise<void> { return this.submitForTab(tabID, input); }
  async SubmitDeliveryRecoveryToTab(tabID: string, _display: string, input: string): Promise<void> { return this.placeholderMethod('SubmitDeliveryRecoveryToTab', tabID, _display, input); }
  async SubmitInvocationsToTab(tabID: string, display: string, input: string, invocations: InvocationRequest[]): Promise<void> { return this.placeholderMethod('SubmitInvocationsToTab', tabID, display, input, invocations); }
  async SubmitEditedDisplayToTab(tabID: string, display: string, input: string, original: string): Promise<void> { return this.placeholderMethod('SubmitEditedDisplayToTab', tabID, display, input, original); }
  async RunShell(command: string): Promise<void> { return this.placeholderMethod('RunShell', command); }
  async RunShellForTab(tabID: string, command: string): Promise<void> { return this.placeholderMethod('RunShellForTab', tabID, command); }
  async Steer(text: string): Promise<void> { return this.placeholderMethod('Steer', text); }
  async SteerForTab(tabID: string, text: string): Promise<void> { return this.placeholderMethod('SteerForTab', tabID, text); }
  async CancelTab(tabID: string): Promise<void> { return this.placeholderMethod('CancelTab', tabID); }
  async ApproveTab(tabID: string, id: string, allow: boolean, session: boolean, persist: boolean): Promise<void> { return this.placeholderMethod('ApproveTab', tabID, id, allow, session, persist); }
  async AnswerQuestionForTab(tabID: string, id: string, answers: QuestionAnswer[]): Promise<void> { return this.placeholderMethod('AnswerQuestionForTab', tabID, id, answers); }
  async SetModeForTab(tabID: string, mode: string): Promise<string[] | void> { return this.placeholderMethod('SetModeForTab', tabID, mode); }
  async SetCollaborationMode(mode: string): Promise<void> { return this.placeholderMethod('SetCollaborationMode', mode); }
  async SetCollaborationModeForTab(tabID: string, mode: string): Promise<void> { return this.placeholderMethod('SetCollaborationModeForTab', tabID, mode); }
  async SetToolApprovalMode(mode: string): Promise<void> { return this.placeholderMethod('SetToolApprovalMode', mode); }
  async SetToolApprovalModeForTab(tabID: string, mode: string): Promise<string[] | void> { return this.placeholderMethod('SetToolApprovalModeForTab', tabID, mode); }
  async SetGoal(goal: string): Promise<void> { return this.placeholderMethod('SetGoal', goal); }
  async SetGoalForTab(tabID: string, goal: string): Promise<void> { return this.placeholderMethod('SetGoalForTab', tabID, goal); }
  async ResumeGoalForTab(tabID: string): Promise<boolean> { return this.placeholderMethod('ResumeGoalForTab', tabID); }
  async ClearGoal(): Promise<void> { return this.placeholderMethod('ClearGoal'); }
  async ClearGoalForTab(tabID: string): Promise<void> { return this.placeholderMethod('ClearGoalForTab', tabID); }
  async Compact(): Promise<void> { return this.placeholderMethod('Compact'); }
  async CompactForTab(tabID: string): Promise<void> { return this.placeholderMethod('CompactForTab', tabID); }
  async NewSessionForTab(tabID: string): Promise<void> {
    this.histories.set(tabID, []);
    this.activeTabId = tabID;
    this.saveToStorage();
  }
  async ClearSessionForTab(tabID: string): Promise<void> {
    this.histories.set(tabID, []);
    this.saveToStorage();
  }
  async HistoryForTab(tabID: string): Promise<HistoryMessage[]> {
    return this.histories.get(tabID) ?? [];
  }
  async HistoryPage(beforeTurn: number, limit: number): Promise<HistoryPage> {
    return this.historyPageForTab(this.activeTabId, beforeTurn, limit);
  }
  async HistoryPageForTab(tabID: string, beforeTurn: number, limit: number): Promise<HistoryPage> {
    return this.historyPageForTab(tabID, beforeTurn, limit);
  }
  async HistoryCheckpointTurnsForTab(tabID: string): Promise<number[]> { return this.placeholderMethod('HistoryCheckpointTurnsForTab', tabID); }
  async Checkpoints(): Promise<CheckpointMeta[]> { return this.placeholderMethod('Checkpoints'); }
  async CheckpointsForTab(tabID: string): Promise<CheckpointMeta[]> { return this.placeholderMethod('CheckpointsForTab', tabID); }
  async Rewind(turn: number, scope: string): Promise<void> { return this.placeholderMethod('Rewind', turn, scope); }
  async RewindForTab(tabID: string, turn: number, scope: string): Promise<void> { return this.placeholderMethod('RewindForTab', tabID, turn, scope); }
  async Fork(turn: number): Promise<TabMeta> { return this.placeholderMethod('Fork', turn); }
  async ForkForTab(tabID: string, turn: number): Promise<TabMeta> { return this.placeholderMethod('ForkForTab', tabID, turn); }
  async SummarizeFrom(turn: number): Promise<void> { return this.placeholderMethod('SummarizeFrom', turn); }
  async SummarizeFromForTab(tabID: string, turn: number): Promise<void> { return this.placeholderMethod('SummarizeFromForTab', tabID, turn); }
  async SummarizeUpTo(turn: number): Promise<void> { return this.placeholderMethod('SummarizeUpTo', turn); }
  async SummarizeUpToForTab(tabID: string, turn: number): Promise<void> { return this.placeholderMethod('SummarizeUpToForTab', tabID, turn); }
  async ListTrashedSessions(): Promise<SessionMeta[]> { return this.placeholderMethod('ListTrashedSessions'); }
  async ResumeSession(path: string): Promise<HistoryMessage[]> { return this.placeholderMethod('ResumeSession', path); }
  async ResumeSessionForTab(tabID: string, path: string): Promise<HistoryMessage[]> { return this.placeholderMethod('ResumeSessionForTab', tabID, path); }
  async ResumeSessionPage(path: string, limit: number): Promise<HistoryPage> { return this.placeholderMethod('ResumeSessionPage', path, limit); }
  async ResumeSessionPageForTab(tabID: string, path: string, limit: number): Promise<HistoryPage> { return this.placeholderMethod('ResumeSessionPageForTab', tabID, path, limit); }
  async OpenChannelSessionForTab(tabID: string, path: string): Promise<HistoryMessage[]> { return this.placeholderMethod('OpenChannelSessionForTab', tabID, path); }
  async OpenChannelSessionPageForTab(tabID: string, path: string, limit: number): Promise<HistoryPage> { return this.placeholderMethod('OpenChannelSessionPageForTab', tabID, path, limit); }
  async PreviewSession(path: string): Promise<HistoryMessage[]> { return this.placeholderMethod('PreviewSession', path); }
  async DeleteSession(path: string): Promise<void> { return this.placeholderMethod('DeleteSession', path); }
  async DeleteRecoveryCopy(path: string): Promise<void> { return this.placeholderMethod('DeleteRecoveryCopy', path); }
  async RestoreSession(path: string): Promise<void> { return this.placeholderMethod('RestoreSession', path); }
  async PurgeTrashedSession(path: string): Promise<void> { return this.placeholderMethod('PurgeTrashedSession', path); }
  async PurgeRecoveryCopy(path: string): Promise<void> { return this.placeholderMethod('PurgeRecoveryCopy', path); }
  async RenameSession(path: string, title: string): Promise<void> { return this.placeholderMethod('RenameSession', path, title); }
  async ScanPromptHistory(nonce: string): Promise<PromptHistoryResult> { return this.placeholderMethod('ScanPromptHistory', nonce); }
  async PickWorkspace(): Promise<string> {
    // Web 无原生目录选择器：App 层在浏览器模式直接弹 CreateProjectDialog，不会走到这里。
    // 兜底返回空串（上层 switchFolder 按"未选择"处理，不刷新）。
    return '';
  }

  async SwitchWorkspace(path: string): Promise<string> {
    // 17 号方案：切换"当前评估项目"（影响默认新建会话归属与目标默认值）
    if (isProjectRoot(path)) {
      const id = projectIdFromRoot(path);
      if (id) webProjects.setActive(id);
    }
    return path;
  }

  async RemoveWorkspace(path: string): Promise<void> {
    if (!isProjectRoot(path)) return;
    const id = projectIdFromRoot(path);
    if (!id) return;
    // 先关闭该项目下的全部 tab（含会话映射），再删项目
    const projectTabIds = this.tabs
      .filter((t) => t.scope === 'project' && projectIdFromRoot(t.workspaceRoot) === id)
      .map((t) => t.id);
    for (const tabId of projectTabIds) {
      this._conversationIdByTab.delete(tabId);
      await this.CloseTab(tabId);
    }
    this.saveConversationsOnly();
    await webProjects.remove(id);
  }
  async ContextUsageForTab(_tabID: string): Promise<ContextInfo> { return this.ContextUsage(); }
  async BalanceForTab(_tabID: string): Promise<BalanceInfo> { return this.Balance(); }
  async Jobs(): Promise<JobView[]> { return this.placeholderMethod('Jobs'); }
  async JobsForTab(tabID: string): Promise<JobView[]> { return this.placeholderMethod('JobsForTab', tabID); }
  async ToolResultForTab(_tabID: string, toolID: string): Promise<{ args: string; output: string } | null> {
      // 浏览器模式：直接从 in-memory cache 读。reducer compactArchivedToolItems 会把
      // item.output 清掉，所以 ToolCard 展开时拿不到 data。这里在 onFrame 的 tool_call / tool_result
      // case 里已经实时写入了 cache。找不到返回 null（与 desktop runtime 语义一致）。
      const entry = this.toolResultCache.get(toolID);
      if (!entry) return null;
      return { args: entry.args, output: entry.output };
    }
  async MetaForTab(_tabID: string): Promise<Meta> { return this.Meta(); }
  async AutoResearchCurrent(): Promise<AutoResearchStatusView> { return this.placeholderMethod('AutoResearchCurrent'); }
  async AutoResearchStatus(tabID: string): Promise<AutoResearchStatusView> { return this.placeholderMethod('AutoResearchStatus', tabID); }
  async AutoResearchList(tabID: string): Promise<AutoResearchStatusView[]> { return this.placeholderMethod('AutoResearchList', tabID); }
  async AutoResearchFindings(tabID: string, limit: number): Promise<AutoResearchFindingView[]> { return this.placeholderMethod('AutoResearchFindings', tabID, limit); }
  async AutoResearchOpenTask(tabID: string): Promise<void> { return this.placeholderMethod('AutoResearchOpenTask', tabID); }
  async AutoResearchRecordEvidence(tabID: string, criterionID: string, input: AutoResearchEvidenceView): Promise<void> { return this.placeholderMethod('AutoResearchRecordEvidence', tabID, criterionID, input); }
  async InspectMCPTrust(name: string): Promise<MCPTrustInspectionView> { return this.placeholderMethod('InspectMCPTrust', name); }
  async SetMCPTrust(name: string, decision: "session" | "workspace" | "revoke"): Promise<void> { return this.placeholderMethod('SetMCPTrust', name, decision); }
  async RefreshMCPCatalog(): Promise<MCPCatalogRefreshView> { return this.placeholderMethod('RefreshMCPCatalog'); }
  async SkillsSettings(): Promise<SkillsSettingsView> { return this.placeholderMethod('SkillsSettings'); }
  async CapabilityDiagnostics(includeSessionRuntime: boolean): Promise<CapabilityDiagnosticsReport> { return this.placeholderMethod('CapabilityDiagnostics', includeSessionRuntime); }
  async PlanPluginInstall(source: string, options: PluginInstallOptions): Promise<string> { return this.placeholderMethod('PlanPluginInstall', source, options); }
  async InstallPlugin(source: string, options: PluginInstallOptions): Promise<string> { return this.placeholderMethod('InstallPlugin', source, options); }
  async RemovePlugin(name: string): Promise<void> { return this.placeholderMethod('RemovePlugin', name); }
  async SetPluginEnabled(name: string, enabled: boolean): Promise<void> { return this.placeholderMethod('SetPluginEnabled', name, enabled); }
  async UpdatePlugin(name: string): Promise<string> { return this.placeholderMethod('UpdatePlugin', name); }
  async PluginDoctor(name: string): Promise<PluginView> { return this.placeholderMethod('PluginDoctor', name); }
  async AddMCPServer(input: MCPServerInput): Promise<number> { return this.placeholderMethod('AddMCPServer', input); }
  async UpdateMCPServer(name: string, input: MCPServerInput): Promise<void> { return this.placeholderMethod('UpdateMCPServer', name, input); }
  async RemoveMCPServer(name: string): Promise<void> { return this.placeholderMethod('RemoveMCPServer', name); }
  async ReconnectMCPServer(name: string): Promise<void> { return this.placeholderMethod('ReconnectMCPServer', name); }
  async ClearMCPServerAuthentication(name: string): Promise<void> { return this.placeholderMethod('ClearMCPServerAuthentication', name); }
  async PickSkillFolder(): Promise<string> { return this.placeholderMethod('PickSkillFolder'); }
  async PickPluginFolder(): Promise<string> { return this.placeholderMethod('PickPluginFolder'); }
  async AddSkillPath(path: string): Promise<void> { return this.placeholderMethod('AddSkillPath', path); }
  async RemoveSkillPath(path: string): Promise<void> { return this.placeholderMethod('RemoveSkillPath', path); }
  async RefreshSkills(): Promise<void> { return this.placeholderMethod('RefreshSkills'); }
  async ReloadCommands(): Promise<void> { return this.placeholderMethod('ReloadCommands'); }
  async SetSkillEnabled(name: string, enabled: boolean): Promise<void> { return this.placeholderMethod('SetSkillEnabled', name, enabled); }
  async AvailableSubagentTools(): Promise<MCPToolView[]> { return this.placeholderMethod('AvailableSubagentTools'); }
  async CreateSubagentProfile(input: SubagentProfileInput): Promise<string> { return this.placeholderMethod('CreateSubagentProfile', input); }
  async UpdateSubagentProfile(name: string, scope: string, input: SubagentProfileInput): Promise<void> { return this.placeholderMethod('UpdateSubagentProfile', name, scope, input); }
  async DeleteSubagentProfile(name: string, scope: string): Promise<void> { return this.placeholderMethod('DeleteSubagentProfile', name, scope); }
  async SetSubagentProfileModel(name: string, ref: string): Promise<void> { return this.placeholderMethod('SetSubagentProfileModel', name, ref); }
  async SetSubagentProfileEffort(name: string, level: string): Promise<void> { return this.placeholderMethod('SetSubagentProfileEffort', name, level); }
  async TrySubagentProfile(input: SubagentProfileInput, task: string): Promise<string> { return this.placeholderMethod('TrySubagentProfile', input, task); }
  async CancelTrySubagentProfile(): Promise<void> { return this.placeholderMethod('CancelTrySubagentProfile'); }
  async SetMCPServerEnabled(name: string, enabled: boolean): Promise<void> { return this.placeholderMethod('SetMCPServerEnabled', name, enabled); }
  async SetMCPServerTier(name: string, tier: string): Promise<void> { return this.placeholderMethod('SetMCPServerTier', name, tier); }
  async SlashArgs(input: string): Promise<SlashArgsResult> { return this.placeholderMethod('SlashArgs', input); }
  async ListDir(rel: string): Promise<DirEntry[]> { return this.placeholderMethod('ListDir', rel); }
  async ListDirForTab(tabID: string, rel: string): Promise<DirEntry[]> { return this.placeholderMethod('ListDirForTab', tabID, rel); }
  async SearchFileRefs(query: string): Promise<DirEntry[]> { return this.placeholderMethod('SearchFileRefs', query); }
  async SearchFileRefsForTab(tabID: string, query: string): Promise<DirEntry[]> { return this.placeholderMethod('SearchFileRefsForTab', tabID, query); }
  async ReadFile(rel: string): Promise<FilePreview> { return this.placeholderMethod('ReadFile', rel); }
  async ReadFileForTab(tabID: string, rel: string): Promise<FilePreview> { return this.placeholderMethod('ReadFileForTab', tabID, rel); }
  async WorkspaceChanges(tabID: string): Promise<WorkspaceChangesView> { return this.placeholderMethod('WorkspaceChanges', tabID); }
  async GitBranches(): Promise<string[]> { return this.placeholderMethod('GitBranches'); }
  async GitCheckout(branch: string): Promise<void> { return this.placeholderMethod('GitCheckout', branch); }
  async WorkspaceGitHistory(tabID: string, path: string): Promise<GitCommitView[]> { return this.placeholderMethod('WorkspaceGitHistory', tabID, path); }
  async WorkspaceGitCommitDetail(tabID: string, hash: string, path: string): Promise<GitCommitDetailView> { return this.placeholderMethod('WorkspaceGitCommitDetail', tabID, hash, path); }
  async OpenWorkspacePath(rel: string): Promise<void> { return this.placeholderMethod('OpenWorkspacePath', rel); }
  async OpenWorkspacePathForTab(tabID: string, rel: string): Promise<void> { return this.placeholderMethod('OpenWorkspacePathForTab', tabID, rel); }
  async ExternalOpeners(): Promise<ExternalOpenersView> { return this.placeholderMethod('ExternalOpeners'); }
  async SetPreferredExternalOpener(id: string): Promise<void> { return this.placeholderMethod('SetPreferredExternalOpener', id); }
  async OpenWorkspaceInExternalOpener(id: string): Promise<void> { return this.placeholderMethod('OpenWorkspaceInExternalOpener', id); }
  async OpenWorkspaceInExternalOpenerForTab(tabID: string, id: string): Promise<void> { return this.placeholderMethod('OpenWorkspaceInExternalOpenerForTab', tabID, id); }
  async RevealWorkspacePath(rel: string): Promise<void> { return this.placeholderMethod('RevealWorkspacePath', rel); }
  async RevealWorkspacePathForTab(tabID: string, rel: string): Promise<void> { return this.placeholderMethod('RevealWorkspacePathForTab', tabID, rel); }
  async RevealPath(path: string): Promise<void> { return this.placeholderMethod('RevealPath', path); }
  async SavePastedImage(dataUrl: string): Promise<string> {
    const id = this.nextAttachmentId++;
    const path = `web-attachment://img-${id}.png`;
    this.attachments.set(path, { name: `pasted-${id}.png`, dataUrl });
    return path;
  }

  async SaveClipboardImage(): Promise<string> {
    // 纯 Web 环境无法从系统剪贴板直接取图像字节；返回占位符路径，保证 Composer 流程不崩溃
    const id = this.nextAttachmentId++;
    const path = `web-attachment://clipboard-${id}.png`;
    const placeholder =
      'data:image/svg+xml;utf8,' +
      encodeURIComponent('<svg xmlns="http://www.w3.org/2000/svg" width="1" height="1"/>');
    this.attachments.set(path, { name: `clipboard-${id}.png`, dataUrl: placeholder });
    return path;
  }

  async SavePastedFile(name: string, dataUrl: string): Promise<string> {
    const id = this.nextAttachmentId++;
    const safeName = name.replace(/[\\/:*?"<>|]/g, '_');
    const path = `web-attachment://file-${id}/${safeName}`;
    let bytes: Uint8Array | undefined;
    try {
      const comma = dataUrl.indexOf(',');
      if (comma !== -1) {
        const base64 = dataUrl.slice(comma + 1);
        const bin = atob(base64);
        const buf = new Uint8Array(bin.length);
        for (let i = 0; i < bin.length; i++) buf[i] = bin.charCodeAt(i);
        bytes = buf;
      }
    } catch { /* ignore decoding failures */ }
    this.attachments.set(path, { name: safeName, dataUrl, bytes });
    // 19 号方案：镜像上传到大脑（POST /api/save-attachment）。fire-and-forget——
    // 端点未部署（404）/未登录/网络失败都静默忽略，内存内联链路不受影响；
    // 成功后 expandFileReferences 会在文件头附服务端副本路径，供部件按路径读原始字节。
    void this.mirrorAttachmentToServer(path, safeName, dataUrl);
    return path;
  }

  /** 附件镜像上传到大脑；成功时回写 attachments[path].serverPath。
   *  21 号方案：请求体带当前 tab 的 conversation_id（无会话则 null，服务端落 _pending
   *  并返回 upload_id）；conversation_bound=true 时标记附件已绑定会话目录。 */
  private async mirrorAttachmentToServer(path: string, name: string, dataUrl: string): Promise<void> {
    try {
      const token = authApi.getCurrentSession()?.token;
      if (!token) return;
      const conversationId = this._conversationIdByTab.get(this.activeTabId) ?? null;
      const resp = await fetch('/api/save-attachment', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
        body: JSON.stringify({ name, dataUrl, conversation_id: conversationId }),
        signal: AbortSignal.timeout(60_000),
      });
      if (!resp.ok) return; // 404=端点未部署，其余状态同样静默
      const j = (await resp.json()) as { path?: unknown; upload_id?: unknown; conversation_bound?: unknown };
      const att = this.attachments.get(path);
      if (!att) return;
      if (typeof j.path === 'string' && j.path.length > 0) att.serverPath = j.path;
      if (typeof j.upload_id === 'string' && j.upload_id.length > 0) att.uploadId = j.upload_id;
      if (j.conversation_bound === true) att.conversationBound = true;
    } catch { /* 镜像失败不影响主链路 */ }
  }

  /** 21 号方案：会话建立（conversation_bound 帧）后，把 _pending 附件 move 进会话目录。
   *  端点未部署（404）静默忽略；成功后按文件名匹配回写新 serverPath 并标记 conversationBound。 */
  private async bindPendingAttachments(conversationId: string): Promise<void> {
    try {
      const pending = [...this.attachments.values()].filter((a) => a.uploadId && !a.conversationBound);
      if (pending.length === 0) return;
      const token = authApi.getCurrentSession()?.token;
      if (!token) return;
      const resp = await fetch('/api/attachments/bind', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
        body: JSON.stringify({ upload_ids: pending.map((a) => a.uploadId), conversation_id: conversationId }),
        signal: AbortSignal.timeout(30_000),
      });
      if (!resp.ok) return; // 404=端点未部署
      const j = (await resp.json()) as { bound?: unknown };
      const bound = Array.isArray(j.bound) ? j.bound.filter((p): p is string => typeof p === 'string') : [];
      pending.forEach((att, i) => {
        att.conversationBound = true;
        const matched = bound.find((p) => p.endsWith(`/${att.name}`)) ?? bound[i];
        if (matched) att.serverPath = matched;
      });
    } catch { /* 绑定失败不阻断对话 */ }
  }

  async PickExportFile(defaultFilename: string, mimeType: string): Promise<string> { return this.placeholderMethod('PickExportFile', defaultFilename, mimeType); }
  async SaveExportFile(path: string, payload: string, base64Encoded: boolean): Promise<void> { return this.placeholderMethod('SaveExportFile', path, payload, base64Encoded); }

  async AttachDropped(path: string): Promise<DroppedItem> {
    // Web 环境没有 OS 级别的拖放路径；但如果是浏览器上传的文件也不会走这里。
    // 此处如果传入的路径恰好是内存附件 key，直接返回 attachment。
    if (this.attachments.has(path)) {
      const att = this.attachments.get(path)!;
      return {
        kind: 'attachment',
        path,
        previewUrl: att.dataUrl,
      };
    }
    // 否则当成 workspace 引用，交给 expandFileReferences 读取真实文件
    return {
      kind: 'workspace',
      path,
      displayPath: path,
    };
  }

  async AttachmentDataURL(path: string): Promise<string> {
    const att = this.attachments.get(path);
    if (att) return att.dataUrl;
    // workspace 引用：没预览图就返回空字符串，UI 会降级为普通文件卡片
    return '';
  }

  /** 21 号方案：附件服务端落盘信息（供消息卡片预览/下载按钮）。未镜像成功返回 null。 */
  async AttachmentServerInfo(path: string): Promise<{ serverPath: string; size?: number } | null> {
    const att = this.attachments.get(path);
    if (!att?.serverPath) return null;
    return { serverPath: att.serverPath, size: att.bytes?.length };
  }
  async DeleteMemory(kind: string, pathOrName: string): Promise<void> {
    // 16 号方案 F3：服务端条目（id 命中）走 DELETE /api/memory/{id}
    if (aisocApi.hasAuthToken() && this._serverMemoryIds.has(pathOrName)) {
      try {
        await aisocApi.deleteMemory(pathOrName);
      } catch {
        // 服务端删除失败仍继续本地清理（下次 Memory() 拉取会恢复服务端态）
      }
    }
    if (kind === 'doc' || kind === 'docs') {
      this.memoryState.docs = this.memoryState.docs.filter(d => d.path !== pathOrName);
    } else if (kind === 'archive' || kind === 'archives') {
      this.memoryState.archives = this.memoryState.archives.filter(a => a.path !== pathOrName);
    } else {
      this.memoryState.facts = this.memoryState.facts.filter(f => f.name !== pathOrName);
    }
    this.saveMemoryOnly();
  }
  async WriteMemory(kind: string, pathOrName: string, body: string, description?: string): Promise<void> {
    // 16 号方案 F3：服务端条目（id 命中）走 PATCH /api/memory/{id}；本地条目维持原逻辑。
    // 后端条目仅支持 content 维度的编辑（title/description 是前端展示态，从 content 派生）。
    if (kind !== 'doc' && kind !== 'docs' && kind !== 'archive' && kind !== 'archives'
        && aisocApi.hasAuthToken() && this._serverMemoryIds.has(pathOrName)) {
      try {
        await aisocApi.updateMemory(pathOrName, { content: body });
        this.memoryState.facts = this.memoryState.facts.map(f =>
          f.name === pathOrName
            ? { ...f, body, description: body.slice(0, 120), title: body.length > 30 ? `${body.slice(0, 30)}…` : body }
            : f,
        );
        this.saveMemoryOnly();
        return;
      } catch {
        // 服务端更新失败 → 落入本地逻辑兜底（下次拉取会被服务端值覆盖）
      }
    }
    if (kind === 'doc' || kind === 'docs') {
      const scope = pathOrName.startsWith('project:') ? 'project' : 'user';
      this.memoryState.docs = this.memoryState.docs.filter(d => d.path !== pathOrName);
      this.memoryState.docs.push({ path: pathOrName, scope, body });
    } else if (kind === 'archive' || kind === 'archives') {
      this.memoryState.archives = this.memoryState.archives.filter(a => a.path !== pathOrName);
      this.memoryState.archives.push({
        path: pathOrName,
        name: pathOrName,
        title: description || pathOrName,
        description: description || '',
        type: 'archive',
        body,
        archivedAt: new Date().toISOString(),
      });
    } else {
      const type = /^(user|project|local|feedback|reference)$/.test(kind ?? '') ? kind : 'user';
      this.memoryState.facts = this.memoryState.facts.filter(f => f.name !== pathOrName);
      this.memoryState.facts.push({
        name: pathOrName,
        title: description || pathOrName,
        description: description || body.slice(0, 120),
        type,
        body,
      });
    }
    this.saveMemoryOnly();
  }
  async MarkMemoryUsed(_kind: string, _pathOrName: string): Promise<void> { /* Web 端不跟踪使用热度，空实现 */ }
  async MemoryUpsertMany(items: Array<{ kind: string; key: string; body?: string }>): Promise<void> {
    for (const it of items) {
      if (typeof it.body === 'string') await this.WriteMemory(it.kind, it.key, it.body);
    }
  }

  async ModelsForTab(_tabID: string): Promise<ModelInfo[]> { return this.Models(); }
  async SetModelForTab(tabID: string, name: string): Promise<void> { return this.placeholderMethod('SetModelForTab', tabID, name); }
  async EffortForTab(_tabID: string): Promise<EffortInfo> { return this.Effort(); }
  async SetEffortForTab(tabID: string, level: string): Promise<void> { return this.placeholderMethod('SetEffortForTab', tabID, level); }
  async SetTokenMode(mode: string): Promise<void> { return this.placeholderMethod('SetTokenMode', mode); }
  async SetTokenModeForTab(tabID: string, mode: string): Promise<void> { return this.placeholderMethod('SetTokenModeForTab', tabID, mode); }
  async MemoryForTab(_tabID: string): Promise<MemoryView> { return this.Memory(); }
  async MemorySuggestionsForTab(_tabID: string): Promise<MemorySuggestionsView> { return this.MemorySuggestions(); }
  async AcceptMemorySuggestion(suggestion: MemorySuggestion): Promise<string> {
    return this.Remember(
      suggestion.type === 'project' ? 'project' : 'user',
      suggestion.body,
      suggestion.name,
      suggestion.title,
      suggestion.description,
    );
  }
  async AcceptSkillSuggestion(suggestion: SkillSuggestion): Promise<string> { return this.placeholderMethod('AcceptSkillSuggestion', suggestion); }
  async AcceptMemorySuggestionForTab(_tabID: string, suggestion: MemorySuggestion): Promise<string> { return this.AcceptMemorySuggestion(suggestion); }
  async AcceptSkillSuggestionForTab(tabID: string, suggestion: SkillSuggestion): Promise<string> { return this.placeholderMethod('AcceptSkillSuggestionForTab', tabID, suggestion); }
  async Remember(scope: string, note: string, name?: string, title?: string, description?: string): Promise<string> {
    // 16 号方案 F3：登录用户"记住"直接落服务端（后端强制 source=user_marked、importance>=80）。
    // 后端 type 枚举 fact|preference|goal|entity|skill，与桌面 scope 语义不同，统一记为 fact。
    if (aisocApi.hasAuthToken()) {
      try {
        const entry = await aisocApi.createMemory({
          content: note,
          type: 'fact',
          importance: 90,
          keywords: title?.trim() ? [title.trim().slice(0, 20)] : undefined,
        });
        this.memoryState.facts = this.memoryState.facts.filter(f => f.name !== entry.id);
        this.memoryState.facts.push({
          name: entry.id,
          title: title?.trim() || (note.length > 30 ? `${note.slice(0, 30)}…` : note),
          description: description?.trim() || note.slice(0, 120),
          type: 'fact',
          body: note,
        });
        this._serverMemoryIds.add(entry.id);
        this.saveMemoryOnly();
        return entry.id;
      } catch {
        // 服务端写入失败 → 降级本地（不丢用户的记录意图）
      }
    }
    const safeScope = /^(user|project|local)$/.test(scope ?? '') ? scope! : 'user';
    const factName = name?.trim() || `note-${Date.now()}`;
    const fact: MemoryFact = {
      name: factName,
      title: title?.trim() || factName,
      description: description?.trim() || note.slice(0, 120),
      type: safeScope,
      body: note,
    };
    this.memoryState.facts = this.memoryState.facts.filter(f => f.name !== fact.name);
    this.memoryState.facts.push(fact);
    this.saveMemoryOnly();
    return fact.name;
  }
  async RememberForTab(_tabID: string, scope: string, note: string): Promise<string> { return this.Remember(scope, note); }
  async Forget(name: string): Promise<void> {
    // 16 号方案 F3：服务端条目（id 命中）走 DELETE /api/memory/{id}，失败降级本地删除
    if (aisocApi.hasAuthToken() && this._serverMemoryIds.has(name)) {
      try {
        await aisocApi.deleteMemory(name);
      } catch {
        // 服务端删除失败仍继续本地清理，保持 UI 一致（下次 Memory() 拉取会恢复服务端态）
      }
    }
    this.memoryState.facts = this.memoryState.facts.filter(f => f.name !== name);
    this.memoryState.docs = this.memoryState.docs.filter(d => d.path !== name);
    this.saveMemoryOnly();
  }
  async ForgetForTab(_tabID: string, name: string): Promise<void> { return this.Forget(name); }
  async SaveDoc(path: string, body: string): Promise<string> {
    const scope = path.startsWith('project:') ? 'project' : 'user';
    this.memoryState.docs = this.memoryState.docs.filter(d => d.path !== path);
    this.memoryState.docs.push({ path, scope, body });
    this.saveMemoryOnly();
    return path;
  }
  async SaveDocForTab(_tabID: string, path: string, body: string): Promise<string> { return this.SaveDoc(path, body); }
  async DesktopStartupSettings(): Promise<DesktopStartupSettingsView> {
    this.hydrateSettingsFromStorage();
    const { bot, desktopLanguage, desktopLayoutStyle, desktopTheme, desktopThemeStyle, displayMode, statusBarStyle, statusBarItems, checkUpdates } = this.settings;
    return JSON.parse(JSON.stringify({
      bot,
      desktopLanguage,
      desktopLayoutStyle,
      desktopTheme,
      desktopThemeStyle,
      displayMode,
      statusBarStyle,
      statusBarItems,
      checkUpdates,
    })) as DesktopStartupSettingsView;
  }
  async HooksSettings(scope: string): Promise<HooksSettingsView> { return this.placeholderMethod('HooksSettings', scope); }
  async SaveHooksSettings(scope: string, hooks: HookConfigView[]): Promise<void> { return this.placeholderMethod('SaveHooksSettings', scope, hooks); }
  async SaveHooksSettingsForRoot(scope: string, projectRoot: string, hooks: HookConfigView[]): Promise<void> { return this.placeholderMethod('SaveHooksSettingsForRoot', scope, projectRoot, hooks); }
  async TrustProjectHooks(): Promise<void> { return this.placeholderMethod('TrustProjectHooks'); }
  async TrustProjectHooksForRoot(projectRoot: string): Promise<void> { return this.placeholderMethod('TrustProjectHooksForRoot', projectRoot); }
  async SetDefaultModel(ref: string): Promise<void> { return this.placeholderMethod('SetDefaultModel', ref); }
  async SetPlannerModel(ref: string): Promise<void> { return this.placeholderMethod('SetPlannerModel', ref); }
  async SetSubagentModel(ref: string): Promise<void> { return this.placeholderMethod('SetSubagentModel', ref); }
  async SetSubagentEffort(level: string): Promise<void> { this.settings.subagentEffort = level; settingsStorage.set('subagentEffort', level); }
  async SetMaxSubagentDepth(depth: number): Promise<void> { this.settings.agent = { ...this.settings.agent, maxSubagentDepth: depth }; settingsStorage.set('agent.maxSubagentDepth', depth); }
  async SetAutoPlan(mode: string): Promise<void> { this.settings.autoPlan = mode; settingsStorage.set('autoPlan', mode); }
  async SetDefaultToolApprovalMode(mode: string): Promise<void> { this.settings.defaultToolApprovalMode = mode; settingsStorage.set('defaultToolApprovalMode', mode); }
  async SaveProvider(p: ProviderView): Promise<void> { return this.placeholderMethod('SaveProvider', p); }
  async SaveProviderWithKey(p: ProviderView, key: string): Promise<string> { return this.placeholderMethod('SaveProviderWithKey', p, key); }
  async AddOfficialProviderAccess(kind: string, key: string): Promise<string> { return this.placeholderMethod('AddOfficialProviderAccess', kind, key); }
  async AddProviderPresetAccess(id: string, key: string): Promise<string> { return this.placeholderMethod('AddProviderPresetAccess', id, key); }
  async ResetProviderPresetAccess(id: string): Promise<void> { return this.placeholderMethod('ResetProviderPresetAccess', id); }
  async FetchProviderModels(p: ProviderView): Promise<string[]> { return this.placeholderMethod('FetchProviderModels', p); }
  async DeleteProvider(name: string): Promise<void> { return this.placeholderMethod('DeleteProvider', name); }
  async RemoveProviderAccess(name: string): Promise<void> { return this.placeholderMethod('RemoveProviderAccess', name); }
  async SaveProviderKey(apiKeyEnv: string, value: string): Promise<string> { return this.placeholderMethod('SaveProviderKey', apiKeyEnv, value); }
  async SetProviderKey(apiKeyEnv: string, value: string): Promise<string> { return this.placeholderMethod('SetProviderKey', apiKeyEnv, value); }
  async ClearProviderKey(apiKeyEnv: string): Promise<void> { return this.placeholderMethod('ClearProviderKey', apiKeyEnv); }
  async SetPermissionMode(mode: string): Promise<void> { return this.placeholderMethod('SetPermissionMode', mode); }
  async AddPermissionRule(list: string, rule: string): Promise<void> { return this.placeholderMethod('AddPermissionRule', list, rule); }
  async RemovePermissionRule(list: string, rule: string): Promise<void> { return this.placeholderMethod('RemovePermissionRule', list, rule); }
  async ReloadSettings(): Promise<void> { return this.placeholderMethod('ReloadSettings'); }
  async SetSandbox(bash: string, network: boolean, workspaceRoot: string, allowWrite: string[], shell: string): Promise<void> { return this.placeholderMethod('SetSandbox', bash, network, workspaceRoot, allowWrite, shell); }
  async SetNetwork(n: NetworkView): Promise<void> { return this.placeholderMethod('SetNetwork', n); }
  async SetBotSettings(b: BotSettingsView): Promise<void> { return this.placeholderMethod('SetBotSettings', b); }
  async SetBotConnectionToolApprovalMode(connID: string, mode: string): Promise<void> { return this.placeholderMethod('SetBotConnectionToolApprovalMode', connID, mode); }
  async SetBotSecret(envName: string, value: string): Promise<void> { return this.placeholderMethod('SetBotSecret', envName, value); }
  async ClearBotSecret(envName: string): Promise<void> { return this.placeholderMethod('ClearBotSecret', envName); }
  async StartBotConnectionInstall(provider: string, domain: string): Promise<BotInstallStartResult> { return this.placeholderMethod('StartBotConnectionInstall', provider, domain); }
  async PollBotConnectionInstall(installID: string): Promise<BotInstallPollResult> { return this.placeholderMethod('PollBotConnectionInstall', installID); }
  async BotRuntimeStatus(): Promise<BotRuntimeStatusView> { return this.placeholderMethod('BotRuntimeStatus'); }
  async DiagnoseBotConnection(id: string): Promise<BotConnectionDiagnostic> { return this.placeholderMethod('DiagnoseBotConnection', id); }
  async TestBotConnection(id: string, target?: string): Promise<BotConnectionDiagnostic> { return this.placeholderMethod('TestBotConnection', id, target); }
  async SetCloseBehavior(mode: string): Promise<void> { this.settings.closeBehavior = mode; settingsStorage.set('closeBehavior', mode); }
  async SetDisplayMode(mode: string): Promise<void> { this.settings.displayMode = mode; settingsStorage.set('displayMode', mode); }
  async SetStatusBarStyle(style: string): Promise<void> { this.settings.statusBarStyle = style; settingsStorage.set('statusBarStyle', style); }
  async SetStatusBarItems(items: string[]): Promise<void> { this.settings.statusBarItems = items; settingsStorage.set('statusBarItems', items); }
  async SetDesktopLanguage(lang: string): Promise<void> { this.settings.desktopLanguage = lang; settingsStorage.set('desktopLanguage', lang); }
  async SetDesktopAppearance(theme: string, style: string): Promise<void> {
    const t = theme === 'auto' || theme === 'light' ? theme : 'dark';
    this.settings.desktopTheme = t;
    this.settings.desktopThemeStyle = style;
    if (typeof localStorage !== 'undefined') {
      try {
        localStorage.setItem(WebApiProxy.LS_KEY_THEME, t);
        localStorage.setItem(WebApiProxy.LS_KEY_THEME_STYLE, style);
      } catch {
        /* ignore storage failures */
      }
    }
  }
  async SetDesktopLayoutStyle(style: string): Promise<void> {
    this.settings.desktopLayoutStyle = style;
    settingsStorage.set('desktopLayoutStyle', style);
  }
  async SetDesktopZoomFactor(factor: number): Promise<void> { return this.placeholderMethod('SetDesktopZoomFactor', factor); }
  async GetDesktopZoomFactor(): Promise<number> { return this.placeholderMethod('GetDesktopZoomFactor'); }
  async RestartApplication(): Promise<void> { return this.placeholderMethod('RestartApplication'); }
  async SetDesktopCheckUpdates(enabled: boolean): Promise<void> { return this.placeholderMethod('SetDesktopCheckUpdates', enabled); }
  async SetDesktopTelemetry(enabled: boolean): Promise<void> { return this.placeholderMethod('SetDesktopTelemetry', enabled); }
  async SetDesktopMetrics(enabled: boolean): Promise<void> { return this.placeholderMethod('SetDesktopMetrics', enabled); }
  async SetMemoryCompilerEnabled(enabled: boolean): Promise<void> {
    this.settings.memoryCompilerEnabled = enabled;
    settingsStorage.set('memoryCompilerEnabled', enabled);
    // 16 号方案 F5：同步写后端 runtime（全局闸）。失败静默——下次 Settings() 拉取会以后端为准，
    // 且对话请求体 use_memory 仍直传本开关值，前端意图不受写失败影响。
    void aisocApi.saveRuntimeSettings({ memoryCompilerEnabled: enabled }).catch(() => {});
  }
  async SetExpandThinking(on: boolean): Promise<void> { return this.placeholderMethod('SetExpandThinking', on); }
  async MigrateDesktopPreferences(language: string, theme: string, style: string): Promise<void> {
    if (language === 'en' || language === 'zh' || language === 'zh-TW') {
      this.settings.desktopLanguage = language;
    }
    if (!this.settings.desktopTheme && !this.settings.desktopThemeStyle) {
      await this.SetDesktopAppearance(theme, style);
    }
  }
  async SetAgentParams(temperature: number, maxSteps: number, plannerMaxSteps: number, systemPrompt: string): Promise<void> { return this.placeholderMethod('SetAgentParams', temperature, maxSteps, plannerMaxSteps, systemPrompt); }
  async SetColdResumePrune(enabled: boolean): Promise<void> { this.settings.agent = { ...this.settings.agent, coldResumePrune: enabled }; settingsStorage.set('agent.coldResumePrune', enabled); }
  async SetReasoningLanguage(lang: string): Promise<void> { this.settings.agent = { ...this.settings.agent, reasoningLanguage: lang }; settingsStorage.set('agent.reasoningLanguage', lang); }
  async SetTrayLocale(locale: "en" | "zh" | "zh-TW"): Promise<void> { return this.placeholderMethod('SetTrayLocale', locale); }
  async SetBypass(on: boolean): Promise<void> { return this.placeholderMethod('SetBypass', on); }
  async Version(): Promise<string> { return this.placeholderMethod('Version'); }
  async CheckUpdate(): Promise<UpdateInfo | null> { return this.placeholderMethod('CheckUpdate'); }
  async DownloadUpdate(): Promise<UpdateDownloadResult | null> { return this.placeholderMethod('DownloadUpdate'); }
  async InstallUpdate(): Promise<void> { return this.placeholderMethod('InstallUpdate'); }
  async ApplyUpdate(): Promise<void> { return this.placeholderMethod('ApplyUpdate'); }
  async OpenDownloadPage(): Promise<void> { return this.placeholderMethod('OpenDownloadPage'); }
  async NeedsOnboarding(): Promise<boolean> { return this.placeholderMethod('NeedsOnboarding'); }
  async ConnectKey(apiKey: string): Promise<string> { return this.placeholderMethod('ConnectKey', apiKey); }
  async ReportCrash(kind: string, detail: string): Promise<void> { return this.placeholderMethod('ReportCrash', kind, detail); }
  async OpenTopicSession(scope: string, workspaceRoot: string, topicID: string, sessionPath: string): Promise<TabMeta> {
    const tab = scope === 'project'
      ? await this.OpenProjectTab(workspaceRoot, topicID)
      : await this.OpenGlobalTab(topicID);
    if (sessionPath) tab.sessionPath = sessionPath;
    return tab;
  }

  async EnsureBlankTab(scope: string, workspaceRoot: string): Promise<TabMeta> {
    const root = scope === 'project' ? (workspaceRoot || '/') : '/';
    // 项目下复用"空白且未绑定会话"的 tab，避免连点"新建会话"产生一串空 tab
    if (scope === 'project' && isProjectRoot(root)) {
      const existing = this.tabs.find((t) =>
        t.scope === 'project'
        && t.workspaceRoot === root
        && !this._conversationIdByTab.has(t.id)
        && (this.histories.get(t.id)?.length ?? 0) === 0
        && !t.running);
      if (existing) {
        this.tabs = this.tabs.map((t) => ({ ...t, active: t.id === existing.id }));
        this.activeTabId = existing.id;
        this.saveToStorage();
        return existing;
      }
    }
    // 创建一个新的空白 tab（独立历史，不影响其他 tab）
    const topicID = `topic-${Date.now()}`;
    const tab = scope === 'project'
      ? await this.OpenProjectTab(root, topicID)
      : await this.OpenGlobalTab(topicID);
    return tab;
  }

  async ActivateTopic(scope: string, workspaceRoot: string, topicID: string, sessionPath: string): Promise<TabMeta> {
    const tab = scope === 'project'
      ? await this.OpenProjectTab(workspaceRoot, topicID)
      : await this.OpenGlobalTab(topicID);
    if (sessionPath) tab.sessionPath = sessionPath;
    return tab;
  }

  async EnsureBlankSurface(scope: string, workspaceRoot: string): Promise<TabMeta> {
    // singleSurfaceLayout 模式下用此方法：清空所有 tab，只保留一个新的。
    // 注意：这里"清空 tab"对应桌面版关闭所有会话窗格，所以 tab 的历史会丢失是预期行为。
    this.tabs = [];
    this.histories.clear();
    return this.EnsureBlankTab(scope, workspaceRoot);
  }
  async RenameProject(workspaceRoot: string, title: string): Promise<void> {
    const id = projectIdFromRoot(workspaceRoot);
    if (!id) return;
    await webProjects.update(id, { name: title });
  }
  async SetProjectColor(workspaceRoot: string, color: string): Promise<void> {
    const id = projectIdFromRoot(workspaceRoot);
    if (!id) return;
    await webProjects.update(id, { color: color || null });
  }
  async SetProjectPinned(workspaceRoot: string, pinned: boolean): Promise<void> {
    const id = projectIdFromRoot(workspaceRoot);
    if (!id) return;
    await webProjects.update(id, { pinned });
  }
  async ReorderProjects(workspaceRoots: string[]): Promise<void> {
    const ids = workspaceRoots.map((r) => projectIdFromRoot(r)).filter((x): x is string => !!x);
    if (ids.length > 0) await webProjects.reorder(ids);
  }
  async CreateTopic(scope: string, workspaceRoot: string, _title: string): Promise<TopicMeta> {
    // 树里的"新建会话"走 App.onCreateTopic → EnsureBlankTab；此方法仅为接口完整性保留
    const tab = await this.EnsureBlankTab(scope, workspaceRoot);
    return { id: tab.topicId, title: tab.topicTitle, createdAt: Date.now() };
  }
  async RenameTopic(topicID: string, title: string): Promise<void> {
    // Web 形态 topicID 即服务端会话 id（uuid 才走服务端）
    if (!WebApiProxy.isServerConversationId(topicID) || !aisocApi.hasAuthToken()) return;
    await aisocApi.updateConversation(topicID, { title });
  }
  async DeleteTopic(topicID: string): Promise<void> {
    if (!WebApiProxy.isServerConversationId(topicID) || !aisocApi.hasAuthToken()) return;
    await aisocApi.deleteConversation(topicID);
    this.detachConversationTab(topicID);
  }
  async TrashTopic(topicID: string): Promise<void> {
    // 后端会话目前只有硬删（DELETE）；前端语义等同删除
    return this.DeleteTopic(topicID);
  }
  async SetTopicPinned(topicID: string, pinned: boolean): Promise<void> {
    if (!WebApiProxy.isServerConversationId(topicID) || !aisocApi.hasAuthToken()) return;
    await aisocApi.updateConversation(topicID, { pinned });
  }

  /** 删除/移走会话后，关掉它对应的本地 tab 与映射 */
  private detachConversationTab(conversationId: string): void {
    for (const [tabId, cid] of [...this._conversationIdByTab.entries()]) {
      if (cid !== conversationId) continue;
      this._conversationIdByTab.delete(tabId);
      void this.CloseTab(tabId);
    }
    this.saveConversationsOnly();
  }
  async DeliveryWorktreeAvailability(workspaceRoot: string): Promise<{ available: boolean; reason?: string }> {
    // Web 形态（尤其 17 号方案 project:// 虚拟根）没有本地 git 工作树，
    // 必须返回 rejected=false 的对象：ProjectTree 打开项目右键菜单时会同步 .then()，
    // 返回 undefined 会导致 TypeError 崩溃整个侧栏。
    if (isProjectRoot(workspaceRoot)) {
      return { available: false, reason: 'Web 评估项目不支持交付工作树' };
    }
    return { available: false, reason: '浏览器模式不支持本地工作树' };
  }
  async CreateDeliveryWorktree(_workspaceRoot: string): Promise<never> {
    throw new Error('浏览器模式不支持创建交付工作树');
  }

  // ==================== AiSOC 安全运营大脑桥接 ====================
  // 直接代理 aisoc-api.ts 中的方法（严格对齐 docs/frontend-api.md），
  // 供前端组件通过 app 绑定调用。若某些方法前端直接 import aisocApi 使用也完全可以。

  /** 设置 AiSOC 认证 token（存在内存，刷新丢失；若需持久化可存 localStorage） */
  async AisocSetAuthToken(token: string): Promise<void> {
    aisocApi.setAuthToken(token);
  }

  /** AiSOC 健康检查（GET /api/health） */
  async AisocHealthCheck(): Promise<{ status: string; service: string }> {
    return aisocApi.healthCheck();
  }

  /** 创建 AiSOC 任务（POST /api/tasks，单 POST 下发） */
  async AisocCreateTask(task: CreateTaskInput): Promise<{ task_id: string; status: string; domain: string }> {
    return aisocApi.createTask(task);
  }

  /** 获取 AiSOC 任务详情（GET /api/tasks/{id}，含阶段进度 + 思维链 + 判定） */
  async AisocGetTask(taskId: string): Promise<TaskDetail | null> {
    // 新接口统一降级（T1-9）：401/404/超时/5xx → null 静默，成功路径不变
    return resilientRequest(() => aisocApi.getTask(taskId), null);
  }

  /** 导出 AiSOC 审计 JSON（GET /api/tasks/{id}/export） */
  async AisocExportTask(taskId: string): Promise<Record<string, unknown>> {
    return aisocApi.exportTask(taskId);
  }

  /** 列出 AiSOC 最近任务（GET /api/tasks?limit=） */
  async AisocListTasks(limit: number = 50): Promise<{ tasks: TaskInfo[] }> {
    // 新接口统一降级（T1-9）：失败静默返回空列表，成功路径不变
    return resilientRequest(() => aisocApi.listTasks(limit), { tasks: [] });
  }

  /** 查询 AiSOC 证据（GET /api/findings?task_id=） */
  async AisocGetFindings(taskId: string): Promise<Finding[]> {
    // 新接口统一降级（T1-9）：失败静默返回空数组，成功路径不变
    return resilientRequest(() => aisocApi.getFindings(taskId), [] as Finding[]);
  }

  /** 获取 AiSOC 报告（GET /api/reports/{task_id}，report 为 Markdown 字符串） */
  async AisocGetReport(taskId: string): Promise<ReportDoc | null> {
    // 新接口统一降级（T1-9）：401/404/超时/5xx → null 静默，成功路径不变
    return resilientRequest(() => aisocApi.getReport(taskId), null);
  }

  /** 审批 AiSOC 工具调用（POST /api/approve） */
  async AisocApproveTool(
    taskId: string,
    action: string,
    decision: 'approved' | 'denied',
  ): Promise<void> {
    // TIR 审批新接口（POST /api/approve）：失败静默降级，不抛异常
    await resilientRequest(() => aisocApi.approveTool(taskId, action, decision));
  }

  /** AiSOC 部件注册表（GET /api/registry，token 已脱敏不渲染） */
  async AisocGetRegistry(): Promise<RegistryPart[]> {
    return aisocApi.getRegistry();
  }

  /** AiSOC 各 Agent 忙闲状态（GET /api/agents/status，状态墙） */
  async AisocGetAgentsStatus(): Promise<AgentsStatus> {
    return aisocApi.getAgentsStatus();
  }

  /** AiSOC XDR 告警样例（GET /api/data/alarms） */
  async AisocGetAlarms(limit: number = 10): Promise<{ source?: string; count?: number; alarms: Alarm[] }> {
    return aisocApi.getAlarms(limit);
  }

  /** AiSOC 告警统计（GET /api/data/alarms/summary） */
  async AisocGetAlarmsSummary(): Promise<AlarmsSummary> {
    return aisocApi.getAlarmsSummary();
  }

  /** 生成 AiSOC 任务 ID（T+YYYYMMDD-HHMMSSxxxx） */
  AisocGenerateTaskId(): string {
    return generateTaskId();
  }

  /** 生成 AiSOC Finding ID（F-<task_id>-<seq>） */
  AisocGenerateFindingId(taskId: string, sequence: number): string {
    return generateFindingId(taskId, sequence);
  }

  /** 创建特定域的 AiSOC API 客户端 */
  AisocCreateDomainClient(domain: string, authToken?: string) {
    return createDomainApiClient(domain, authToken);
  }

  /**
   * 发送事件给订阅者
   */
  private emitEvent(event: WireEvent) {
    this.eventListeners.forEach(listener => {
      try {
        listener(event);
      } catch (error) {
        console.error('Event listener error:', error);
      }
    });
  }

  /**
   * 订阅事件流
   */
  onEvent(cb: (e: WireEvent) => void): () => void {
    this.eventListeners.add(cb);
    return () => {
      this.eventListeners.delete(cb);
    };
  }

  /**
   * 读取某个 tab 的流式进度（供 Composer 等 React 组件 poll）。
   * 返回纯对象快照，调用方负责 useTick 触发重渲染。
   * 不存在时返回 idle 占位，避免调用方空判断。
   */
  getStreamStats(tabId: string): { receivedChars: number; ttfbMs: number | null; phase: 'idle' | 'waiting_ttfb' | 'streaming' | 'final' } {
    return this.streamStats.get(tabId) ?? { receivedChars: 0, ttfbMs: null, phase: 'idle' };
  }
}

/**
 * Web API单例实例
 */
let webApiInstance: WebApiProxy | null = null;

export function getWebApi(): WebApiProxy {
  if (!webApiInstance) {
    webApiInstance = new WebApiProxy();
  }
  return webApiInstance;
}

/**
 * 检查是否应该使用Web API（用于网页版）
 */
export function shouldUseWebApi(): boolean {
  if (typeof window === 'undefined') return false;
  if (window.go?.main?.App) return false;
  return true;
}

export default WebApiProxy;