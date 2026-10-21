# EduShield 前端 ↔ 桌面后端桥接接口文档

> 覆盖范围：React 前端与 Go 内核之间的桥接层。
> 核心源码：
> - [bridge.ts](../../frontend/src/lib/bridge.ts) — 桥接契约 `AppBindings` 与事件订阅
> - [types.ts](../../frontend/src/lib/types.ts) — 桥接层数据类型
> - [httpApiAdapter.ts](../../frontend/src/lib/httpApiAdapter.ts) — 浏览器模式的 HTTP 客户端
> - [webApiProxy.ts](../../frontend/src/lib/webApiProxy.ts) — Web 模式 API 代理
> - Go 侧：`desktop/app.go`、`desktop/tabs.go` 等 Wails 绑定

---

## 1. 架构总览

前端（React）不直接访问文件系统、DeepSeek API 或模型运行时，而是通过**单一桥接层**与 Go 内核交互：

```
React 组件
   │  调用 app.<Method>(...)（AppBindings 接口）
   ▼
bridge.ts（Proxy + 三种绑定实现）
   ├─ Wails 壳模式  → window.go.main.App.*（生成的 Wails 绑定）+ window.runtime.EventsOn
   ├─ 浏览器模式    → HTTP API（httpApiAdapter，127.0.0.1:8787）
   └─ 纯浏览器降级  → mock（makeMockApp，返回固定数据用于 UI 开发）
   ▼
Go 内核（app.go）— 会话、历史、工具、模型、记忆、设置、工作区等
```

绑定解析优先级（[bridge.ts `getRealBindingOrHttp`](../../frontend/src/lib/bridge.ts)）：

1. `window.go?.main?.App` 存在 → 使用 **Wails 绑定**（真实桌面环境）。
2. 否则检查 HTTP API 服务（`checkHttpServiceAvailable`，5 秒缓存）→ 可用则用 **HTTP API 绑定**。
3. 都不可用 → 使用 **mock 绑定**。

---

## 2. 传输与事件

### 2.1 Wails 壳模式

- **方法调用**：通过 Wails 生成的绑定 `window.go.main.App.<Method>()`，异步返回 `Promise`。
- **事件订阅**：通过 `window.runtime.EventsOn(channel, cb)` 订阅事件流。

事件通道常量（[bridge.ts](../../frontend/src/lib/bridge.ts)）：

```ts
const EVENT_CHANNEL = "agent:event";
```

### 2.2 浏览器模式（HTTP API）

当不在 Wails 壳内运行时，若检测到 HTTP 服务，则走 HTTP API（[httpApiAdapter.ts](../../frontend/src/lib/httpApiAdapter.ts)）。

- 基础地址：`http://127.0.0.1:8787`
- 事件流端点：`GET /events`（SSE，`text/event-stream`）

已实现的端点映射：

| AppBindings 方法 | HTTP 端点 | 方法 |
|---|---|---|
| `Submit` | `/api/submit` | POST |
| `Cancel` | `/api/cancel` | POST |
| `Approve` | `/api/approve` | POST |
| `History` | `/api/history` | GET |
| `Meta` | `/api/meta` | GET |
| `ContextUsage` | `/api/context` | GET |
| `Balance` | `/api/balance` | GET |
| `Models` | `/api/models` | GET |
| `Settings` | `/api/settings` | GET |
| `Capabilities` | `/api/capabilities` | GET |
| `ListSessions` | `/api/sessions` | GET |

> 注意：HTTP API 绑定（`createHttpApiBinding`）目前只实现了上述方法；其余方法返回 `undefined` 并打印 `HTTP API method not implemented` 警告。

### 2.3 事件订阅 API

前端通过 `onEvent` 订阅类型化事件流，返回取消订阅函数：

```ts
export function onEvent(cb: (e: WireEvent) => void): () => void;
```

其它订阅辅助函数：

| 函数 | 用途 |
|---|---|
| `onUpdaterProgress(cb)` | 自动更新进度 |
| `onFilesDropped(cb)` | 文件拖拽（路径数组） |
| `onRuntimeRebuilt(cb)` | 运行时重建（可选 `tabId`） |
| `onReady(cb)` | 会话就绪（可选 `tabId`） |
| `onProjectTreeChanged(cb)` | 项目树变化 |
| `onSessionRecovered(cb)` | 会话恢复成功 |
| `onSessionRecoveryFailed(cb)` | 会话恢复失败 |

---

## 3. 事件流：`WireEvent`

事件类型枚举（[types.ts `EventKind`](../../frontend/src/lib/types.ts)）：

```
turn_started | reasoning | text | message | tool_dispatch | tool_result
| tool_progress | usage | notice | phase | approval_request | ask_request
| turn_done | compaction_started | compaction_done | mcp_surface_ready
| retrying | steer | memory_compiler_stats | guardian_assessment
```

`WireEvent` 结构：

```ts
interface WireEvent {
  kind: EventKind;
  text?: string;
  detail?: string;
  code?: string;            // 稳定的本地化通知 id；缺失时按 text 匹配
  reasoning?: string;
  memoryCitations?: MemoryCitation[];
  memoryCompiler?: MemoryCompilerStats;
  level?: "info" | "warn";  // 注意：不允许 "error"
  tool?: WireTool;
  usage?: WireUsage;
  approval?: WireApproval;
  ask?: WireAsk;
  compaction?: WireCompaction;
  guardian?: WireGuardian;
  err?: string;
  outcome?: "final_readiness";
  readiness?: WireFinalReadiness;
  retryAttempt?: number;
  retryMax?: number;
  tabId?: string;           // 由 Go 侧 tabEventSink 写入，多标签页按此路由
  sessionHitTokens?: number;
  sessionMissTokens?: number;
  sessionCost?: number;
  sessionCurrency?: string;
  sessionCostUsd?: number;  // 已废弃兼容别名，优先 sessionCost + sessionCurrency
}
```

**关键约束**（来自工程约定）：
- `WireEvent.level` 只允许 `"info"` 或 `"warn"`，**不允许 `"error"`**。
- `tabId` 用于多标签页事件路由，缺失时按当前活动标签处理。

---

## 4. `AppBindings` 接口参考

`AppBindings`（[bridge.ts](../../frontend/src/lib/bridge.ts)）是 React 与 Go 内核之间的手写契约，使用本地类型（`types.ts`）。以下按域分组列出全部方法。

### 4.1 窗口与平台

```ts
Platform(): Promise<string>;
MinimiseMainWindow(): Promise<void>;
ToggleMaximiseMainWindow(): Promise<void>;
IsMainWindowMaximised(): Promise<boolean>;
CloseMainWindow(): Promise<void>;
```

### 4.2 心跳（Heartbeat）

```ts
HeartbeatListTasks(): Promise<unknown>;
HeartbeatReloadTasks(): Promise<unknown>;
HeartbeatSaveTasks(tasks: unknown): Promise<void>;
HeartbeatTriggerNow(id: string): Promise<void>;
HeartbeatGenerateID(): Promise<string>;
```

### 4.3 提交与交互

```ts
Submit(input: string): Promise<void>;
SubmitToTab(tabID: string, input: string): Promise<void>;
SubmitDisplay(display: string, input: string): Promise<void>;
SubmitDisplayToTab(tabID: string, display: string, input: string): Promise<void>;
SubmitDeliveryRecoveryToTab(tabID: string, display: string, input: string): Promise<void>;
SubmitInvocationsToTab(tabID: string, display: string, input: string, invocations: InvocationRequest[]): Promise<void>;
SubmitEditedDisplayToTab(tabID: string, display: string, input: string, original: string): Promise<void>;
RunShell(command: string): Promise<void>;
RunShellForTab(tabID: string, command: string): Promise<void>;
Steer(text: string): Promise<void>;
SteerForTab(tabID: string, text: string): Promise<void>;
Cancel(): Promise<void>;
CancelTab(tabID: string): Promise<void>;
Approve(id: string, allow: boolean, session: boolean, persist: boolean): Promise<void>;
ApproveTab(tabID: string, id: string, allow: boolean, session: boolean, persist: boolean): Promise<void>;
AnswerQuestion(id: string, answers: QuestionAnswer[]): Promise<void>;
AnswerQuestionForTab(tabID: string, id: string, answers: QuestionAnswer[]): Promise<void>;
ReplayPendingPrompts(): Promise<void>;
```

### 4.4 模式 / 目标 / 审批

```ts
SetPlanMode(on: boolean): Promise<void>;
SetMode(mode: string): Promise<void>;
// 返回该标签页切换时自动放行的待审批 prompt id（已 drain）；未列出的仍在后端待审批
SetModeForTab(tabID: string, mode: string): Promise<string[] | void>;
SetAutoApproveTools(on: boolean): Promise<void>;
SetCollaborationMode(mode: string): Promise<void>;
SetCollaborationModeForTab(tabID: string, mode: string): Promise<void>;
SetToolApprovalMode(mode: string): Promise<void>;
// 与 SetModeForTab 相同的 drain 契约
SetToolApprovalModeForTab(tabID: string, mode: string): Promise<string[] | void>;
SetGoal(goal: string): Promise<void>;
SetGoalForTab(tabID: string, goal: string): Promise<void>;
ResumeGoalForTab(tabID: string): Promise<boolean>;
ClearGoal(): Promise<void>;
ClearGoalForTab(tabID: string): Promise<void>;
// SetBypass 是 YOLO/全权限工具自动审批的旧 Wails 名（仅运行时）
SetBypass(on: boolean): Promise<void>;
```

### 4.5 会话

```ts
Compact(): Promise<void>;
CompactForTab(tabID: string): Promise<void>;
NewSession(): Promise<void>;
NewSessionForTab(tabID: string): Promise<void>;
ClearSession(): Promise<void>;
ClearSessionForTab(tabID: string): Promise<void>;
```

### 4.6 历史与检查点

```ts
History(): Promise<HistoryMessage[]>;
HistoryForTab(tabID: string): Promise<HistoryMessage[]>;
HistoryPage(beforeTurn: number, limit: number): Promise<HistoryPage>;
HistoryPageForTab(tabID: string, beforeTurn: number, limit: number): Promise<HistoryPage>;
HistoryCheckpointTurnsForTab(tabID: string): Promise<number[]>;
Checkpoints(): Promise<CheckpointMeta[]>;
CheckpointsForTab(tabID: string): Promise<CheckpointMeta[]>;
Rewind(turn: number, scope: string): Promise<void>;
RewindForTab(tabID: string, turn: number, scope: string): Promise<void>;
Fork(turn: number): Promise<TabMeta>;
ForkForTab(tabID: string, turn: number): Promise<TabMeta>;
SummarizeFrom(turn: number): Promise<void>;
SummarizeFromForTab(tabID: string, turn: number): Promise<void>;
SummarizeUpTo(turn: number): Promise<void>;
SummarizeUpToForTab(tabID: string, turn: number): Promise<void>;
```

### 4.7 会话列表

```ts
ListSessions(): Promise<SessionMeta[]>;
ListTrashedSessions(): Promise<SessionMeta[]>;
ResumeSession(path: string): Promise<HistoryMessage[]>;
ResumeSessionForTab(tabID: string, path: string): Promise<HistoryMessage[]>;
ResumeSessionPage(path: string, limit: number): Promise<HistoryPage>;
ResumeSessionPageForTab(tabID: string, path: string, limit: number): Promise<HistoryPage>;
OpenChannelSessionForTab(tabID: string, path: string): Promise<HistoryMessage[]>;
OpenChannelSessionPageForTab(tabID: string, path: string, limit: number): Promise<HistoryPage>;
PreviewSession(path: string): Promise<HistoryMessage[]>;
DeleteSession(path: string): Promise<void>;
DeleteRecoveryCopy(path: string): Promise<void>;
RestoreSession(path: string): Promise<void>;
PurgeTrashedSession(path: string): Promise<void>;
PurgeRecoveryCopy(path: string): Promise<void>;
RenameSession(path: string, title: string): Promise<void>;
ScanPromptHistory(nonce: string): Promise<PromptHistoryResult>;
```

### 4.8 工作区

```ts
ListWorkspaces(): Promise<WorkspaceView[]>;
PickWorkspace(): Promise<string>;
SwitchWorkspace(path: string): Promise<string>;
RemoveWorkspace(path: string): Promise<void>;
```

### 4.9 上下文 / 余额 / 任务

```ts
ContextUsage(): Promise<ContextInfo>;
ContextUsageForTab(tabID: string): Promise<ContextInfo>;
Balance(): Promise<BalanceInfo>;
BalanceForTab(tabID: string): Promise<BalanceInfo>;
Jobs(): Promise<JobView[]>;
JobsForTab(tabID: string): Promise<JobView[]>;
ToolResultForTab(tabID: string, toolID: string): Promise<{ args: string; output: string } | null>;
Meta(): Promise<Meta>;
MetaForTab(tabID: string): Promise<Meta>;
```

### 4.10 自主研究（AutoResearch）

```ts
AutoResearchCurrent(): Promise<AutoResearchStatusView>;
AutoResearchStatus(tabID: string): Promise<AutoResearchStatusView>;
AutoResearchList(tabID: string): Promise<AutoResearchStatusView[]>;
AutoResearchFindings(tabID: string, limit: number): Promise<AutoResearchFindingView[]>;
AutoResearchOpenTask(tabID: string): Promise<void>;
AutoResearchRecordEvidence(tabID: string, criterionID: string, input: AutoResearchEvidenceView): Promise<void>;
```

### 4.11 能力 / 命令 / MCP / 技能 / 插件 / 子代理

```ts
Commands(): Promise<CommandInfo[]>;
Capabilities(): Promise<CapabilitiesView>;
MCPServers(): Promise<ServerView[]>;
InspectMCPTrust(name: string): Promise<MCPTrustInspectionView>;
SetMCPTrust(name: string, decision: "session" | "workspace" | "revoke"): Promise<void>;
RefreshMCPCatalog(): Promise<MCPCatalogRefreshView>;
SkillsSettings(): Promise<SkillsSettingsView>;
CapabilityDiagnostics(includeSessionRuntime: boolean): Promise<CapabilityDiagnosticsReport>;
Plugins(): Promise<PluginView[]>;
PlanPluginInstall(source: string, options: PluginInstallOptions): Promise<string>;
InstallPlugin(source: string, options: PluginInstallOptions): Promise<string>;
RemovePlugin(name: string): Promise<void>;
SetPluginEnabled(name: string, enabled: boolean): Promise<void>;
UpdatePlugin(name: string): Promise<string>;
PluginDoctor(name: string): Promise<PluginView>;
AddMCPServer(input: MCPServerInput): Promise<number>;
UpdateMCPServer(name: string, input: MCPServerInput): Promise<void>;
RemoveMCPServer(name: string): Promise<void>;
ReconnectMCPServer(name: string): Promise<void>;
ClearMCPServerAuthentication(name: string): Promise<void>;
PickSkillFolder(): Promise<string>;
PickPluginFolder(): Promise<string>;
AddSkillPath(path: string): Promise<void>;
RemoveSkillPath(path: string): Promise<void>;
RefreshSkills(): Promise<void>;
ReloadCommands(): Promise<void>;
SetSkillEnabled(name: string, enabled: boolean): Promise<void>;
AvailableSubagentTools(): Promise<MCPToolView[]>;
CreateSubagentProfile(input: SubagentProfileInput): Promise<string>;
UpdateSubagentProfile(name: string, scope: string, input: SubagentProfileInput): Promise<void>;
DeleteSubagentProfile(name: string, scope: string): Promise<void>;
SetSubagentProfileModel(name: string, ref: string): Promise<void>;
SetSubagentProfileEffort(name: string, level: string): Promise<void>;
TrySubagentProfile(input: SubagentProfileInput, task: string): Promise<string>;
CancelTrySubagentProfile(): Promise<void>;
SetMCPServerEnabled(name: string, enabled: boolean): Promise<void>;
SetMCPServerTier(name: string, tier: string): Promise<void>;
```

### 4.12 文件系统与 Git

```ts
SlashArgs(input: string): Promise<SlashArgsResult>;
ListDir(rel: string): Promise<DirEntry[]>;
ListDirForTab(tabID: string, rel: string): Promise<DirEntry[]>;
SearchFileRefs(query: string): Promise<DirEntry[]>;
SearchFileRefsForTab(tabID: string, query: string): Promise<DirEntry[]>;
ReadFile(rel: string): Promise<FilePreview>;
ReadFileForTab(tabID: string, rel: string): Promise<FilePreview>;
WorkspaceChanges(tabID: string): Promise<WorkspaceChangesView>;
GitBranches(): Promise<string[]>;
GitCheckout(branch: string): Promise<void>;
WorkspaceGitHistory(tabID: string, path: string): Promise<GitCommitView[]>;
WorkspaceGitCommitDetail(tabID: string, hash: string, path: string): Promise<GitCommitDetailView>;
OpenWorkspacePath(rel: string): Promise<void>;
OpenWorkspacePathForTab(tabID: string, rel: string): Promise<void>;
ExternalOpeners(): Promise<ExternalOpenersView>;
SetPreferredExternalOpener(id: string): Promise<void>;
OpenWorkspaceInExternalOpener(id: string): Promise<void>;
OpenWorkspaceInExternalOpenerForTab(tabID: string, id: string): Promise<void>;
RevealWorkspacePath(rel: string): Promise<void>;
RevealWorkspacePathForTab(tabID: string, rel: string): Promise<void>;
RevealPath(path: string): Promise<void>;
```

### 4.13 附件与粘贴

```ts
SavePastedImage(dataUrl: string): Promise<string>;
SaveClipboardImage(): Promise<string>;
SavePastedFile(name: string, dataUrl: string): Promise<string>;
PickExportFile(defaultFilename: string, mimeType: string): Promise<string>;
SaveExportFile(path: string, payload: string, base64Encoded: boolean): Promise<void>;
AttachDropped(path: string): Promise<DroppedItem>;
AttachmentDataURL(path: string): Promise<string>;
```

### 4.14 模型 / 努力度 / Token 模式

```ts
Models(): Promise<ModelInfo[]>;
SetModel(name: string): Promise<void>;
ModelsForTab(tabID: string): Promise<ModelInfo[]>;
SetModelForTab(tabID: string, name: string): Promise<void>;
Effort(): Promise<EffortInfo>;
SetEffort(level: string): Promise<void>;
EffortForTab(tabID: string): Promise<EffortInfo>;
SetEffortForTab(tabID: string, level: string): Promise<void>;
SetTokenMode(mode: string): Promise<void>;
SetTokenModeForTab(tabID: string, mode: string): Promise<void>;
```

### 4.15 记忆

```ts
Memory(): Promise<MemoryView>;
MemorySuggestions(): Promise<MemorySuggestionsView>;
AcceptMemorySuggestion(suggestion: MemorySuggestion): Promise<string>;
AcceptSkillSuggestion(suggestion: SkillSuggestion): Promise<string>;
MemoryForTab(tabID: string): Promise<MemoryView>;
MemorySuggestionsForTab(tabID: string): Promise<MemorySuggestionsView>;
AcceptMemorySuggestionForTab(tabID: string, suggestion: MemorySuggestion): Promise<string>;
AcceptSkillSuggestionForTab(tabID: string, suggestion: SkillSuggestion): Promise<string>;
Remember(scope: string, note: string): Promise<string>;
RememberForTab(tabID: string, scope: string, note: string): Promise<string>;
Forget(name: string): Promise<void>;
ForgetForTab(tabID: string, name: string): Promise<void>;
SaveDoc(path: string, body: string): Promise<string>;
SaveDocForTab(tabID: string, path: string, body: string): Promise<string>;
```

### 4.16 设置 / 桌面偏好

```ts
DesktopStartupSettings(): Promise<DesktopStartupSettingsView>;
Settings(): Promise<SettingsView>;
HooksSettings(scope: string): Promise<HooksSettingsView>;
SaveHooksSettings(scope: string, hooks: HookConfigView[]): Promise<void>;
SaveHooksSettingsForRoot(scope: string, projectRoot: string, hooks: HookConfigView[]): Promise<void>;
TrustProjectHooks(): Promise<void>;
TrustProjectHooksForRoot(projectRoot: string): Promise<void>;
SetDefaultModel(ref: string): Promise<void>;
SetPlannerModel(ref: string): Promise<void>;
SetSubagentModel(ref: string): Promise<void>;
SetSubagentEffort(level: string): Promise<void>;
SetMaxSubagentDepth(depth: number): Promise<void>;
SetAutoPlan(mode: string): Promise<void>;
SetDefaultToolApprovalMode(mode: string): Promise<void>;
```

### 4.17 Provider 与密钥

```ts
SaveProvider(p: ProviderView): Promise<void>;
SaveProviderWithKey(p: ProviderView, key: string): Promise<string>;
AddOfficialProviderAccess(kind: string, key: string): Promise<string>;
AddProviderPresetAccess(id: string, key: string): Promise<string>;
ResetProviderPresetAccess(id: string): Promise<void>;
FetchProviderModels(p: ProviderView): Promise<string[]>;
DeleteProvider(name: string): Promise<void>;
RemoveProviderAccess(name: string): Promise<void>;
SaveProviderKey(apiKeyEnv: string, value: string): Promise<string>;
SetProviderKey(apiKeyEnv: string, value: string): Promise<string>;
ClearProviderKey(apiKeyEnv: string): Promise<void>;
```

### 4.18 权限 / 沙箱 / 网络 / Bot 连接

```ts
SetPermissionMode(mode: string): Promise<void>;
AddPermissionRule(list: string, rule: string): Promise<void>;
RemovePermissionRule(list: string, rule: string): Promise<void>;
ReloadSettings(): Promise<void>;
SetSandbox(bash: string, network: boolean, workspaceRoot: string, allowWrite: string[], shell: string): Promise<void>;
SetNetwork(n: NetworkView): Promise<void>;
SetBotSettings(b: BotSettingsView): Promise<void>;
SetBotConnectionToolApprovalMode(connID: string, mode: string): Promise<void>;
SetBotSecret(envName: string, value: string): Promise<void>;
ClearBotSecret(envName: string): Promise<void>;
StartBotConnectionInstall(provider: string, domain: string): Promise<BotInstallStartResult>;
PollBotConnectionInstall(installID: string): Promise<BotInstallPollResult>;
BotRuntimeStatus(): Promise<BotRuntimeStatusView>;
DiagnoseBotConnection(id: string): Promise<BotConnectionDiagnostic>;
TestBotConnection(id: string, target?: string): Promise<BotConnectionDiagnostic>;
```

### 4.19 显示 / 外观 / 语言 / 缩放

```ts
SetCloseBehavior(mode: string): Promise<void>;
SetDisplayMode(mode: string): Promise<void>;
SetStatusBarStyle(style: string): Promise<void>;
SetStatusBarItems(items: string[]): Promise<void>;
SetDesktopLanguage(lang: string): Promise<void>;
SetDesktopAppearance(theme: string, style: string): Promise<void>;
SetDesktopLayoutStyle(style: string): Promise<void>;
SetDesktopZoomFactor(factor: number): Promise<void>;
GetDesktopZoomFactor(): Promise<number>;
RestartApplication(): Promise<void>;
SetDesktopCheckUpdates(enabled: boolean): Promise<void>;
SetDesktopTelemetry(enabled: boolean): Promise<void>;
SetDesktopMetrics(enabled: boolean): Promise<void>;
SetMemoryCompilerEnabled(enabled: boolean): Promise<void>;
SetExpandThinking(on: boolean): Promise<void>;
MigrateDesktopPreferences(language: string, theme: string, style: string): Promise<void>;
SetAgentParams(temperature: number, maxSteps: number, plannerMaxSteps: number, systemPrompt: string): Promise<void>;
SetColdResumePrune(enabled: boolean): Promise<void>;
SetReasoningLanguage(lang: string): Promise<void>;
SetTrayLocale(locale: "en" | "zh" | "zh-TW"): Promise<void>;
```

### 4.20 更新 / API Key / 崩溃上报

```ts
Version(): Promise<string>;
CheckUpdate(): Promise<UpdateInfo | null>;
DownloadUpdate(): Promise<UpdateDownloadResult | null>;
InstallUpdate(): Promise<void>;
ApplyUpdate(): Promise<void>;
OpenDownloadPage(): Promise<void>;
NeedsOnboarding(): Promise<boolean>;
ConnectKey(apiKey: string): Promise<string>;
// 崩溃遮罩「发送报告」：脱敏用户路径，附带 version/os/arch，仅用户点击时发送
ReportCrash(kind: string, detail: string): Promise<void>;
```

### 4.21 标签页 / 项目 / 主题

```ts
ListTabs(): Promise<TabMeta[]>;
OpenProjectTab(workspaceRoot: string, topicID: string): Promise<TabMeta>;
DeliveryWorktreeAvailability(workspaceRoot: string): Promise<DeliveryWorktreeAvailability>;
CreateDeliveryWorktree(workspaceRoot: string): Promise<DeliveryWorktreeOpenResult>;
OpenGlobalTab(topicID: string): Promise<TabMeta>;
OpenTopicSession(scope: string, workspaceRoot: string, topicID: string, sessionPath: string): Promise<TabMeta>;
EnsureBlankTab(scope: string, workspaceRoot: string): Promise<TabMeta>;
ActivateTopic(scope: string, workspaceRoot: string, topicID: string, sessionPath: string): Promise<TabMeta>;
EnsureBlankSurface(scope: string, workspaceRoot: string): Promise<TabMeta>;
SetActiveTab(tabID: string): Promise<void>;
ReorderTabs(tabIDs: string[]): Promise<void>;
CloseTab(tabID: string): Promise<void>;
ListProjectTree(): Promise<ProjectNode[]>;
RenameProject(workspaceRoot: string, title: string): Promise<void>;
SetProjectColor(workspaceRoot: string, color: string): Promise<void>;
SetProjectPinned(workspaceRoot: string, pinned: boolean): Promise<void>;
ReorderProjects(workspaceRoots: string[]): Promise<void>;
CreateTopic(scope: string, workspaceRoot: string, title: string): Promise<TopicMeta>;
RenameTopic(topicID: string, title: string): Promise<void>;
DeleteTopic(topicID: string): Promise<void>;
TrashTopic(topicID: string): Promise<void>;
SetTopicPinned(topicID: string, pinned: boolean): Promise<void>;
ContextPanel(tabID: string): Promise<ContextPanelInfo>;
```

### 4.22 原生对话框与窗口状态

```ts
ConfirmAction(req: NativeConfirmRequest): Promise<boolean>;
SaveWindowState(state: DesktopWindowState): Promise<void>;
```

---

## 5. 关键数据类型

> 完整定义见 [types.ts](../../frontend/src/lib/types.ts)。以下为桥接层最常用的类型。

### 5.1 `Meta`（会话元信息）

```ts
interface Meta {
  label: string;              // 动态返回当前模型
  ready: boolean;             // 反映 API Key 配置状态
  startupErr?: string;
  eventChannel: string;
  cwd: string;
  workspaceRoot?: string;
  workspaceName?: string;
  workspacePath?: string;
  sessionPath?: string;
  gitBranch?: string;
  imageInputEnabled?: boolean;
  autoApproveTools?: boolean;
  bypass?: boolean;           // 旧 JSON 键，YOLO/全权限工具自动审批
  collaborationMode?: CollaborationMode;
  toolApprovalMode?: ToolApprovalMode;
  tokenMode?: TokenMode;
  goal?: string;
  goalStatus?: GoalStatus;
  autoResearch?: AutoResearchCompactView;
}
```

### 5.2 `HistoryMessage` / `HistoryPage` / `CheckpointMeta`

```ts
interface HistoryMessage {
  role: string;
  content: string;
  detail?: string;
  code?: string;
  submitText?: string;
  checkpointTurn?: number;
  createdAt?: number;
  reasoning?: string;
  workDurationMs?: number;
  memoryCitations?: MemoryCitation[];
  level?: "info" | "warn";
  toolCalls?: HistoryToolCall[];
  toolCallId?: string;
  toolName?: string;
  toolResultArchived?: boolean;
  toolResultError?: string;
  pending?: boolean;
  trigger?: string;
  messages?: number;
  summary?: string;
  archive?: string;
}

interface HistoryPage {
  messages: HistoryMessage[];
  startTurn: number;
  endTurn: number;
  totalTurns: number;
  hasOlder: boolean;
}

interface CheckpointMeta {
  turn: number;
  prompt: string;
  files: string[];
  fileCount?: number;
  filesTruncated?: boolean;
  turnFileCount?: number;
  time: number;               // unix ms
  canCode?: boolean;
  canConversation?: boolean;
}
```

### 5.3 `SessionMeta` / `TabMeta`

```ts
interface SessionMeta {
  path: string;
  preview: string;
  title?: string;             // 用户命名；空时回退到 preview
  turns: number;
  createdAt: number;
  lastActivityAt: number;
  modTime: number;            // lastActivityAt 的兼容别名
  deletedAt?: number;         // 已回收会话存在
  current: boolean;
  open: boolean;
  scope?: "project" | "global";
  workspaceRoot?: string;
  topicId?: string;
  topicTitle?: string;
  kind?: "session" | "channel" | string;
  channel?: string;
  channelLabel?: string;
  recovered?: boolean;
  recoveryCopy?: boolean;
  // ...（其余渠道字段省略）
}

interface TabMeta {
  id: string;
  tabType?: "session" | "file";
  scope: string;
  workspaceRoot: string;
  workspaceName: string;
  topicId: string;
  topicTitle: string;
  sessionPath?: string;
  label: string;
  ready: boolean;
  running: boolean;
  pendingPrompt?: boolean;
  backgroundJobs?: number;
  cancelRequested?: boolean;
  cancellable?: boolean;
  mode: Mode;
  collaborationMode?: CollaborationMode;
  toolApprovalMode?: ToolApprovalMode;
  tokenMode?: TokenMode;
  goal?: string;
  goalStatus?: GoalStatus;
  recovered?: boolean;
  recoveryReason?: string;
  recoveryDigest?: string;
  recoveryParentId?: string;
  startupErr?: string;
  active: boolean;
  cwd: string;
  // ...（其余字段省略）
}
```

### 5.4 `ContextInfo` / `BalanceInfo` / `WorkspaceView` / `JobView`

```ts
interface ContextInfo {
  used: number;
  window: number;
  sessionTokens: number;
  compactRatio?: number;
  sessionCost?: number;
  sessionCurrency?: string;
  cacheHitTokens?: number;
  cacheMissTokens?: number;
  sources?: Record<string, UsageSourceStats>;
}

interface BalanceInfo {
  available: boolean;
  display: string;
  err?: string;
}

interface WorkspaceView {
  path: string;
  name: string;
  current: boolean;
}

interface JobView {
  id: string;
  kind: string;               // "bash" | "task"
  label: string;
  status: string;             // "running"
  startedAt: number;          // unix ms
}
```

### 5.5 模式枚举

```ts
type CollaborationMode = "normal" | "plan" | "goal";
type ToolApprovalMode = "ask" | "auto" | "yolo";
type TokenMode = "full" | "economy" | "delivery";  // "full" 是 Balanced 运行时的持久化兼容值
type GoalStatus = "running" | "complete" | "blocked" | "stopped";
```

---

## 6. 前端调用约定

1. **统一入口**：所有组件通过 `app.<Method>()` 调用（`app` 是 `AppBindings` 的 Proxy，自动解析当前绑定）。

   ```ts
   import { app } from "../lib/bridge";
   const meta = await app.Meta();
   ```

2. **按标签页隔离**：带 `ForTab` 后缀的方法作用于指定 `tabID`；无后缀的作用于当前活动标签。会话历史、记忆、上下文、模式等均按标签页隔离。

3. **事件订阅**：`onEvent` 订阅 `agent:event` 事件流；事件含 `tabId`，前端据此路由到对应标签页 reducer。

4. **类型漂移检查**：`bridge.ts` 中的 `_CheckGenToApp` 在编译期比对生成的 `GeneratedApp` 键与 `AppBindings` 键，Go 侧新增/重命名方法时若未同步 `AppBindings` 会报类型错误（方法签名完整比对由调用点 `tsc` 兜底）。

5. **降级策略**：无 Wails、无 HTTP API 时自动回退到 mock 数据（`makeMockApp`），保证纯浏览器 `pnpm dev` 下 UI 可独立开发。

---

## 7. 扩展指南

- **新增 Go 绑定方法**：在 `app.go` 实现 → 运行 `wails generate module` 重新生成 `wailsjs/go/main/App` → 在 `bridge.ts` 的 `AppBindings` 中补充签名 → 若走 HTTP 模式还需在 `createHttpApiBinding` 与 `httpApiAdapter.ts` 增加端点映射。
- **新增事件类型**：在 `types.ts` 扩展 `EventKind` 与 `WireEvent` 字段 → Go 侧通过 `agent:event` 通道下发。
- **注意**：`WireEvent.level` 禁止使用 `"error"`。
