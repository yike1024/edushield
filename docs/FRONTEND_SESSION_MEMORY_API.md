# 前端会话记忆与工具集成 — 对接接口文档

> 适用范围：`desktop/frontend`（React + Wails 绑定层）与后端（Go kernel / desktop 进程）之间的对接。
> 本文件只描述前端技术方案、可用的 API 规范、数据结构与交互流程；后端实现细节不在范围内。
> 所有方法均通过 `src/lib/bridge.ts` 的 `app.*` 代理暴露（Wails `Bind` 绑定），事件通过 `onEvent` / `onProjectTreeChanged` 等订阅回调推送。

---

## 0. 可行性结论

| 需求 | 结论 | 依据 |
| --- | --- | --- |
| 新增工具流畅接入前端（三个维度卡顿） | ✅ 可行 | 工具卡片的渲染函数 `subjectOf/diffsFor/summarize` 是硬编码 switch（[tools.ts](file:///home/caoyike/DeepSeek-Reasonix/DeepSeek-Reasonix/desktop/frontend/src/lib/tools.ts#L57-L84)），新增工具落入 default 分支导致展示缺失；改为声明式元数据驱动即可根治，后端已有 `Capabilities` / `MCPServers` / `mcp_surface_ready` 事件支撑 |
| 创建新会话后保留历史数据 | ✅ 可行 | 已有完整会话 CRUD API + `onProjectTreeChanged` 变更事件（见 §3.1） |
| 历史会话折叠展示在左侧 | ✅ 可行 | 左侧 sidebar 已承载 `ProjectTree`（workspace→topic→session 三级 [ProjectNode](file:///home/caoyike/DeepSeek-Reasonix/DeepSeek-Reasonix/desktop/frontend/src/lib/types.ts#L250-L271)），可直接在其上叠加"历史会话"折叠分组；`HistoryPanel` 已有现成会话列表/分组/过滤逻辑可复用 |
| 记忆模块（豆包式会话记忆） | ✅ 可行 | 已有 `Memory/MemoryForTab/Remember/Forget/SaveDoc/MemorySuggestions` 全套接口（见 §3.2），仅需将现有右抽屉/设置页形态改为左侧折叠列表 + 会话级记忆入口 |

**总体判断**：两项功能的数据层与接口层均已具备，前端无需等待后端新增接口，仅需前端组合现有 API 并补齐少量展示逻辑。下文文档按接口对接需要组织，新增/可选接口已单独标注 `[新增]` 供后端排期，其余均为已存在接口。

---

## 1. 功能一：工具集成流畅性

### 1.1 三个维度卡顿的根因（前端侧）

#### 维度 A — 工具卡片渲染层（`src/lib/tools.ts`）
`subjectOf()`（卡片标题）、`diffsFor()`（内联 diff）、`summarize()`（结果一行摘要）三个函数全部是 `switch (name)` 硬编码：
- 新增工具不在 switch 内 → 落到 `default: return str(a, "path") || str(a, "file_path")`（[tools.ts#L81-L83](file:///home/caoyike/DeepSeek-Reasonix/DeepSeek-Reasonix/desktop/frontend/src/lib/tools.ts#L81-L83)）→ 卡片无标题、无 diff、无摘要。
- `ToolCard.tsx` 里 `SUBAGENT_TOOLS` 集合（[ToolCard.tsx#L15](file:///home/caoyike/DeepSeek-Reasonix/DeepSeek-Reasonix/desktop/frontend/src/components/ToolCard.tsx#L15)）同样硬编码子代理工具清单。

**根因**：前端用"工具名 → 展示规则"的映射表，而不是用工具自身的元数据（名称/参数 schema/read-only）驱动渲染。每新增一个工具都要改前端代码，改漏就"卡顿/残缺"。

**前端优化方案**（无需后端配合）：
1. 将 `tools.ts` 的 switch 改写为声明式规则表：
   - 按参数 schema 推断 subject：优先读取 `description` 中标注的 `path`/`command`/`url`/`pattern` 字段，而非枚举工具名。
   - diff 渲染改为"输出含 unified diff 即渲染 DiffView"，不再依赖工具名白名单。
   - summarize 改为按输出结构启发式（行数/JSON key）兜底。
2. 新增工具时，若规则表无匹配，走通用渲染（raw JSON args + output），保证"接入即可用"，避免卡死。
3. 新增前端契约测试 `tools-contract.test.ts`：扫描 `WireTool.name` 白名单，断言所有已登记工具都有对应 subject 规则（模式参考后端 `TestBuiltinToolContractTableMatchesCode`）。

#### 维度 B — 工具清单同步层
- 前端在启动/设置页拉取 `Capabilities()`（[bridge.ts#L238](file:///home/caoyike/DeepSeek-Reasonix/DeepSeek-Reasonix/desktop/frontend/src/lib/bridge.ts#L238)）、`MCPServers()`（[bridge.ts#L239](file:///home/caoyike/DeepSeek-Reasonix/DeepSeek-Reasonix/desktop/frontend/src/lib/bridge.ts#L239)）与 `CapabilityDiagnostics()`（[bridge.ts#L244](file:///home/caoyike/DeepSeek-Reasonix/DeepSeek-Reasonix/desktop/frontend/src/lib/bridge.ts#L244)）。
- 会话运行中 MCP 服务连接/断连、工具面变化通过 `WireEvent.kind === "mcp_surface_ready"` 推送（types.ts 事件枚举 [types.ts#L4-L24](file:///home/caoyike/DeepSeek-Reasonix/DeepSeek-Reasonix/desktop/frontend/src/lib/types.ts#L4-L24)）。

**根因**：工具面变更事件未驱动前端能力面板/权限面板做**增量刷新**，只能整表重拉（全量请求 + 全量重渲染 = 卡顿）。

**前端优化方案**：
1. 订阅 `mcp_surface_ready`（含 `tabId`）后仅刷新对应 tab 的 `ServerView.toolList` 与工具审批策略，不整屏重渲染。
2. 工具清单渲染改为按 `ServerView.status`/`toolChanges`（[MCPToolTrustChangeView](file:///home/caoyike/DeepSeek-Reasonix/DeepSeek-Reasonix/desktop/frontend/src/lib/types.ts#L767-L770)）做 diff 更新。

#### 维度 C — 工具元数据契约层
前端 `WireTool`（[types.ts#L38-L55](file:///home/caoyike/DeepSeek-Reasonix/DeepSeek-Reasonix/desktop/frontend/src/lib/types.ts#L38-L55)）依赖 `readOnly` 字段决定只读/写入样式与审批；`ServerView.trustState / toolPolicies`（[types.ts#L711-L765](file:///home/caoyike/DeepSeek-Reasonix/DeepSeek-Reasonix/desktop/frontend/src/lib/types.ts#L711-L765)）决定权限面板展示。

**根因**：新增工具若后端未随事件下发 `readOnly`/`trust*` 元数据，前端审批与只读样式会回退到默认（保守/放行两难）。

**前端优化方案**：审批按钮与只读样式改为"元数据缺失即显式未知态"，并在 `CapabilityDiagnostics` 报告中暴露缺失项（该能力已存在于 [CapabilityDiagnosticsReport](file:///home/caoyike/DeepSeek-Reasonix/DeepSeek-Reasonix/desktop/frontend/src/lib/types.ts#L1047-L1115)）。

**联动后端**：上一阶段已为内置工具契约增加自动校验（`TestBuiltinToolContractTableMatchesCode`），保证 read-only/描述/schema 与文档同步；前端侧新增 `tools-contract.test.ts` 后两端契约一致，新增工具自动通过校验，不再有"三个维度卡顿"。

---

## 2. 功能二：会话记忆（豆包式会话管理）

### 2.1 目标形态
1. **新建会话后保留历史**：新建会话不销毁已有会话文件；左侧历史列表实时出现新会话与旧会话。
2. **左侧折叠历史会话栏**：左侧 sidebar（现有 `ProjectTree` 区域）增加"历史会话"分组 — 按日期（今天/昨天/更早）折叠，点击展开、单击预览、双击恢复，支持搜索/重命名/删除/恢复（复用 [HistoryPanel.tsx](file:///home/caoyike/DeepSeek-Reasonix/DeepSeek-Reasonix/desktop/frontend/src/components/HistoryPanel.tsx#L20-L47) 交互）。
3. **记忆模块**：会话级与全局记忆在左侧/右侧折叠卡片展示（已保存事实 + 指令文档 + 快捷记忆），参考豆包"会话左侧 + 记忆抽屉"布局。

前端组件边界建议：
- 新增 `SessionHistoryRail.tsx`（左侧常驻折叠列表），复用 `HistoryPanel` 的分组/过滤纯函数（`dayLabel`/`dateBucket`/`sessionScope` 等，[HistoryPanel.tsx#L644-L692](file:///home/caoyike/DeepSeek-Reasonix/DeepSeek-Reasonix/desktop/frontend/src/components/HistoryPanel.tsx#L644-L692)）。
- 记忆入口复用 [MemoryPanel.tsx](file:///home/caoyike/DeepSeek-Reasonix/DeepSeek-Reasonix/desktop/frontend/src/components/MemoryPanel.tsx#L235-L247) 的抽屉，挂接到会话 tab（`MemoryForTab`）。

---

## 3. 接口规范

> 以下均为已存在接口（`app.*` 绑定），`[新增]` 为建议后端补充的轻量接口。数据结构定义见 §4。

### 3.1 会话历史 / 会话管理

| 方法 | 签名 | 返回 | 用途 |
| --- | --- | --- | --- |
| `NewSession` | `NewSession(): Promise<void>` | `-` | 新建会话（前端随后订阅 `onProjectTreeChanged` 刷新列表） |
| `NewSessionForTab` | `(tabID: string): Promise<void>` | `-` | 指定 tab 新建会话 |
| `ListSessions` | `ListSessions(): Promise<SessionMeta[]>` | `SessionMeta[]` | 历史会话列表（新→旧，含 `current`/`open`/`scope`/`recoveryCopy` 标记） |
| `ListTrashedSessions` | `ListTrashedSessions(): Promise<SessionMeta[]>` | `SessionMeta[]` | 回收站会话 |
| `PreviewSession` | `(path: string): Promise<HistoryMessage[]>` | `HistoryMessage[]` | 侧栏单击预览（只读，不加载 tab） |
| `ResumeSession` | `(path: string): Promise<HistoryMessage[]>` | `HistoryMessage[]` | 恢复会话为当前 tab |
| `ResumeSessionPage` | `(path, limit): Promise<HistoryPage>` | `HistoryPage` | 分页恢复（可配 `HistoryPage` 的 `startTurn`/`endTurn`/`hasOlder`） |
| `ResumeSessionForTab` / `ResumeSessionPageForTab` | 同上 + `tabID` | 同左 | 恢复到指定 tab（多 tab 场景） |
| `RenameSession` | `(path, title): Promise<void>` | `-` | 重命名会话 |
| `DeleteSession` | `(path): Promise<void>` | `-` | 移入回收站 |
| `RestoreSession` | `(path): Promise<void>` | `-` | 从回收站恢复 |
| `DeleteRecoveryCopy` | `(path): Promise<void>` | `-` | 清理恢复副本 |
| `ListProjectTree` | `(): Promise<ProjectNode[]>` | `ProjectNode[]` | 左侧项目树（workspace→topic→session，含 `createdAt`/`lastActivityAt`/`open`/`running`） |
| `CreateTopic` | `(scope, workspaceRoot, title): Promise<TopicMeta>` | `TopicMeta` | 新建话题（分组） |
| `RenameTopic` / `DeleteTopic` | 见 [bridge.ts#L418-L420](file:///home/caoyike/DeepSeek-Reasonix/DeepSeek-Reasonix/desktop/frontend/src/lib/bridge.ts#L418-L420) | `Promise<void>` | 分组重命名/删除 |
| `OpenTopicSession` | `(scope, workspaceRoot, topicID, sessionPath): Promise<TabMeta>` | `TabMeta` | 打开指定会话 tab |
| `History` / `HistoryPage` | `(): Promise<HistoryMessage[]>` / `(beforeTurn, limit): Promise<HistoryPage>` | 见 §4 | 当前会话消息（预览/导出用） |

**事件**：`onProjectTreeChanged(() => void)`（[bridge.ts#L773](file:///home/caoyike/DeepSeek-Reasonix/DeepSeek-Reasonix/desktop/frontend/src/lib/bridge.ts#L773)）— 会话/话题/工作区任何增删改后触发，前端据此增量刷新左侧列表；`onSessionRecovered` / `onSessionRecoveryFailed`（[bridge.ts#L780-L787](file:///home/caoyike/DeepSeek-Reasonix/DeepSeek-Reasonix/desktop/frontend/src/lib/bridge.ts#L780-L787)）— 冲突恢复通知。

### 3.2 记忆模块

| 方法 | 签名 | 返回 | 用途 |
| --- | --- | --- | --- |
| `Memory` | `(): Promise<MemoryView>` | `MemoryView` | 全局记忆总览（docs/facts/archives/scopes） |
| `MemoryForTab` | `(tabID): Promise<MemoryView>` | `MemoryView` | 当前会话（工作区）记忆 |
| `Remember` | `(scope, note): Promise<string>` | 写入路径 | 快速记忆（scope ∈ user/project/local） |
| `RememberForTab` | `(tabID, scope, note): Promise<string>` | 写入路径 | 会话级快速记忆 |
| `Forget` / `ForgetForTab` | `(name)` / `(tabID, name): Promise<void>` | `-` | 删除已保存事实 |
| `SaveDoc` / `SaveDocForTab` | `(path, body): Promise<string>` | 写入路径 | 编辑指令文档（REASONIX.md 等） |
| `MemorySuggestions` / `ForTab` | `(): Promise<MemorySuggestionsView>` | `MemorySuggestionsView` | 记忆/技能候选（扫描生成） |
| `AcceptMemorySuggestion` / `ForTab` | `(suggestion: MemorySuggestion): Promise<string>` | 写入路径 | 采纳候选事实 |
| `AcceptSkillSuggestion` / `ForTab` | `(suggestion: SkillSuggestion): Promise<string>` | 写入路径 | 采纳候选技能 |

**事件**：`WireEvent.kind === "memory_compiler_stats"`（[WireEvent.memoryCompiler](file:///home/caoyike/DeepSeek-Reasonix/DeepSeek-Reasonix/desktop/frontend/src/lib/types.ts#L157-L172)）— 记忆注入统计，可用于状态栏/面板展示记忆是否生效（排查"记忆模块未生效"的直接证据）。

### 3.3 工具能力面

| 方法 | 签名 | 返回 | 用途 |
| --- | --- | --- | --- |
| `Capabilities` | `(): Promise<CapabilitiesView>` | `CapabilitiesView` | 服务/技能/技能根/插件总览 |
| `MCPServers` | `(): Promise<ServerView[]>` | `ServerView[]` | MCP 服务（含 `toolList`/`trustState`/`toolPolicies`） |
| `CapabilityDiagnostics` | `(includeSessionRuntime): Promise<CapabilityDiagnosticsReport>` | 报告 | 能力诊断（新增工具元数据缺失定位） |
| `ToolResultForTab` | `(tabID, toolID): Promise<{ args; output } | null>` | 工具数据 | 卡片展开时懒加载被归档的工具详情 |

**事件**：`WireEvent.kind === "mcp_surface_ready"` — MCP 工具面变更；`"tool_dispatch"` / `"tool_result"` / `"tool_progress"`（`WireEvent.tool: WireTool`）— 会话流中的工具卡片数据（见 [types.ts#L174-L204](file:///home/caoyike/DeepSeek-Reasonix/DeepSeek-Reasonix/desktop/frontend/src/lib/types.ts#L174-L204)）。

### 3.4 建议新增（后端排期，前端不强依赖）

| 方法 | 签名 | 说明 |
| --- | --- | --- |
| `SessionSummaries(paths: string[]): Promise<SessionSummary[]>` `[新增]` | 入参会话 path 数组 | 返回 `{ path, title, preview, turns, lastActivityAt, tags? }`，供左侧列表一次拉取多会话摘要，减少 N 次 `PreviewSession` |
| `MemoryForSession(path): Promise<MemoryView>` `[新增]` | 入参会话语义路径 | 会话归档后按 path（而非 tabID）取记忆，保证 tab 关闭后记忆仍可读 |
| `SearchSessions(query, cursor, limit): Promise<{ items: SessionMeta[]; cursor?; hasMore: boolean }>` `[新增]` | 分页搜索 | 会话数大时左侧搜索分页化（当前 `ListSessions` 全量返回） |

---

## 4. 数据结构定义

> 完整定义见 [types.ts](file:///home/caoyike/DeepSeek-Reasonix/DeepSeek-Reasonix/desktop/frontend/src/lib/types.ts)。以下为本方案关键结构。

### 4.1 会话（SessionMeta）
```ts
interface SessionMeta {
  path: string;            // 会话文件路径（唯一标识）
  preview: string;         // 首条消息预览（列表显示主力）
  title?: string;          // 用户重命名标题，优先于 preview
  turns: number;
  createdAt: number;       // unix ms
  lastActivityAt: number;  // unix ms（列表排序/日期分组依据）
  modTime: number;         // lastActivityAt 兼容别名
  deletedAt?: number;      // 回收站标记
  current: boolean;        // 是否是当前活动会话
  open: boolean;           // 是否有打开的 tab
  scope?: "project" | "global";
  workspaceRoot?: string;  // 项目根（项目分组依据）
  topicId?: string;        // 话题分组
  topicTitle?: string;
  kind?: "session" | "channel";
  recovered?: boolean;     // 冲突恢复产生
  recoveryCopy?: boolean;  // 内容与父分支一致的副本（清理对象）
}
```
引用：[types.ts#L443-L469](file:///home/caoyike/DeepSeek-Reasonix/DeepSeek-Reasonix/desktop/frontend/src/lib/types.ts#L443-L469)

### 4.2 项目树节点（ProjectNode，左侧结构化展示）
```ts
interface ProjectNode {
  key: string;
  kind: "project" | "topic" | "session" | "global_folder" | "global_topic" | "global_session";
  label: string;
  root?: string;            // project: 工作区根
  topicId?: string;
  sessionPath?: string;     // session: 会话路径
  turns?: number;
  createdAt?: number;
  lastActivityAt?: number;  // 话题/会话排序
  open?: boolean;
  running?: boolean;
  recovered?: boolean;
  children?: ProjectNode[];
}
```
引用：[types.ts#L250-L271](file:///home/caoyike/DeepSeek-Reasonix/DeepSeek-Reasonix/desktop/frontend/src/lib/types.ts#L250-L271)

### 4.3 历史消息分页（HistoryPage / HistoryMessage / HistoryToolCall）
```ts
interface HistoryPage {
  messages: HistoryMessage[]; // 一页消息
  startTurn: number;
  endTurn: number;
  totalTurns: number;
  hasOlder: boolean;          // 是否还有更早（用于"加载更多"）
}
interface HistoryMessage {
  role: string; content: string; detail?: string;
  createdAt?: number; reasoning?: string;
  toolCallId?: string; toolName?: string;
  toolCalls?: HistoryToolCall[];   // 工具调用（含 arguments/diff/added/removed）
  memoryCitations?: MemoryCitation[]; // 记忆引用
  pending?: boolean;
}
```
引用：[types.ts#L372-L406](file:///home/caoyike/DeepSeek-Reasonix/DeepSeek-Reasonix/desktop/frontend/src/lib/types.ts#L372-L406)

### 4.4 记忆（MemoryView / MemoryFact / MemorySuggestion）
```ts
interface MemoryView {
  docs: MemoryDoc[];        // 指令文件（scope: user|ancestor|project|local）
  facts: MemoryFact[];      // 已保存事实（read-only，模型通过 remember 拥有）
  archives: MemoryArchive[];// 归档事实
  scopes: MemoryScope[];    // 可选作用域（快速记忆下拉）
  storeDir: string; storeGlobalDir?: string;
  available: boolean;       // 记忆存储是否可用（不可用显示原因）
}
interface MemoryFact {
  name: string; title?: string; description: string;
  type: "user" | "feedback" | "project" | "reference";
  body: string;
}
interface MemorySuggestion extends MemoryFact { id: string; reason: string; evidence: string[]; }
```
引用：[types.ts#L979-L1041](file:///home/caoyike/DeepSeek-Reasonix/DeepSeek-Reasonix/desktop/frontend/src/lib/types.ts#L979-L1041)

### 4.5 工具能力面（CapabilitiesView / ServerView / WireTool）
```ts
interface CapabilitiesView {
  servers: ServerView[]; skills: SkillView[];
  skillRoots: SkillRootView[]; plugins: PluginView[];
}
interface ServerView {
  name: string; status: "connected" | "deferred" | "failed" | "initializing" | "disabled";
  builtIn?: boolean; autoStart: boolean; tools: number;
  toolList?: MCPToolView[];          // 工具清单（name/description/readOnlyHint/schemaError）
  trustState?: "official" | "workspace" | "session" | "changed" | "untrusted";
  toolPolicies?: Record<string, MCPToolPolicy>;  // 审批策略 approval_mode
  changedTools?: string[]; toolChanges?: MCPToolTrustChangeView[];
}
interface WireTool {  // 会话流工具事件
  id?: string; name: string; args?: string; output?: string; err?: string;
  readOnly: boolean;          // 关键：只读/写入样式与审批
  truncated?: boolean; durationMs?: number; partial?: boolean;
  diff?: string; added?: number; removed?: number;
  parentId?: string;          // 子代理调用归属
}
```
引用：[types.ts#L833-L838](file:///home/caoyike/DeepSeek-Reasonix/DeepSeek-Reasonix/desktop/frontend/src/lib/types.ts#L833-L838) / [types.ts#L711-L765](file:///home/caoyike/DeepSeek-Reasonix/DeepSeek-Reasonix/desktop/frontend/src/lib/types.ts#L711-L765) / [types.ts#L38-L55](file:///home/caoyike/DeepSeek-Reasonix/DeepSeek-Reasonix/desktop/frontend/src/lib/types.ts#L38-L55)

---

## 5. 交互流程

### 5.1 左侧历史会话折叠栏（会话生命周期）
```
启动                        ListTabs() + ListSessions() + ListProjectTree()
   │                              │
   │                              ▼
   │                   状态: tabs[] / sessions[] / tree[]
   │                              │
新建会话 (＋ 按钮) ──► app.NewSession()
   │                              │
   │                   后端触发 onProjectTreeChanged
   │                              │
   │                              ▼
   │                   sessionHistoryRail 增量刷新（新增会话置顶 Today 分组）
   │
左侧单击会话 ──► app.PreviewSession(path) → 只读预览（不切 tab）
左侧双击会话 ──► app.ResumeSession(path) → 打开为当前 tab
右键菜单    ──► RenameSession / DeleteSession(移回收站) / RestoreSession / DeleteRecoveryCopy
回收站清空  ──► ListTrashedSessions → RestoreSession / DeleteSession
```

### 5.2 记忆模块加载与写入
```
打开记忆入口(会话级) ──► app.MemoryForTab(activeTabId) → MemoryView
                         ├─ facts → 折叠卡片（[[name]] 交叉链接跳转）
                         ├─ docs  → 内联编辑 → SaveDocForTab(path, body)
                         └─ scopes→ Quick-add → RememberForTab(scope, note)
打开"建议"      ──► app.MemorySuggestionsForTab(tabId) → 候选列表
                         └─ 采纳 → AcceptMemorySuggestionForTab(candidate)
会话流中记忆生效 ──► 订阅 onEvent(memory_compiler_stats) → 状态栏展示注入统计
```

### 5.3 新增工具接入（前端连贯路径）
```
后端新增内置工具 → 后端契约测试自动校验（read-only/描述/schema/文档一致）
   │
   ▼
前端:
 1. tools.ts 声明式规则表命中或走通用渲染 → 卡片"接入即可用"
 2. 订阅 mcp_surface_ready → 能力面板/权限面板增量刷新 toolList
 3. tools-contract.test.ts（前端契约）→ 校验新工具在前端有展示规则
   │
   ▼
部署后 CapabilityDiagnostics() → 检查元数据缺失 → 无缺失即全链路通畅
```

---

## 6. 前端实现清单（供排期）

| 项 | 落点 | 产出 |
| --- | --- | --- |
| 工具卡片声明式渲染 | `src/lib/tools.ts`、`ToolCard.tsx` | switch → 规则表 + 通用兜底 |
| 工具清单增量刷新 | `CapabilitiesPanel.tsx` + `mcp_surface_ready` 订阅 | 按 tab 增量更新 |
| 前端工具契约测试 | `src/__tests__/tools-contract.test.ts` | 新增工具自动校验 |
| 左侧历史会话栏 | 新组件 `SessionHistoryRail.tsx`（复用 HistoryPanel 分组/过滤纯函数） | 折叠分组 + 搜索 + 右键菜单 |
| 会话新建后刷新 | `App.tsx` 订阅 `onProjectTreeChanged` | 新建会话后列表实时更新 |
| 记忆入口挂接 | `MemoryPanel.tsx` + `MemoryForTab` | 会话级记忆左/右侧折叠卡片 |
| 可选：会话摘要批量接口 | 后端排期 `SessionSummaries` | 大数据量下左侧列表一次拉取 |