# Web 运行时行为类设置 —— 后端读取接口文档

> 版本 v1.0 ｜ 适用：`aisoc-brain`（FastAPI，端口 **6657**）后端同事
> 交付背景：前端 L1 持久化闭环（Web 版设置面板）需要后端提供「运行时行为类字段」的读取接口。
> 纯界面类字段（语言 / 桌面风格 / 主题 / 显示模式 / 信息栏 / 关闭行为）由前端 localStorage 闭环，**不在本文档范围**。

---

## 1. 为什么需要这个接口

前端 Web 版设置面板目前把全部设置持久化到浏览器 `localStorage`（`reasonix-settings:` 前缀），
其中大部分是「纯界面呈现」字段，前端自己就能闭环。

但有 7 个字段属于**运行时行为**——它们决定大脑服务（Agent 执行、工具审批、子智能体、记忆编译）的实际行为，
**必须由后端真正读取并生效**。前端只负责：把用户的选择持久化到 localStorage，并在启动 / 打开设置时
向后端**拉取**这些字段作为「权威值」回填。

**Source of Truth 约定（重要）：**
- 后端接口可用 → 以**后端返回值**为权威，前端用它覆盖 localStorage；
- 后端接口不可用（超时 / 未实现 / 4xx）→ 前端**静默降级**到 localStorage 本地值，不报错、不阻塞设置面板。

---

## 2. 接口定义

### 2.1 读取全部运行时行为字段

```
GET /api/settings/runtime
```

**200 响应**（示例）：

```json
{
  "defaultToolApprovalMode": "ask",
  "autoPlan": "off",
  "memoryCompilerEnabled": false,
  "subagentEffort": "medium",
  "maxSubagentDepth": 2,
  "coldResumePrune": true,
  "reasoningLanguage": "auto"
}
```

**约定：**
- 始终返回**全量 7 个字段**，缺一不可（前端按字段级缺省回退，但建议后端给全）；
- 未配置的字段返回各自的**默认值**（见 §3），不要返回 `null`；
- 响应头统一 `Content-Type: application/json`，CORS 已全开。

### 2.2 （可选）写入/保存

```
POST /api/settings/runtime
```

```json
{
  "defaultToolApprovalMode": "yolo"
}
```

> 仅当后端希望同时承担「运行时设置持久化」职责时实现。当前 L1 阶段前端不调用写接口，
> 前端只读 + 本地写。后续若后端实现持久化，可切换为写后端；**本文档不阻塞该决策**。

### 2.3 错误约定

| 场景 | 表现 | 前端处理 |
|---|---|---|
| 接口未实现（404/405） | HTTP 错误 | 降级 localStorage，不报错 |
| 服务不可达 | 网络错误 / 超时（建议后端 5s 内返回） | 降级 localStorage，不阻塞 UI |
| 字段缺失 | 200 但缺字段 | 该字段用 localStorage / 默认值 |

---

## 3. 字段清单（运行时行为类）

| 字段 | 类型 | 允许值 | 默认值 | 语义 | 前端 localStorage key |
|---|---|---|---|---|---|
| `defaultToolApprovalMode` | string | `"ask"` / `"auto"` / `"yolo"` | `"auto"` | 新会话默认工具审批模式 | `reasonix-settings:defaultToolApprovalMode` |
| `autoPlan` | string | `"off"` / `"on"` | `"off"` | 自动计划模式开关 | `reasonix-settings:autoPlan` |
| `memoryCompilerEnabled` | boolean | `true` / `false` | `false` | Memory v5 执行编译器开关 | `reasonix-settings:memoryCompilerEnabled` |
| `subagentEffort` | string | 由后端 effort 枚举定义（前端透传，建议含 `low`/`medium`/`high`/`auto`） | `"medium"` | 子智能体默认努力程度 | `reasonix-settings:subagentEffort` |
| `maxSubagentDepth` | number | 正整数（前端 UI 限 1 / 2） | `2` | 子智能体最大嵌套深度 | `reasonix-settings:agent.maxSubagentDepth` |
| `coldResumePrune` | boolean | `true` / `false` | `true` | 冷启动恢复时是否剪枝上下文 | `reasonix-settings:agent.coldResumePrune` |
| `reasoningLanguage` | string | `"auto"` / `"zh"` / `"en"` | `"auto"` | 推理链输出语言 | `reasonix-settings:agent.reasoningLanguage` |

> 前端对 `agent.*` 字段使用点分 key 持久化；后端接口返回**扁平字段名**（不含 `agent.` 前缀），如上表。

---

## 4. 前端对接方式（已就绪）

前端 `webApiProxy.ts` 的 `Settings()` 已实现 hydrate 闭环：

```ts
async Settings(): Promise<SettingsView> {
  this.hydrateSettingsFromStorage();            // localStorage 回填（现有效）
  // （待后端接口就绪后，在此处追加：）
  // const runtime = await aisocApi.getRuntimeSettings();  // 权威值覆盖
  // this.applyRuntimeSettings(runtime);
  return this.settings;
}
```

后端接口就绪后，前端接入点：
1. `GET /api/settings/runtime` 在 `Settings()` 与 `DesktopStartupSettings()` 中调用；
2. 返回成功 → 用后端值覆盖 `this.settings` 对应字段（并可选同步回 `settingsStorage`）；
3. 返回失败 → 保留当前 localStorage 回填结果，静默继续。

**验收标准（后端）**：`curl http://127.0.0.1:6657/api/settings/runtime` 返回 §2.1 的 7 字段 JSON，且改动任一字段后再次 GET 返回值一致（若实现了持久化）。
