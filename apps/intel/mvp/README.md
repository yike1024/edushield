# Reasonix Security Intel Agent · MVP

把 Reasonix 改造为"渗透测试 / 安全情报收集"AI 助手的最小可跑骨架。

## 当前状态

| 组件 | 状态 |
|---|---|
| 工作目录 `mvp/` | ✅ 完成 |
| KB 语料（5 篇，覆盖 policy / playbook / internal / attack） | ✅ 完成 |
| 领域人格提示词 `mvp/prompts/security_intel.md` | ✅ 完成 |
| Skill `threat-intel-collector` | ✅ 完成 |
| `cmd/reasonix-plugin-threatintel/`（8 文件，1378 行） | ✅ 完成 |
| `mvp/reasonix.toml`（DeepSeek + 3 插件 + sandbox + permissions） | ✅ 完成 |
| `.NET` 编译 case + seckb 二进制 | ⏳ **等 Go 装好后** |
| 编译 threatintel 二进制 | ⏳ **等 Go 装好后** |
| `seckb -load mvp/kb-corpus` 灌入 KB | ⏳ **等 Go 装好后** |
| 冒烟测试 | ⏳ **等 Go 装好后** |

## 等 Go 装好后执行（按顺序）

### 1. 编译三个 MCP 插件

```powershell
cd D:\chengxu\Reasonix
go build -o bin/reasonix-plugin-case.exe        .\cmd\reasonix-plugin-case
go build -o bin/reasonix-plugin-seckb.exe       .\cmd\reasonix-plugin-seckb
go build -o bin/reasonix-plugin-threatintel.exe .\cmd\reasonix-plugin-threatintel
ls bin\
```

预期三个 `.exe` 都出现，每个 ~12 MB（含 modernc.org/sqlite 静态库）。

如果编译报错，**先看错误信息**：
- 拼写错误 → 修源码
- import 循环 → 检查是否误引了 `internal/`
- `undefined: xxx` → 大概率是 `envOr` / `getenv` 重复定义，把多余的删掉

### 2. 把二进制放到 PATH 或 mvp 同级

最简单：复制到 `mvp/bin/`：

```powershell
mkdir D:\chengxu\Reasonix\mvp\bin
copy bin\reasonix-plugin-case.exe        D:\chengxu\Reasonix\mvp\bin\
copy bin\reasonix-plugin-seckb.exe       D:\chengxu\Reasonix\mvp\bin\
copy bin\reasonix-plugin-threatintel.exe D:\chengxu\Reasonix\mvp\bin\
```

> `reasonix.toml` 用的是裸命令名 `command = "reasonix-plugin-seckb"`，所以三个二进制必须在 PATH 里，或放在 `reasonix` 启动时的工作目录。

### 3. 灌入 KB 语料

```powershell
cd D:\chengxu\Reasonix\mvp
..\bin\reasonix-plugin-seckb.exe -load .\kb-corpus
```

预期看到 `loaded 5 documents across 4 collections` 之类的输出。
执行完后应生成 `mvp\seckb.db`（SQLite）。

### 4. 配置 API Key

```powershell
$env:DEEPSEEK_API_KEY   = "sk-..."
# 可选：拿到 key 后填，能大幅提升 NVD / GHSA 速率
$env:NVD_API_KEY        = "<从 https://nvd.nist.gov/developers/request-an-api-key 申请>"
$env:GITHUB_TOKEN        = "ghp_..."
```

> **不要把 key 写进 toml 文件**。`reasonix.toml` 用 `${DEEPSEEK_API_KEY}` / `${NVD_API_KEY:-}` 引用操作系统环境变量。

### 5. 启动 Reasonix 并冒烟测试

```powershell
cd D:\chengxu\Reasonix\mvp
..\bin\reasonix.exe   # 或者: ..\cmd\reasonix\reasonix.exe
# 启动后尝试这些 prompt 来验证链路:

> 列出当前 KB 都有哪些 collection 和文档数量
> 查一下 CVE-2024-12345 的 KEV 状态
> 帮我看一下 T1566.001 的处置预案
```

预期：
- 启动后 `mcp__threatintel__*` 工具出现在工具列表
- KB 检索返回 4 条 collection（policy / playbook / internal / attack）
- KEV 检查成功返回 JSON（CVE-2024-12345 大概率不在 KEV，工具会返回 `on_kev: false`）

### 6. 失败排查

| 症状 | 排查 |
|---|---|
| 启动后找不到 `mcp__threatintel__intel_*` | 三个 exe 不在 PATH；或 reasonix.toml 的 `[plugins]` 段格式错 |
| `kb_search` 返回 0 结果 | `seckb -load` 没跑；或 `mvp/seckb.db` 没生成 |
| `intel_cve_lookup` 报 `NVD HTTP 429` | 没设 NVD_API_KEY；等 30s 再试；或启用代理 |
| `reasonix` 命令找不到 | 重新构建 `cmd/reasonix`：`go build -o bin/reasonix.exe .\cmd\reasonix` |
| 沙箱拦截写入 mvp/ | 检查 `reasonix.toml` 的 `workspace_root` 路径前缀 |

## 关键设计点（写进 PR 描述时用）

- **职责分离**：`threatintel` 插件只读外部源，把规范化结果通过 `kb_ingest`
  灌入 `seckb`。durable knowledge 只在 seckb，threatintel 进程重启不影响
- **缓存层**：所有外部响应进 SQLite 缓存（modernc.org/sqlite WAL），可离线
  复盘、防限流、防外网抖动
- **失败透明**：所有工具调用都返回 `fetched_at` + 源 URL；不可达时明示，不
  默默回退到模型记忆
- **零猜测原则**（写在 system prompt）：模型不会"听起来合理"地编 CVE 编
  ATT&CK 编号，每条断言都有 KB 或外部源引用
- **凭据不入盘**：所有 API key 通过 `env = { KEY = "${VAR}" }` 引用系统环境
  变量，TOML 文件本身可以提交进 git

## 下一步（Go 跑通后）

1. 启用 seckb 的 embedding rerank（配 `REASONIX_SECKB_EMBED_*` env），把
   纯 BM25 升级到 BM25+向量重排
2. 编写 `cve-feed` 集合的灌入脚本（建议放 `mvp/scripts/ingest-recent.ps1`），
   跑 `intel_kev_recent(days=14)` 后批量 `kb_ingest` 到 `cve-feed` 集合
3. 接入 VS Code / Zed via ACP（`reasonix acp --port 7000`）
4. 内部 postmortem 流程改造：要求所有 postmortem 通过 `kb_ingest` 写
   `internal` 集合
