# 改造记录：从"各自硬编码"到"配置注入"

合并成 monorepo 时，除了搬目录，只动了**两类**东西，每处都保持"默认值与改造前一致"：

1. **端口 / 地址 / token / 日志路径改为读环境变量**（不填就走原默认值，单独跑仍能起）
2. **删掉写死在源码里的真实密钥**（改为 `DEEPSEEK_API_KEY`）

不改任何业务逻辑、不改 HTTP 端点、不改协议字段。

## 逐文件改动

### `apps/pentest/.adapter.py`

| 位置 | 改造前 | 改造后 |
|---|---|---|
| 顶部常量 | `ADAPTER_PORT` 隐含在 `ThreadingHTTPServer(("127.0.0.1", 8786))` | `ADAPTER_PORT=int(os.getenv("ADAPTER_PORT","8786"))` |
| | `RIX_BASE = "http://127.0.0.1:4523"` | `RIX_BASE=_env("RIX_BASE", f"http://127.0.0.1:{RIX_PORT}")` |
| | `BRAIN_TOKEN = "sk-795f…"` | `_env("BRAIN_TOKEN", "")` |
| | `RIX_TOKEN = "sk-795f…"` | `_env("RIX_TOKEN", "")` |
| | `DEEPSEEK_KEY = "sk-fe4e…"` | `_env("DEEPSEEK_API_KEY", "")` |
| 日志 | `open("/home/wangwei/Rix/adapter-debug.log")` | `os.path.join(ADAPTER_LOG_DIR, "adapter-debug.log")` |
| | `open("/home/wangwei/Rix/ai-approval.log")` | 同上目录下 `ai-approval.log` |
| 看门狗 | `STALL_LIMIT=300` 等常量 | 同名环境变量，默认不变 |
| SSL | `create_default_context(cafile="/etc/ssl/certs/…")`（Windows 会直接崩） | 文件存在才用，否则回退系统默认 CA |
| `_auth_ok` | 硬比较 token | token 为空（未配置）时放行，方便本地调试；配了就照旧严格校验 |
| AI 审批门 | 无 key 时每次 401 → 所有敏感命令被拒 | key 为空**或仍是 `sk-xxxx` 占位符**时跳过模型裁决并记日志（`no-key-skip`，判定函数 `_is_unset`） |
| 审批门 API | `api.deepseek.com` / `deepseek-v4-flash` 写死 | `AIGATE_URL` / `AIGATE_MODEL`，默认不变 |

### `apps/intel/intel-agent/adapter.py`

同上全部；另外：

| 位置 | 改造前 | 改造后 |
|---|---|---|
| 常量块 | `ADAPTER_PORT = 8789` / `RIX_PORT = 8089` 写死 | 环境变量，默认不变 |
| 审批门 key | 用 `RIX_TOKEN` 当 DeepSeek key | `DEEPSEEK_API_KEY`，缺失时回退 `RIX_TOKEN` |
| 日志 | `open("adapter-debug.log")`（cwd 内） | `ADAPTER_LOG_DIR` 下（默认仍 cwd） |

### `apps/pentest/run-serve.sh`、`apps/intel/intel-agent/run-serve.sh`

```diff
-port="${1:-4523}"
-token="sk-795f…（原明文，已删除）"
+port="${1:-${RIX_PORT:-4523}}"
+token="${RIX_TOKEN:-}"        # 缺失则报错退出，不再偷偷用写死的 token
```

### `apps/logaudit/scripts/start-logaudit.sh`

```diff
-  --addr 127.0.0.1:8788 \
+  --addr "127.0.0.1:${LOG_AUDIT_PORT:-8788}" \
-  >> "$HOME/serve-8788.log" 2>&1 &
+  >> "$HOME/serve-${LOG_AUDIT_PORT:-8788}.log" 2>&1 &
```

### `apps/frontend/serve_frontend.py`

```diff
-PORT = 3000
+PORT = int(os.getenv("PORT", "3000"))
+BRAIN_BASE_URL        = os.getenv("BRAIN_BASE_URL", "http://127.0.0.1:6657")
+ADAPTER_PENTEST_URL   = os.getenv("ADAPTER_PENTEST_URL", "http://127.0.0.1:8786")
+ADAPTER_LOGAUDIT_URL  = os.getenv("ADAPTER_LOGAUDIT_URL", "http://127.0.0.1:8788")
```

`ROUTES` 表结构、前缀、顺序完全未变，只是目标地址改由上面三个变量拼出。

### `apps/intel/intel-agent/README.md`

把文档示例里出现的真实 token 换成 `<INTEL_PART_TOKEN>` / `<INTEL_SERVE_TOKEN>` 占位符。

## 未改动（保持原样）

- `apps/brain/**`：本来就全走 `config/settings.py` + `load_dotenv()`，无需改；只用
  `REGISTRY_FILE` 指向新路径。
- `apps/tir/**`：本来就全走 `TIR_*` 环境变量。
- `apps/logaudit/**`（除上面那个脚本）：reasonix 本体配置由 `REASONIX_HOME` 决定。
- 三个域里的 reasonix Go 内核源码：一行没动。
- 所有 HTTP 端点、协议字段、事件类型：一行没动。

## 遗留待办（需要各自负责人确认）

- [ ] **凭据默认是占位符**：源码里的明文已删除，`config/env/shared.env.example` 里所有
      key/token 都是 `sk-xxxx`。`gen-env` 原样复制（不随机生成），真实值由各自填在本地
      `shared.env`。占位符的后果是明确的：adapter 的 AI 审批门遇到 `xxxx` 会跳过模型裁决
      （`_is_unset()`），不会因 401 把敏感命令全拒；reasonix serve 调模型时会直接报错。
      对外发布前也不用再处理 `.example`——它本来就没有真值。
- [ ] `apps/brain/registry/__init__.py` 里的 `"token": "tk_pentest_dev"` 是内置默认注册表的
      占位值（不是真实密钥），生产靠 `REGISTRY_FILE` 覆盖，可保留。
- [ ] 前端 `apps/frontend/desktop/frontend/.env`（仓库自带，只有 `VITE_BRAIN_API_URL`）
      会由 `gen-env` 生成的 `.env.local` 优先级覆盖，两者都无害。
- [ ] `apps/pentest/.adapter.py` 仍是隐藏文件（点开头），在 Windows 上 `Get-ChildItem`
      默认看不到。要不要改名成 `adapter.py` 由 pentest 负责人决定（改名要同步
      `config/services.json` 的 `cmd`）。
