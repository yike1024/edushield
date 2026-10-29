# 新成员接入：30 分钟加一个域

以"资产测绘域 `assetmap`（adapter 8790 → reasonix serve 8091）"为例。

## 0. 决定形态

| 你的模块是 | 选这个形态 | services.json 里几条 |
|---|---|---|
| reasonix agent，要给大脑当部件 | adapter + engine | 2 条 |
| reasonix agent，能自己扛 submit/status | engine 直连 | 1 条 |
| 自己写的 HTTP 服务（FastAPI/Go/Node） | 单服务 | 1 条 |

## 1. 放代码

```
apps/assetmap/                 ← 你的模块根（能单独 clone 出去跑）
  ├─ .reasonix-home/config.toml   模型与权限（只有你读）
  ├─ adapter.py                   可选：包装成 submit/status/events
  ├─ bin/reasonix                 可选：构建产物（gitignore）
  ├─ requirements.txt / go.mod / package.json   你自己的依赖
  └─ README.md                    你怎么跑、怎么测
```

## 2. 加环境变量模板

`config/env/assetmap.env.tmpl`（照抄 `pentest.env.tmpl` 改端口与 token 名）：

```ini
ADAPTER_PORT=8790
RIX_PORT=8091
RIX_TOKEN=${ASSETMAP_SERVE_TOKEN}
BRAIN_TOKEN=${ASSETMAP_PART_TOKEN}
REASONIX_HOME=./.reasonix-home
DEEPSEEK_API_KEY=${DEEPSEEK_API_KEY}
DEEPSEEK_API_BASE=${DEEPSEEK_API_BASE}
DEEPSEEK_MODEL=${DEEPSEEK_MODEL}
```

再往 `config/env/shared.env.example` 加 `ASSETMAP_SERVE_TOKEN=sk-xxxx` 与
`ASSETMAP_PART_TOKEN=sk-xxxx`（占位符即可）。`gen-env` 直接复制这份 `.example`，
不做随机生成；真实值填在本地 `config/env/shared.env`，占位符或空值会让该域 401。

## 3. 注册服务

在 `config/services.json` 的 `services` 数组里加：

```json
{
  "id": "assetmap-serve",
  "group": "assetmap",
  "role": "engine",
  "kind": "http",
  "cwd": "apps/assetmap",
  "cmd": ["${REASONIX_BIN}", "serve", "--addr", "127.0.0.1:${ASSETMAP_RIX_PORT}", "--auth", "token", "--token", "${ASSETMAP_SERVE_TOKEN}"],
  "envFile": "config/env/assetmap.env",
  "extraEnvFiles": ["apps/assetmap/.reasonix-home/.env"],
  "port": 8091,
  "baseUrl": "http://127.0.0.1:8091",
  "health": { "path": "/status", "expect": 200, "auth": "cookie", "cookieName": "reasonix_token", "cookieVar": "ASSETMAP_SERVE_TOKEN" },
  "postStart": { "path": "/tool-approval-mode", "method": "POST", "cookieVar": "ASSETMAP_SERVE_TOKEN", "body": { "mode": "auto" } },
  "dependsOn": [],
  "startOrder": 42,
  "enabled": true,
  "notes": "资产测绘域（一句话说明）"
},
{
  "id": "assetmap-adapter",
  "group": "assetmap",
  "role": "adapter",
  "kind": "http",
  "cwd": "apps/assetmap",
  "cmd": ["python", "adapter.py"],
  "envFile": "config/env/assetmap.env",
  "port": 8790,
  "baseUrl": "http://127.0.0.1:8790",
  "health": { "path": "/status", "expect": 200, "auth": "none" },
  "dependsOn": ["assetmap-serve"],
  "startOrder": 43,
  "enabled": true
}
```

再在 `groups` 里加一行 `"assetmap": { "desc": "...", "owner": "@你的账号" }`。

## 4. 注册到大脑

`config/registry/brain.registry.json.tmpl`：

```json
"assetmap": { "host": "127.0.0.1", "port": 8790, "token": "${ASSETMAP_PART_TOKEN}", "auth": "bearer", "enabled": true }
```

如果大脑的 `Domain` 枚举里没有这个域，同步在 `apps/brain/protocol/__init__.py` 的
`Domain` 加一个值 —— 这是**唯一**需要动别人代码的地方，改完在 PR 里 @ 大脑负责人。

## 5. 收尾三件事

- `CODEOWNERS` 加一行 `apps/assetmap/ @你的账号`
- `docs/PORTS.md` 端口表补两行
- `docs/HTTP-CONTRACT.md` 如果新增了端点或字段，补上

## 6. 自检清单（PR 前逐条打勾）

- [ ] 端口只从环境变量来（`ADAPTER_PORT` / `RIX_PORT` / `API_PORT`），代码里没有裸数字
- [ ] token / API key 只从环境变量来，仓库里搜不到真实密钥
- [ ] 日志写到 `ADAPTER_LOG_DIR`（默认仓根 `logs/`），不写死 `/home/xxx/...`
- [ ] 有可探测的健康端点（`/status` 或 `/health`），返回 200 不依赖模型是否在跑
- [ ] `scripts/gen-env.*` + `scripts/dev-up.*` 能把它拉起来，`status` 显示 `ok`
- [ ] 没有 import 别的 `apps/<域>`；跨域数据走 HTTP
- [ ] 模块 README 写清：怎么单独跑、怎么单独测、依赖什么外部资源

## 反例（会被 review 拦下）

```python
# ✗ 端口写死
http.server.ThreadingHTTPServer(("127.0.0.1", 8786), H)

# ✓ 从环境变量来，保留原默认值
PORT = int(os.getenv("ADAPTER_PORT", "8786"))
http.server.ThreadingHTTPServer(("127.0.0.1", PORT), H)
```

```python
# ✗ 绝对路径 + 明文 token
LOG = open("/home/wangwei/Rix/adapter-debug.log", "a")
BRAIN_TOKEN = "sk-795ff07c..."

# ✓ 可配 + 可缺省
LOG_DIR = os.getenv("ADAPTER_LOG_DIR", ".")
os.makedirs(LOG_DIR, exist_ok=True)
LOG = open(os.path.join(LOG_DIR, "adapter-debug.log"), "a")
BRAIN_TOKEN = os.environ["BRAIN_TOKEN"]   # 缺失就让启动失败，别偷偷用默认值
```
