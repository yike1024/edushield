# EduShield 校园智盾 · 统一仓库

六个成员各写一个模块，**模块之间只通过 HTTP 通信，代码互不 import**。本仓把它们放进
一个文件夹里统一管理：一套端口表、一份启动编排、一份环境变量，但每个模块仍是独立进程、
独立技术栈、独立负责人。任何模块都可以单独跑，也可以随时抽出去独立部署。

```
                       浏览器
                         │
             ┌───────────┴────────────┐
             │  frontend :3000        │  静态 dist + 反向代理
             │  (dev: vite :5173)     │  /aisoc-*/api → 6657
             └───────────┬────────────┘
                         │ HTTP / SSE
             ┌───────────┴────────────┐
             │  brain :6657           │  编排 / 判定 / 报告 / SSE
             │  FastAPI + SQLite      │  registry 定位各部件
             └──┬────────┬────────┬───┘
                │        │        │        HTTP（Bearer / Cookie）
     ┌──────────┴─┐ ┌────┴─────┐ ┌┴──────────────┐   ┌──────────────┐
     │ pentest    │ │ logaudit │ │ intel         │   │ tir :8090    │
     │ adapter    │ │ serve    │ │ adapter :8789 │   │ 威胁警报+应急 │
     │ :8786      │ │ :8788    │ │   ↓           │   │ 响应子 Agent │
     │   ↓        │ │(reasonix)│ │ serve :8089   │   └──────────────┘
     │ serve :4523│ └──────────┘ │ (reasonix)    │
     │(reasonix)  │              └───────────────┘
     └────────────┘
```

## 目录结构

```
edushield-platform/
├─ apps/                       ← 六个模块，各自一个子目录，成员只动自己的
│  ├─ brain/                   AiSOC 大脑（FastAPI 6657，编排/判定/报告）
│  ├─ frontend/                前端（Vite + React，静态代理 serve_frontend.py）
│  ├─ pentest/                 渗透验证域（rix-agent 内核 + adapter）
│  ├─ logaudit/                日志审计域（DeepSeek-Reasonix + logaudit 工具链）
│  ├─ intel/                   情报收集域（rax-intel-agent）
│  └─ tir/                     威胁警报 / 应急响应子 Agent（FastAPI 8090）
├─ config/                     ← 跨模块的配置都在这里
│  ├─ services.json            ★ 唯一事实来源：端口、启动命令、健康检查、依赖顺序
│  ├─ env/                     ★ 环境变量模板（*.env.tmpl）→ 渲染出 *.env（不进 git）
│  ├─ registry/                大脑的部件注册表模板（渲染后带真实 token）
│  └─ reasonix/               三份 reasonix 配置的差异说明（真实文件在各自模块内）
├─ scripts/                    生成配置 / 启停 / 巡检（Windows 与 Linux 各一套）
├─ packages/contracts/         跨模块协议（TaskMessage / Finding / Report）的落地约定
├─ docs/                       架构、HTTP 契约、端口表、加模块、迁移
├─ logs/                       运行日志（gitignore）
└─ .run/                       进程状态（gitignore）
```

## 端口表

| 服务 id | 端口 | 组件 | 负责人 |
|---|---|---|---|
| `frontend` | 3000 | 静态 dist + 反向代理 | @linyuxuan |
| `frontend-dev` | 5173 | vite dev server（可选，与 3000 二选一） | @linyuxuan |
| `brain` | 6657 | 大脑 FastAPI（统一入口） | @linyuxuan |
| `tir` | 8090 | 威胁警报 / 应急响应 | @chenyiming |
| `pentest-adapter` | 8786 | 渗透域适配层（大脑只认这个端口） | @wangwei |
| `pentest-serve` | 4523 | reasonix serve（渗透域推理引擎） | @wangwei |
| `logaudit-serve` | 8788 | reasonix serve（日志审计域，serve 直连） | @linchen |
| `intel-adapter` | 8789 | 情报域适配层 | @wangwei |
| `intel-serve` | 8089 | reasonix serve（情报域推理引擎） | @wangwei |

改端口只改 `config/services.json`（+ 对应 `config/env/*.env.tmpl` 里的同名变量），
启动脚本、健康检查、状态表、registry 会一起跟着变。

## 5 分钟跑起来

```powershell
# 1) 生成环境：config/env/shared.env（key/token 默认是占位符 sk-xxxx，先换成真实值再跑）
pwsh scripts/gen-env.ps1

# 2) 按顺序拉起全部服务（各自独立进程，日志落 logs/）
pwsh scripts/dev-up.ps1

# 3) 一屏看状态
pwsh scripts/status.ps1

# 4) 全停
pwsh scripts/dev-down.ps1
```

Linux 服务器同名脚本（读同一份 `services.json`）：

```bash
bash scripts/gen-env.sh
bash scripts/dev-up.sh            # 或 --group pentest / --only brain,tir
bash scripts/status.sh
bash scripts/dev-down.sh
```

只想起一个域（本地调试自己的模块，不打扰别人）：

```powershell
pwsh scripts/dev-up.ps1 -Group logaudit      # serve 8788
pwsh scripts/dev-up.ps1 -Only brain,tir      # 大脑 + TIR
pwsh scripts/dev-up.ps1 -Only frontend-dev   # 前端热更新
```

> `pentest / logaudit / intel` 三个 reasonix 进程需要先构建二进制
> （`apps/<域>/bin/reasonix`，`make build`）。缺二进制时 `dev-up` 会直接告诉你
> `need-build`，而不是起一个空壳进程。

## 配置地图：改什么去哪里

| 想改的东西 | 改这里 | 会不会影响别人 |
|---|---|---|
| 端口 / 启动命令 / 依赖顺序 / 健康检查 | `config/services.json` | 影响整仓，改动要 review |
| API key、代理、部件 token | `config/env/shared.env`（由 `.example` 复制） | 影响所有域 |
| 某个域的模型/权限/工具 | `apps/<域>/.reasonix-home/config.toml` | 只影响该域 |
| 某域的运行参数（超时、目录） | `config/env/<域>.env.tmpl` | 只影响该域 |
| 大脑识别哪些部件、指向哪个端口 | `config/registry/brain.registry.json.tmpl` | 大脑与对应域 |
| 跨模块字段（TaskMessage/Finding/Report） | `docs/HTTP-CONTRACT.md` + `packages/contracts/` | 全部，必须同步版本 |

约定：**端口/依赖归整仓，模型/权限归模块，密钥归 `shared.env`**。三类不混写，
就不会出现"改个端口要翻六个仓库"的情况。

## 模块边界（成员协作规则）

1. **不跨目录 import**。需要别的模块的数据，走 HTTP（大脑是唯一编排者，域之间不直连）。
2. **对外只暴露契约里的端点**（`/submit` `/status` `/events` 或 `/api/tir/*`），
   内部实现随便改。
3. **端口从环境变量来**，不在代码里写死（见 `docs/ADD-MODULE.md` 的自检清单）。
4. **密钥只从环境变量来**，任何 `.env` / token 都不进 git（`.gitignore` 已覆盖）。
5. **改契约先改文档**：`docs/HTTP-CONTRACT.md` 里的字段加一次、版本加一次，
   六个模块按需跟进，而不是某一方偷偷加字段。

## 文档索引

| 文档 | 内容 |
|---|---|
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | 整体架构、一次任务的完整链路、为什么这样切分 |
| [docs/HTTP-CONTRACT.md](docs/HTTP-CONTRACT.md) | 模块间 HTTP 契约（逐个端点、鉴权、超时、错误码） |
| [docs/PORTS.md](docs/PORTS.md) | 端口与端口冲突排查 |
| [docs/ADD-MODULE.md](docs/ADD-MODULE.md) | 新成员接入：30 分钟加一个域 |
| [docs/MIGRATION.md](docs/MIGRATION.md) | 从六个独立仓库合并到本仓（保留 git 历史） |
| [docs/REFACTOR-LOG.md](docs/REFACTOR-LOG.md) | 合并时对源码做过的**全部**改动（端口/token 环境变量化） |
| [config/reasonix/README.md](config/reasonix/README.md) | 三份 reasonix 配置的差异与维护约定 |
| [config/registry/README.md](config/registry/README.md) | 大脑部件注册表的格式与加域方法 |
| [packages/contracts/README.md](packages/contracts/README.md) | 协议 schema 的生成与各语言用法 |
