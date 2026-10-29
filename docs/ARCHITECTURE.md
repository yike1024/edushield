# 架构：六个独立模块，一个仓库

## 三条硬边界

| 边界 | 规则 | 违反的后果 |
|---|---|---|
| **进程边界** | 一个模块 = 一个（或两个）独立进程，独立崩、独立重启 | 某个域 OOM 会拖垮整套 |
| **协议边界** | 跨模块只走 HTTP（+SSE），不 import 对方代码 | 改一行字段要六个仓库一起动 |
| **配置边界** | 端口/依赖归整仓（`config/services.json`），模型/权限归模块 | 改端口要翻六份 README |

这三条是本仓的设计前提：**没有把六个模块合并成一个应用**，只是把它们放进一个文件夹，
让"装起来"这件事只需要一条命令。任何模块仍然可以被单独拷走、单独部署。

## 目录即故障域

```
apps/<模块>/            一个目录 = 一个成员 = 一个故障域 = 一个 CODEOWNERS 条目
  ├─ 该模块的全部代码（go.mod / package.json / requirements.txt 各自独立）
  ├─ .reasonix-home/    该域的模型与权限配置（只有该域读）
  └─ .env               该域运行时环境（由 config/env/<域>.env 分发而来，不进 git）
```

`apps/` 下每个子目录都是一个完整的、能单独 `git clone` 出去运行的项目。

## 一次任务的完整链路

### 单域任务（以日志审计为例）

```
前端 :3000 ──POST /aisoc-logaudit/api/tasks──▶ 大脑 :6657
                                                │ 1. 白名单校验 target
                                                │ 2. registry[logaudit] → 127.0.0.1:8788
                                                │ 3. TaskMessage.to_input_text() 压成纯文本
                                                ▼
                                logaudit serve :8788  POST /submit   ──▶ 202
                                                │
                          大脑 GET /events (SSE) ◀── turn_started / reasoning / message / turn_done
                          大脑 GET /status?task_id= ◀── running / completed + findings[]
                                                │ 4. Finding 落库（SQLite）
                                                │ 5. 判定双轨（规则轨抑制校园误报 + LLM 轨）
                                                │ 6. Report 生成
                                                ▼
前端 ──GET /aisoc-logaudit/api/stream (SSE)──◀ 任务状态推进事件
```

### 多阶段管道（data_leak 调查）

```
logaudit Finding（发现数据泄露线索）
   → 大脑 orchestrator 判断需要验证
   → 下发 pentest :8786（携带 context.evidence_summary + ref_task_ids）
   → pentest Finding 回收
   → 判定 real_threat
   → TIR :8090 POST /api/tir/ingest（DetectionEvent）
   → TIR 返回 alert + playbook（建议模式，不执行任何真实命令）
   → 前端展示 → 人工批准 → 大脑 POST /api/tir/playbooks/{id}/decision
   → TIR 产出应急响应报告（report_md + ledger_entry）
```

跨域协作是**星型**的：部件之间从不直连，一律经大脑转发上下文。这样加一个新域不需要
修改任何已有域。

## 三种部件形态

| 形态 | 例子 | 大脑怎么访问 | 鉴权 |
|---|---|---|---|
| adapter + engine | pentest（8786 → 4523）、intel（8789 → 8089） | adapter 的 `/submit` `/status` `/events` | Bearer（adapter）+ Cookie（engine） |
| engine 直连 | logaudit（8788） | reasonix serve 原生 `/submit` `/status` `/events` | Cookie `reasonix_token` |
| 纯 FastAPI 子 Agent | brain（6657）、tir（8090） | 原生 REST | 无（本地回环） |

adapter 的作用是把 reasonix 的"会话式 serve"包装成"任务式 submit/status"，并额外做
看门狗（事件停滞 → cancel + 重试）、AI 审批门（敏感命令二次校验）、findings 回溯补捉。
没有 adapter 的域（logaudit）就靠大脑自己按 15s 无进展判定 completed。

## 数据落在哪

| 数据 | 位置 | 谁写 |
|---|---|---|
| 任务/证据/报告/账号 | `apps/brain/data/brain.sqlite3`（或 `DATABASE_URL` 指向的 PG） | 只有大脑 |
| 告警/预案/应急报告 | `apps/tir/storage/data/` | 只有 TIR |
| 日志审计分片（带哈希链） | `apps/logaudit/.serve-home/logaudit/` | 只有 logaudit |
| reasonix 会话/会话状态 | 各域 `REASONIX_HOME`（`apps/<域>/.reasonix-home`） | 各域自己 |
| 运行日志 | `logs/<service>.out.log`（gitignore） | 启动脚本重定向 |
| 进程状态 | `.run/state.json`、`.run/pids/*.pid`（gitignore） | 启动脚本 |

没有共享数据库、没有共享队列 —— 这也是"模块独立"的一部分。想让两个域共享数据，
唯一合法方式是走 HTTP 契约。

## 为什么三个域各带一份 reasonix 源码

`apps/pentest`、`apps/intel` 各带一份完整 reasonix 内核（`cmd/` `internal/` `sdk/`），
`apps/logaudit` 是带 logaudit 工具链的版本。这是"成员各自负责"的直接结果，也保证了
每个域可以独立编译、独立升级、互不影响。

代价是三份 ~19MB 的源码。演进路径（可选，不影响当前结构）：

1. **先不动**（推荐）：三份各自 build 各自的 `bin/reasonix`，从 `config/env/shared.env`
   统一 `REASONIX_BIN`。
2. 若要收敛：抽 `third_party/reasonix-core`（git submodule 或 subtree），三个域改用
   同一份内核算，各域只保留自己的 `.reasonix-home/` 与工具扩展。**注意**：这会让
   "改内核"从单域行为变成全局行为，需要三方 review，等协议稳定后再做。

## 故障与降级

| 故障 | 现象 | 现有行为 |
|---|---|---|
| 某域 serve 挂了 | 大脑下发返回 502/timeout | 任务标 `failed`，其余域不受影响（进程隔离） |
| 某域 adapter 挂了 | registry 里该域不可用 | 其它域照常；`status` 脚本一眼看出是 `port-only` 还是 `down` |
| 模型通道欠费/断网 | reasonix 无输出 | TIR 自动降级到规则引擎；adapter 看门狗 cancel 后重试 2 次 |
| 大脑挂了 | 前端所有 `/aisoc-*/api` 502 | 各域仍在跑，任务状态留在各自 serve 里 |
| TIR 没起 | 大脑判定后无法下发预案 | `TIR_ENABLED=true` 时会报错但不影响证据落库，起 TIR 后重试即可 |

## 扩展点

- **加一个域** → `docs/ADD-MODULE.md`（改 4 个文件，30 分钟）
- **给某域加工具** → 改该域 `config.toml` 的 `[tools]`（只在模块内生效）
- **换模型** → 改该域 `[[providers]]`（四域可各用各的模型）
- **换端口/加依赖顺序** → 只改 `config/services.json`
