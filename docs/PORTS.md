# 端口与端口冲突

## 端口分配

| 服务 id | 端口 | 进程 | 监听 | 谁访问它 |
|---|---|---|---|---|
| `frontend` | 3000 | `serve_frontend.py`（静态 dist + 反代） | `0.0.0.0` | 浏览器 |
| `frontend-dev` | 5173 | `vite`（开发热更新，可选） | `127.0.0.1` | 浏览器（开发者） |
| `brain` | 6657 | `python -m api.main`（FastAPI） | `127.0.0.1` | 前端、所有域（回调） |
| `tir` | 8090 | `python -m threat_ir_agent serve`（FastAPI） | `127.0.0.1` | 大脑 |
| `pentest-adapter` | 8786 | `.adapter.py` | `127.0.0.1` | 大脑、前端（`/api/events` 网关） |
| `pentest-serve` | 4523 | `reasonix serve` | `127.0.0.1` | 只有 pentest-adapter |
| `logaudit-serve` | 8788 | `reasonix serve` | `127.0.0.1` | 大脑（直连，Cookie 鉴权） |
| `intel-adapter` | 8789 | `intel-agent/adapter.py` | `127.0.0.1` | 大脑 |
| `intel-serve` | 8089 | `reasonix serve` | `127.0.0.1` | 只有 intel-adapter |

原则：**只有前端（3000）和前端的反代/大脑入口需要对集群外可达，其余一律
`127.0.0.1`**。reasonix serve 的 engine 端口（4523/8089/18788）永远不该直接暴露。

### 历史端口（读到旧文档时别被误导）

| 端口 | 历史含义 | 现在的状态 |
|---|---|---|
| 8787 | 旧版 pentest adapter 端口（`registry.example.json` 里还有） | 已改为 **8786**，registry 模板用 8786 |
| 4523 | pentest reasonix serve | 不变 |
| 18788 | logaudit 走 adapter 时的 serve 端口 | 当前用 **8788 直连**；若要恢复 adapter 前置，把 `LOGAUDIT_PORT` 改 18788 并加 adapter |
| 8089 | intel reasonix serve | 不变 |
| 8000 | edushield 主系统（不在本仓） | TIR 的 `TIR_NOTIFY_URL` 历史上指向它；本仓不启动这个进程 |
| 5432 | PostgreSQL（`DATABASE_URL` 生产用） | 可选；不配则大脑回退 SQLite |

## 冲突排查

Windows：

```powershell
# 谁占了这个端口
Get-NetTCPConnection -LocalPort 8788 -State Listen | Select-Object LocalAddress,LocalPort,OwningProcess
Get-Process -Id (Get-NetTCPConnection -LocalPort 8788 -State Listen).OwningProcess

# 端口表快照
Get-NetTCPConnection -State Listen | Sort-Object LocalPort |
  Select-Object LocalPort,OwningProcess | Format-Table
```

Linux：

```bash
ss -tlnp | grep -E ':(3000|5173|6657|8090|8786|8788|8789|4523|8089)\b'
# 或
lsof -i :8788
```

脚本已经做了这件事：`pwsh scripts/status.ps1` / `bash scripts/status.sh` 会显示
`state=port-only`（端口被占但没有 dev-up 记录的 PID）—— 这通常意味着**上次没走
dev-down 就杀了进程**，或有别的程序占了端口。

## 改端口的正确姿势

1. 改 `config/services.json` 里该服务的 `port` 与 `baseUrl`。
2. 改对应 `config/env/*.env.tmpl` 里的同名变量（`API_PORT` / `TIR_API_PORT` /
   `RIX_PORT` / `LOGAUDIT_PORT` / `ADAPTER_PORT` / `PORT`）。
3. 若该端口被大脑 registry 引用，改 `config/registry/brain.registry.json.tmpl`。
4. 重新 `scripts/gen-env.*`，然后 `dev-down && dev-up`，`status` 复核。

**不要**在各模块代码里再写一份端口默认值，否则三者会漂移（这是这套配置存在的唯一原因）。
