# reasonix 配置在家目录里，不在仓根

三个 reasonix 域（pentest / logaudit / intel）的配置是**运行时生效**的，位置由
`REASONIX_HOME` 决定，所以真实文件必须留在各模块内：

| 域 | 生效文件 | 启动方式 | 审批策略 |
|---|---|---|---|
| pentest | `apps/pentest/.reasonix-home/config.toml` | `reasonix serve --addr 127.0.0.1:4523 --auth token` | `[permissions] mode=allow` + 大批 `ask`（sqlmap/nmap/nc/... 全走 adapter 的 AI 审批门），启动后切 `auto` |
| logaudit | `apps/logaudit/.serve-home/config.toml`（首次由 `logaudit.example.toml` 复制） | `reasonix serve --addr 127.0.0.1:8788 --auth token --behind-proxy` | 默认 + `[tools] enabled` 限定 `log_ingest/anomaly_detect/correlation/findings/report`，`[sandbox] bash="off"` |
| intel | `apps/intel/intel-agent/.reasonix-home/config.toml` | `reasonix serve --addr 127.0.0.1:8089 --auth token` | `[permissions] mode=allow` + 少量 `deny`，启动后切 `yolo`（情报源需要外网，`[sandbox] network=true`） |

## 为什么不在 `config/` 里再存一份

`reasonix` 只认 `REASONIX_HOME`，任何"集中副本"都会和生效文件漂移，两份配置对不上时
排查成本极高。所以本仓的约定是：

1. **配置归属模块**：改配置的 PR 只动 `apps/<域>/...`，CODEOWNERS 自动派给对应成员。
2. **差异由本文件维护**：新增/调整权限策略时，同步更新上表（一行说明即可）。
3. **密钥不进配置**：`api_key_env` 指向的 `DEEPSEEK_API_KEY` 放在
   `apps/<域>/.reasonix-home/.env`（由 `scripts/gen-env.*` 生成，已 gitignore）。
4. **端口不写进 toml**：端口由 `config/services.json` + 启动脚本的 `--addr` 决定，
   模块配置里不出现端口，避免改端口要动两处。

## 换模型 / 换供应商

改对应 `config.toml` 的 `[[providers]]` 段即可，四个域可各用各的模型；只是
`config/services.json` 里切不了模型（那是进程编排，不是模型配置）。这么分工是刻意的：
**端口/依赖/启动属于整仓，模型/权限属于模块**。
