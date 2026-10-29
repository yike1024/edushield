# Log Audit Deployment

## 服务器路径

- 二进制：`/home/linchen/.local/bin/reasonix`
- 仓库：`/home/linchen/projects/DeepSeek-Reasonix`
- 日志审计配置：`/home/linchen/aisoc/parts/logaudit/reasonix.toml`
- 独立状态目录：`/home/linchen/.serve-logaudit`
- serve 日志：`/home/linchen/serve-8788.log`
- Go 工具链：`/home/linchen/tools/go`

## 新增工具

- `log_ingest`：nginx/apache/syslog/json/csv/generic 日志归一化
- `anomaly_detect`：暴力破解、扫描、SQLi、webshell、异常时段、大流量
- `correlation`：按 IP 生成时间线并关联攻击链

## 常用命令

```bash
export REASONIX_SERVE_TOKEN=<component-token>
bash ~/projects/DeepSeek-Reasonix/scripts/start-logaudit.sh
bash ~/projects/DeepSeek-Reasonix/scripts/verify-logaudit.sh
bash ~/projects/DeepSeek-Reasonix/scripts/logaudit-demo.sh
```

## 鉴权方式

Reasonix serve 的 token 模式使用 Cookie 或 URL query，不是 `Authorization: Bearer`：

```bash
curl -H "Cookie: reasonix_token=<token>" http://127.0.0.1:8788/status
curl -L "http://127.0.0.1:8788/status?token=<token>"
```

## 待完成

- 隧道恢复后复验 Cookie/query 鉴权。
- 运行 `logaudit-demo.sh` 完成端到端工具验证。
- 清理构建缓存：`rm -rf ~/gomodcache ~/gocache`。
- 向管理员申请创建 `/data1/linchen`。
- 在 AiSOC 大脑注册表登记 `logaudit -> 127.0.0.1:8788`。
