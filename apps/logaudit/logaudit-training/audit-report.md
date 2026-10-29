# 日志审计（logaudit）报告 — TRAINING-20260825-0001

> 部件：身体部件 B（log-audit-agent）｜框架：Reasonix 内核 + 日志审计三件套工具
> 训练方式：端到端测试驱动（`TestLogAuditTrainingE2E`），不依赖 LLM
> 审计范围（授权内模拟日志）：access_normal.log（62 条）、access_attack.log（51 条）、auth.log（13 条）

## 摘要（verdict + confidence）

- **verdict（部件侧定性，最终判定归大脑）**：存在真实攻击活动（real_threat，待大脑交叉确认）
- **confidence**：0.90（攻击特征命中规则库且多证据互证；模拟数据置信度上限受限）
- 共接入 **126 条**归一化日志记录、17 个源 IP；产出 **7 条威胁 Finding**（critical×2、high×3、medium×1、low×1）+ 3 条接入记录（info）
- 误报抑制验证通过：搜索引擎爬虫（66.249.66.1 / 114.114.8.9）、校园正常流量与选课高并发（10.20.0.0/16 段）均未产出威胁 Finding

## 发现列表

| Finding ID | 源 IP | 严重度 | 定性 | MITRE | CWE |
|---|---|---|---|---|---|
| anomaly_detect:198.51.100.23:sqli | 198.51.100.23 | critical | SQL 注入 | T1190 | CWE-89 |
| anomaly_detect:198.51.100.23:webshell | 198.51.100.23 | critical | Webshell 访问 | T1505.003, T1190 | CWE-434 |
| correlation:203.0.113.77:credential_stuffing_success | 203.0.113.77 | high | 爆破成功攻击链 | T1110 | CWE-287 |
| anomaly_detect:203.0.113.77:brute_force | 203.0.113.77 | high | 管理后台暴力破解 | T1110 | CWE-307 |
| anomaly_detect:45.155.205.100:brute_force | 45.155.205.100 | high | SSH 暴力破解 | T1110 | CWE-307 |
| anomaly_detect:192.0.2.45:scan | 192.0.2.45 | medium | 目录扫描侦察 | T1046, T1595 | CWE-200 |
| anomaly_detect:172.16.9.9:out_of_hours | 172.16.9.9 | low | 凌晨批量导出学生数据 | T1078 | CWE-778 |

## 详细发现（按严重度排序）

### 1. [critical] 198.51.100.23 — SQL 注入 + Webshell 完整入侵链

- **时间线**：22:10:00 UNION SELECT 探测（500）→ 22:10:30 盲注 SLEEP(5)（200）→ 22:11:00 information_schema 枚举（500）→ 22:12:00 POST /upload → 22:15:00 访问 /uploads/cmd.php?c=whoami（200）→ 22:16:00 POST cmd.php
- **证据**：`GET /search?q=1%20AND%20SLEEP(5) HTTP/1.1" 200`、`GET /uploads/cmd.php?c=whoami HTTP/1.1" 200`
- **定性**：注入试探后上传并成功调用 Webshell，**疑似主机已失陷**
- **修复建议**：立即排查上传目录、查杀 webshell、确认失陷后隔离主机并轮换凭据；数据库查询参数化 + WAF SQLi 规则
- **置信度**：0.95（多阶段行为链互证）

### 2. [high] 203.0.113.77 — 管理后台爆破成功（凭据撞库成功链）

- **时间线**：21:00:01–21:00:23 连续 12 次 POST /admin/login 401（python-requests UA）→ 21:00:25 返回 **200** → 21:01:00 访问 /admin/dashboard
- **定性**：暴力破解后登录成功，**管理账号已失陷**
- **修复建议**：按失陷处置——强制改密、吊销会话、审查登录后行为、启用 MFA 与登录限速（fail2ban/WAF）
- **置信度**：0.95（correlation 工具凭据爆破成功链规则命中）

### 3. [high] 45.155.205.100 — SSH 暴力破解

- **时间线**：20:30:01–20:30:21 共 11 次 Failed password（root/admin 及 oracle/test/postgres 等不存在用户），字典爆破特征明显
- **定性**：SSH 口令爆破（未见后续成功登录）
- **修复建议**：封禁/限速该源，启用账户锁定，核查是否有后续成功登录
- **置信度**：0.92
- **备注**：本检出依赖本次训练修复的 syslog 源 IP 提取能力（修复前该攻击将全量漏报）

### 4. [medium] 192.0.2.45 — 自动化目录扫描

- **时间线**：14:00:00–14:00:19 每秒 1 次共 20 个敏感路径探测（/admin、/.env、/backup.sql、/.git/HEAD…），全部 404，UA 为 nikto/2.5.0
- **定性**：侦察扫描，未发现后续利用行为
- **修复建议**：封禁或限速该源，核查相邻主机是否被同源扫描
- **置信度**：0.95（扫描器 UA + 行为双重命中）

### 5. [low] 172.16.9.9 — 凌晨批量导出敏感数据

- **时间线**：02:00:00–02:05:00 连续 11 页 /api/export/students 导出（每次 1MB），内网 IP 于凌晨集中活动
- **定性**：异常时段批量导出学生数据，**需人工核实是否为合法定时任务**（可能为数据泄露前兆）
- **修复建议**：核实自动化任务白名单；若非预期，按数据泄露流程调查
- **置信度**：0.70（内网合法任务可能性存在，故定 low）

## 误报抑制验证（校园场景）

| 流量 | 判定 | 依据 |
|---|---|---|
| Googlebot 66.249.66.1、Baiduspider 114.114.8.9 | 非攻击 | 搜索引擎爬虫，全部 200，无 Finding |
| 选课流量 10.20.0.60–63（/xk/select 高频） | 非攻击 | 业务高并发≠DDoS，全部 200，无 Finding |
| 运维登录 10.20.0.5（Accepted password，09:00/18:30） | 正常 | 工作时段、次数少，无 Finding |

## 附录

### A. 工具调用链（思维链账本）

1. `log_ingest(access_normal.log, nginx)` → Parsed: 62, Skipped: 0
2. `log_ingest(access_attack.log, nginx)` → Parsed: 51, Skipped: 0
3. `log_ingest(auth.log, syslog)` → Parsed: 13, Skipped: 0
4. `anomaly_detect(checks=all)` → 17 IPs / 126 records → 6 条异常 Finding
5. `correlation(window_minutes=120, min_events=2)` → 1 条攻击链 Finding
6. 汇总：10 条 Finding（含 3 条 info 级接入记录），全部结构化可上报大脑

### B. 训练中发现并修复的缺陷

- **缺陷**：`log_ingest` 解析 syslog 时仅从消息行首提取源 IP，sshd 标准格式 `Failed password ... from <IP> port` 的 IP 在句中，导致 SourceIP 为空、SSH 爆破全量漏报
- **修复**：`parseSyslogLine` 增加 `from <IP>` / `rhost=<IP>` 提取（`sshdFromIPRe`）
- **回归**：原有 4 项单元测试 + 本训练 7 项检出断言 + 4 项误报抑制断言全部通过

### C. 交付清单（给大脑组员）

- 审计实例：`reasonix serve -addr 127.0.0.1:8788 -auth token`（文档 05 规范）
- 统一协议：部件经 `/submit` 收 TaskMessage（domain=logaudit）、`/events` 输出事件流，Finding 结构符合 02 协议
- 验证程序：`internal/tool/builtin/logaudit_training_e2e_test.go`（可重复执行回归）
