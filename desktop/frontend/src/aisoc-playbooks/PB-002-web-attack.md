---
id: PB-002
name: Web 攻击 / SQL 注入 / XSS
threat_class: [91, 92, 93]
rule_ids: [20001, 20002, 20003, 20004]
severity: high
tags: [web, sqli, xss, waf]
estimated_minutes: 25
updated: 2026-09-08
---

# 预案 PB-002：Web 攻击 / SQL 注入 / XSS

## 1. 识别（3 分钟）

- **特征**：WAF / IDS 规则 `20001-20004` 触发，URL 含典型攻击 payload（`' OR 1=1--`、`%3Cscript%3E`、`<svg/onload=...>`）
- **AI 研判关键词**：`verdict_hint` 为 `real_threat` 且 `severity_score > 50`
- **来源 IP**：`source_ip[0]` 是否在威胁情报库命中

## 2. 立即隔离（5 分钟）

1. **WAF 临时规则**：把攻击 URL pattern 加入 WAF 黑名单（封禁 24h）
2. **速率限制**：对 `source_ip[0]` 应用严格速率限制（5 req/min）
3. **蜜罐回滚**：若攻击打到蜜罐，记录 payload 进威胁情报库

## 3. 取证（10 分钟）

通过大脑下发 pentest 任务验证漏洞：
- **任务**：`对 {host}{url} 做 SQL 注入 / XSS 漏洞深度验证`
- **domain**：pentest
- **目标**：`{host}`（必须是白名单内资产）

取证清单：
- [ ] Payload 是否真正执行（sleep benchmark / `@@version` 回显 / `<img src=x onerror=...>` 触发）
- [ ] 数据库版本与权限
- [ ] 注入点是否在所有输入点都覆盖
- [ ] 是否拿到数据库写权限（`INTO OUTFILE` / `xp_cmdshell`）

## 4. 修复（10 分钟）

- **参数化查询**：所有用户输入点用预编译语句（PDO / JDBC PreparedStatement）
- **WAF 规则**：补充自定义规则到 WAF（带业务字段白名单）
- **X-Frame-Options / CSP**：防 XSS 二次利用
- **数据库账号降权**：web 账号只给 SELECT / INSERT，禁用 `INFORMATION_SCHEMA` 读权限
- **审计日志**：所有 5xx / 异常响应入库，便于溯源

## 5. 后续

- [ ] SAST 扫描（SonarQube）作为 CI 卡点
- [ ] 渗透测试报告归档
- [ ] WAF 规则库更新
- [ ] 开发安全培训
