---
id: PB-001
name: 未授权获取密码 / 凭据泄露
threat_class: 94
threat_type: 1
rule_ids: [10001, 10002, 10003]
severity: high
tags: [credential, leak, web, api]
estimated_minutes: 30
updated: 2026-09-08
---

# 预案 PB-001：未授权获取密码 / 凭据泄露

## 1. 识别（5 分钟）

- **特征**：XDR 规则 `10001` / `10002` / `10003` 触发，命中接口 `/Index_M/GetSystem`、`/api/login`、`/user/profile` 等返回密码哈希 / 系统配置 / 个人信息
- **攻击方 IP**：`source_ip[0]`
- **受害主机**：`host`（如 `192.168.212.166:8080`）
- **AI 研判**：`verdict_hint == real_threat` 表示高度可信

## 2. 立即隔离（5 分钟）

1. **封禁攻击源 IP**（在大脑创建 pentest 任务做来源溯源）：
   ```
   目标：封锁 source_ip[0] 在边界防火墙
   ```
2. **冻结凭据**：定位 `host` 上的应用，使用大脑 logaudit 部件拉取最近 1 小时日志，标记所有使用过该凭据的 session
3. **强制下线**：杀掉所有持有 `sysPassword` 哈希对应明文密码的活跃 session

## 3. 取证（10 分钟）

通过大脑下发 pentest 任务：
- **任务**：`对 {host} 做凭据泄露复现 + 影响面扫描`
- **domain**：pentest
- **pipeline**：data_leak（自动跑 4 阶段：审计 → 渗透 → 判定 → 报告）

取证清单：
- [ ] 攻击路径完整复现
- [ ] 暴露的密码字段（明文 / 哈希 / JWT）
- [ ] 涉及用户数
- [ ] 是否触发数据外传（看 `dest_ip` 是否在威胁情报库）

## 4. 修复（10 分钟）

- **应用层**：所有返回敏感字段的接口强制鉴权（JWT / Cookie / OAuth）
- **响应过滤**：response body 在 `data` 字段前先过敏感信息过滤（手机号、身份证、密码哈希）
- **密钥轮换**：被暴露的密码 / token 立即失效
- **告警升级**：在 XDR 里把 `rule_id 10001` 提升为 critical，加白名单豁免只能由安全团队审批

## 5. 后续（1 周内）

- [ ] 提交漏洞修复 PR + 复测报告
- [ ] 在应急报告里把这次事件归档为「PB-001 实例 #N」
- [ ] 安全培训：API 鉴权规范
- [ ] 加固：所有 GET 接口默认鉴权，敏感字段 response body 走 DLP 过滤
