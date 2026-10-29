# high-risk 高危样本说明（M-3 · 供 T0-5 / L-7 real_threat 全链路真机验收）

> 交付人：chenyiming ｜ 2026-10-23（录制日定档平移刷新）｜ 消费方：linyuxuan（大脑 6657 / TIR 8090 真机）
> 门槛要求：至少一条能稳定触发 `severity=high` 且 `confidence≥0.7` 的样本 —— **本目录首选样本实测 critical / 0.95，稳定达标**。
> **合规声明：全部数据人工合成，无真实师生信息；发件域/IP 均为虚构或 RFC 5737 文档保留段；附件为无害占位文件；离线可用，无外网依赖。**

---

## 1. 样本清单与预期研判结论

| 文件 | 用途 | 消费工具 | 预期研判结论（工具实测值） | 期望命中的证据 |
|---|---|---|---|---|
| `principal-urgent.eml` ★首选 | T0-5 触发样本 | 8788 `email_parse` | **domain=phishing，severity=critical，score=19，confidence=0.95** | From 显示名"校长办公室"、发件域 `xynu-edu.top` 仿冒校方 `xynu.edu.cn`；Return-Path `bounce@mailer-relay-7.top` 与显示名不符；spf=softfail、dkim=none、dmarc=fail；正文仿冒统一身份认证链接 `http://xynu-edu.top/cas/login`；索取凭据（学号与密码）；紧迫话术（今日17:00前/逾期通报）；附件 紧急通知.pdf（90B 无害占位，sha256 见 §3） |
| `cas.log` 备选 | 日志侧高危任务 | 8788 `ioc_extract` | **verdict=phishing，severity=critical，confidence=0.95**（target=xynu-edu.top）；另产出 203.0.113.77/.200、198.51.100.44 三条"待人工研判" | 仿冒域命中 lookalike+SSO 双强信号；校园域 `cas.xynu.edu.cn` 静默零误报 |
| `compromised-account-202311010101.log` 备选 | 跨源失陷链（预 join 摘录，206 行） | 8788 logaudit 工具链 / compromised-account 技能 | **domain=compromised-account**，预期 severity≥high、confidence≥0.8 | 账号 202311010101 完整时间线：2026-10-16 10:12 收钓鱼邮件 → 13:00 仿冒门户提交凭据 success → 10-22 07:00 校外 IP 198.51.100.23（沈阳）VPN 登录 success（异地双指标：校外段+geo≠home）→ 08:00~09:00 经网关 10.20.5.8 批量发信 200 封（18s 间隔） |

**反例警示**：完整样本包（`~/samples/校园运营样本包/`）里的脏数据与 challenge 样本 confidence 有意封顶 ≤0.5（验证降级路径），**不要**拿来触发 T0-5。

## 2. T0-5 建议触发方式（对应待做清单 L-7）

1. 前端附件入口上传 `principal-urgent.eml`，消息输入 **"帮我研判这封举报邮件"**（依赖 L-4 反诈关键词规则轨 + 纯附件 target；若 L-4 未上线，消息里手动带上域名 `xynu-edu.top` 作为 target）。
2. 预期链路：任务 domain=logaudit → email_parse Finding（phishing/critical/0.95，过 `severity∈{critical,high} & confidence≥0.7` 门槛）→ 判定 real_threat → 8090 落告警/预案 → 前端批准 → `responded`（带 report_id/report_md）或 `recorded` → 报告含"反诈研判"段。
3. 该 .eml 判定值已经 linchen 的 test_email_parse.py 29 项测试验证（唯一未过项为附件 sha256 常量比对，与本样本的判定触发无关，闭环方式见完整包 HANDOFF §待办 2）。

## 3. 文件 sha256（交付时实测）

| 文件 | 大小 | sha256 |
|---|---|---|
| principal-urgent.eml | 2471 B | `da084ef63dc255dc6507ca8b2e220830a28def8e4adc622d68cb692c04669b2c` |
| cas.log | 30153 B | `7ed95968371d535e802fd69b48e03496c3270e20b5cebb9fb34d1ffb74506dbd` |
| compromised-account-202311010101.log | 48974 B | `b113575a0dbc75990e8d6ba1260b7dba921f8abfc7d80f0c57875b2f0d3e9f12` |
| （eml 内嵌附件 紧急通知.pdf） | 90 B | `f40b14e54796a0cfdde44c168e1a6a78d9a7ae954468becc2230b6b1c9bd5727`（占位件；linchen 旧基准常量为 614c1b0a…，闭环见完整包 HANDOFF） |

## 4. 关联资产位置（同服务器）

- 完整样本包（M-1/M-2，前端演示与测试断言用）：`~/samples/校园运营样本包/`（README 断言表 16 行 + HANDOFF-for-linchen.md）
- 原始压缩包：`~/t11-sample-pack-20261021.zip`
- 本目录三个文件均取自完整包（cas.log 逐字节相同；.eml 相同；时间线摘录由三源日志按 account_id 一次字典分组生成，可由 `_selfcheck/generate_samples.py` 体系复现）。
