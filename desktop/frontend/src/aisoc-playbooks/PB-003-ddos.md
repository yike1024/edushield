---
id: PB-003
name: DDoS / 大流量攻击
threat_class: [80, 81, 82]
rule_ids: [30001, 30002, 30003]
severity: critical
tags: [ddos, flood, network]
estimated_minutes: 15
updated: 2026-09-08
---

# 预案 PB-003：DDoS / 大流量攻击

## 1. 识别（1 分钟）

- **特征**：边界流量异常飙升（> 平时 10x），`protocol` 集中为 udp/icmp/tcp-syn，`source_ip` 数量大
- **研判**：XDR 规则 `30001-30003` 触发，AI 自动判定为 `real_threat`

## 2. 立即缓解（5 分钟）

1. **BGP Anycast / 高防 IP 切换**：联系运营商或 CDN 厂商走高防 IP
2. **SYN Cookie**：开启内核 `tcp_syncookies=1`
3. **连接数限制**：`iptables -A INPUT -p tcp --syn -m connlimit --connlimit-above 50 -j DROP`
4. **限速 / 黑洞路由**：在边界路由器对 `source_ip` 网段做 rate-limit

## 3. 溯源（5 分钟）

- **攻击类型**：`protocol` 字段判断（UDP flood / SYN flood / HTTP flood / DNS amplification）
- **源 IP 分布**：`source_ip` 是否在威胁情报库（botnet C&C）
- **目标**：`dest_ip` 是否暴露核心服务端口

通过大脑下发 intel 任务查询源 IP 信誉：
- **任务**：`威胁情报查询：source_ip[0..N]`
- **domain**：intel

## 4. 恢复（5 分钟）

- 业务切到备用机房 / 灾备 DNS
- 监控恢复（流量回落到基线 1.5x 内）
- 关闭限速规则（保留高防 IP）

## 5. 后续

- [ ] 报备网安 / 运营商
- [ ] 加购高防服务
- [ ] 业务弹性扩容预案
- [ ] 应急演练（每季度一次）
