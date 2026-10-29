"""
AiSOC 校园智盾 —— 大脑（FastAPI 平台层）
=========================================

多 Agent 安全运营平台的大脑：编排调度 · 威胁判定 · 会话管理 · 审计留档 · 报告。

启动:
    pip install -r requirements.txt
    python mock_part.py          # 假身体部件（联调用）
    python -m api.main           # 大脑 → http://0.0.0.0:6657

架构（阶段 1）:
    FastAPI (6657)
      ├── api/            路由层
      ├── protocol/       统一协议（TaskMessage/Finding/Report）
      ├── registry/       部件注册表（pentest 8787 / logaudit 8788）
      ├── session/        SQLite 会话存储 + 状态机
      └── orchestrator/   派活调度（白名单 → 下发 → 回收）

身体部件（队友负责）:
    reasonix serve 实例（8787 渗透 / 8788 日志审计），HTTP /submit 对接。
"""
