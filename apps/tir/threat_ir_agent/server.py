# -*- coding: utf-8 -*-
"""
子 Agent HTTP 服务（FastAPI）
=============================
edushield 主系统可通过 HTTP REST 调用本子 Agent（对齐计划书 3.5
“HTTP REST 为总线”），无需修改主系统任何代码。

端点一览（全部为子 Agent 新增接口，命名空间 /api/tir/*）：
  GET  /api/tir/health                     健康检查
  POST /api/tir/ingest                     接收主平台安全检测事件 → 告警+预案
  GET  /api/tir/alerts                     列出告警
  GET  /api/tir/alerts/{alert_id}          查询单条告警
  POST /api/tir/alerts/{alert_id}/ack      确认告警
  POST /api/tir/alerts/{alert_id}/playbook 生成处置预案(?mode=suggestion|simulation)
  POST /api/tir/playbooks/{playbook_id}/decision   接收主agent确认指令→应急响应报告
  GET  /api/tir/playbooks                  列出预案
  GET  /api/tir/reports                    列出报告
  GET  /api/tir/reports/{report_id}        查询应急响应报告

本文件为【新增文件】，未修改任何存量文件。
"""

from __future__ import annotations

import logging
from typing import Optional

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from .config import config
from .models import PlaybookMode, to_jsonable
from . import ThreatIRSubAgent

logger = logging.getLogger(__name__)

agent = ThreatIRSubAgent()


# ---------------------------------------------------------------------------
# 请求模型
# ---------------------------------------------------------------------------

class IngestRequest(BaseModel):
    """edushield 主平台推送的安全检测事件。"""
    event: dict = Field(description="安全检测事件（DetectionEvent 字段）")
    task_id: str = Field(default="", description="主系统任务ID（可选，贯穿追溯）")


class PlaybookRequest(BaseModel):
    mode: str = Field(default="suggestion", description="suggestion | simulation")


class DecisionRequest(BaseModel):
    """主 agent 下发的确认指令。"""
    decision: str = Field(default="approve", description="approve | reject")
    operator: str = Field(default="edushield-main-agent", description="确认方标识")
    reject_reason: str = Field(default="", description="拒绝原因（decision=reject 时）")


# ---------------------------------------------------------------------------
# App
# ---------------------------------------------------------------------------

def create_app() -> FastAPI:
    app = FastAPI(
        title="威胁警报-应急响应 子Agent",
        description="edushield 插件式子Agent：威胁分级告警 + 应急响应预案/模拟/报告",
        version="1.0.0",
    )
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"], allow_credentials=True,
        allow_methods=["*"], allow_headers=["*"],
    )

    @app.get("/api/tir/health")
    async def health():
        return {"status": "ok", "subagent": "threat-ir-agent", "namespace": "tir_"}

    @app.post("/api/tir/ingest")
    async def ingest(req: IngestRequest):
        """接收安全检测事件 → 威胁分级 → 告警 → 持久化 → 推送 → 预案。"""
        try:
            return agent.handle_event(req.event, task_id=req.task_id)
        except Exception as e:  # noqa: BLE001
            logger.exception("[API] ingest 失败")
            raise HTTPException(status_code=500, detail=str(e))

    @app.get("/api/tir/alerts")
    async def list_alerts():
        return {"alerts": agent.list_alerts()}

    @app.get("/api/tir/alerts/{alert_id}")
    async def get_alert(alert_id: str):
        alert = agent.get_alert(alert_id)
        if alert is None:
            raise HTTPException(status_code=404, detail="告警不存在")
        return to_jsonable(alert)

    @app.post("/api/tir/alerts/{alert_id}/ack")
    async def ack_alert(alert_id: str):
        return agent.acknowledge_alert(alert_id)

    @app.post("/api/tir/alerts/{alert_id}/playbook")
    async def make_playbook(alert_id: str, req: Optional[PlaybookRequest] = None):
        mode = (req.mode if req else "suggestion")
        try:
            mode_enum = PlaybookMode(mode)
        except ValueError:
            raise HTTPException(status_code=400, detail="mode 必须为 suggestion|simulation")
        try:
            pb = agent.generate_playbook(alert_id, mode=mode_enum)
        except ValueError as e:
            raise HTTPException(status_code=404, detail=str(e))
        return {"playbook": to_jsonable(pb), "display_md": pb.to_markdown()}

    @app.post("/api/tir/playbooks/{playbook_id}/decision")
    async def confirm(playbook_id: str, req: DecisionRequest):
        result = agent.confirm_decision(
            playbook_id, decision=req.decision,
            operator=req.operator, reject_reason=req.reject_reason,
        )
        if "error" in result:
            raise HTTPException(status_code=404, detail=result["error"])
        return result

    @app.get("/api/tir/playbooks")
    async def list_playbooks():
        return {"playbooks": agent.list_playbooks()}

    @app.get("/api/tir/reports")
    async def list_reports():
        return {"reports": agent.list_reports()}

    @app.get("/api/tir/reports/{report_id}")
    async def get_report(report_id: str):
        report = agent.get_report(report_id)
        if report is None:
            raise HTTPException(status_code=404, detail="报告不存在")
        return to_jsonable(report)

    return app


app = create_app()
