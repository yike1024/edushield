"""XDR OpenAPI 客户端（阶段 2，live 模式骨架）。

官方认证：Access Key / Security Key（AK/SK）或联动码 authCode 签名。
签名实现来自深信服官方 SDK（见 xdr_sign.py），不可改签后的请求。

说明：
- 未配置 XDR_BASE_URL / 联动码时，平台自动使用样例模式（data_source.SampleAlarmLoader）
- 接口列表见《OpenAPIDocument/深信服XDR平台接口开放列表.html》
  本客户端只封装一期需要的几个接口，后续按需扩展
"""

from __future__ import annotations

import logging
from typing import Any, Optional

import httpx

from config.settings import settings
from data_source.xdr_sign import Signature

logger = logging.getLogger(__name__)


class _SignableRequest:
    """适配官方 SDK 签名接口的最小请求对象。"""

    def __init__(self, url: str, method: str, params: Optional[dict] = None,
                 json_body: Optional[dict] = None, data: Optional[str] = None):
        self.url = url
        self.method = method
        self.params = params or {}
        self.json = json_body
        self.data = data
        self.headers: dict[str, str] = {}


class XdrClient:
    """XDR OpenAPI 客户端（live 模式）。"""

    def __init__(self, base_url: str = "", auth_code: str = "", ak: str = "", sk: str = ""):
        self.base_url = (base_url or settings.XDR_BASE_URL).rstrip("/")
        self.auth_code = auth_code or settings.XDR_AUTH_CODE
        self.ak = ak or settings.XDR_AK
        self.sk = sk or settings.XDR_SK
        if self.auth_code or (self.ak and self.sk):
            self._signer = Signature(auth_code=self.auth_code or None, ak=self.ak or None, sk=self.sk or None)
        else:
            self._signer = None

    @property
    def configured(self) -> bool:
        return bool(self.base_url and self._signer)

    def _request(self, method: str, path: str, params: Optional[dict] = None,
                 json_body: Optional[dict] = None) -> dict[str, Any]:
        if not self.configured:
            raise RuntimeError("XDR live 模式未配置：需要 XDR_BASE_URL + XDR_AUTH_CODE（或 XDR_AK/XDR_SK）")

        url = f"{self.base_url}{path}"
        req = _SignableRequest(url, method, params=params, json_body=json_body)
        self._signer.signature(req)

        headers = {k: v for k, v in req.headers.items() if k != "sdk-content-type"}
        if json_body is not None:
            headers.setdefault("Content-Type", "application/json")

        logger.info(f"[xdr] {method} {path}")
        resp = httpx.request(
            method, url, params=params, json=json_body, data=req.data,
            headers=headers, timeout=settings.PART_SUBMIT_TIMEOUT_S,
        )
        resp.raise_for_status()
        return resp.json()

    # ---- 一期需要的接口 ----

    def alerts_list(self, start_ts: int, end_ts: int, page: int = 1, page_size: int = 50) -> dict:
        return self._request("GET", "/api/xdr/v1/alerts/list", params={
            "startTimestamp": start_ts, "endTimestamp": end_ts,
            "page": page, "pageSize": page_size,
        })

    def incidents_list(self, start_ts: int, end_ts: int, page: int = 1, page_size: int = 50) -> dict:
        return self._request("GET", "/api/xdr/v1/incidents/list", params={
            "startTimestamp": start_ts, "endTimestamp": end_ts,
            "page": page, "pageSize": page_size,
        })

    def vuls_risk_list(self, start_ts: int, end_ts: int, page_size: int = 50) -> dict:
        return self._request("GET", "/api/xdr/v1/vuls/risk/list", params={
            "startTimestamp": start_ts, "endTimestamp": end_ts,
            "pageSize": page_size,
        })

    def block_ip_network(self, name: str, reason: str, block_ips: list[str], devices: list[str]) -> dict:
        """新增网侧封禁地址策略（真实处置接口；演示环境优先用 mock）。"""
        return self._request("POST", "/api/xdr/v1/responses/blockiprule/network", json_body={
            "name": name, "reason": reason,
            "timeType": 1, "timeValue": 1, "timeUnit": "hour",
            "blockIpRule": block_ips, "devices": devices,
        })


def get_xdr_client() -> XdrClient:
    return XdrClient()


def live_enabled() -> bool:
    return get_xdr_client().configured
