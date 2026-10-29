"""EventHub —— 平台实时事件聚合（阶段 4 简化版）。

- publish()：大脑侧关键事件（task_created / status_* / findings_stored / verdict / report）
- subscribe()：前端 /api/stream 订阅队列
- 后续联调真实 reasonix 时，再增加"订阅各部件 /events SSE"的采集端
"""

from __future__ import annotations

import json
import queue
import threading
from typing import Any, Optional

_hub: Optional["EventHub"] = None
_hub_lock = threading.Lock()


class EventHub:
    def __init__(self):
        self._subs: list[queue.Queue] = []
        self._lock = threading.Lock()

    def publish(self, task_id: str, domain: str, event_type: str, payload: Any = None):
        event = {
            "task_id": task_id,
            "domain": domain,
            "event": event_type,
            "payload": payload or {},
        }
        with self._lock:
            subs = list(self._subs)
        for q in subs:
            try:
                q.put_nowait(event)
            except queue.Full:
                pass

    def subscribe(self, maxsize: int = 200) -> queue.Queue:
        q: queue.Queue = queue.Queue(maxsize=maxsize)
        with self._lock:
            self._subs.append(q)
        return q

    def unsubscribe(self, q: queue.Queue):
        with self._lock:
            if q in self._subs:
                self._subs.remove(q)


def get_hub() -> EventHub:
    global _hub
    with _hub_lock:
        if _hub is None:
            _hub = EventHub()
        return _hub
