"""AiSOC 大脑 — 启动入口。

用法:
    python -m api.main
    uvicorn api.main:app --reload --host 0.0.0.0 --port 6657
"""

import logging

logger = logging.getLogger("aisoc-brain")

if __name__ == "__main__":
    import uvicorn
    from api import app
    from config.settings import settings

    logger.info(f"AiSOC 大脑启动 → http://{settings.API_HOST}:{settings.API_PORT}")
    uvicorn.run(app, host=settings.API_HOST, port=settings.API_PORT)
else:
    # 当通过 uvicorn api.main:app 启动时，暴露 app 引用
    from api import app  # noqa: F811
