from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles

from credtest.web import db
from credtest.web.routes.api import api_router
from credtest.web.routes.pages import pages_router
from credtest.web.routes.ws import ws_router

BASE_DIR = Path(__file__).parent


def create_app() -> FastAPI:
    app = FastAPI(
        title="CredTest Dashboard",
        description="Automated credential validation — authorized use only",
        docs_url="/api/docs",
        redoc_url=None,
    )

    # Static files
    static_dir = BASE_DIR / "static"
    app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")

    @app.on_event("startup")
    async def startup() -> None:
        await db.init()
        await db.enable_wal()
        print("\n⚠  CredTest dashboard is running.")
        print("   For authorized security audits only.\n")

    @app.on_event("shutdown")
    async def shutdown() -> None:
        await db.close()

    app.include_router(pages_router)
    app.include_router(api_router, prefix="/api")
    app.include_router(ws_router)

    return app
