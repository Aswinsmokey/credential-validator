from __future__ import annotations

import json
from pathlib import Path

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

from credtest.web import db as database

pages_router = APIRouter()
templates = Jinja2Templates(directory=str(Path(__file__).parent.parent / "templates"))


@pages_router.get("/", response_class=HTMLResponse)
async def dashboard(request: Request):
    targets = await database.get_all_targets()
    counts = await database.get_dashboard_counts()
    return templates.TemplateResponse(
        request,
        "dashboard.html",
        {
            "targets": [dict(t) for t in targets],
            "counts": counts,
        },
    )


@pages_router.get("/app/{app_id}", response_class=HTMLResponse)
async def app_detail(request: Request, app_id: int):
    target = await database.get_target(app_id)
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")

    recon = await database.get_latest_recon(app_id)
    run = await database.get_latest_run(app_id)
    summary = await database.get_results_summary(app_id)

    recon_data = None
    if recon:
        recon_data = dict(recon)
        if recon_data.get("fields"):
            recon_data["fields"] = json.loads(recon_data["fields"])

    run_data = dict(run) if run else None

    return templates.TemplateResponse(
        request,
        "partials/app_detail.html",
        {
            "target": dict(target),
            "recon": recon_data,
            "run": run_data,
            "summary": summary,
        },
    )
