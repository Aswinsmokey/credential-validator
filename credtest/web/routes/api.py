from __future__ import annotations

import csv
import io
import json
import os
import time
from pathlib import Path

from fastapi import APIRouter, BackgroundTasks, HTTPException, UploadFile, File
from fastapi.responses import FileResponse, JSONResponse, StreamingResponse

from credtest.web import db as database
from credtest.web.models import TestStartRequest
from credtest.web.routes.ws import ws_manager
from credtest.web import tasks as bg_tasks

api_router = APIRouter()

UPLOADS_DIR = Path("data/uploads")
SCREENSHOTS_DIR = Path("data/screenshots")
DEFAULT_USERNAMES = Path("credtest/wordlists/top_usernames.txt")
DEFAULT_PASSWORDS = Path("credtest/wordlists/top_passwords.txt")


# ---------------------------------------------------------------------------
# Health
# ---------------------------------------------------------------------------

@api_router.get("/health")
async def health():
    db_size = os.path.getsize("data/credtest.db") / (1024 * 1024) if Path("data/credtest.db").exists() else 0
    try:
        import resource
        rss_mb = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024
    except Exception:
        rss_mb = -1
    counts = await database.get_dashboard_counts()
    return {"rss_mb": round(rss_mb, 1), "db_size_mb": round(db_size, 2), "targets": counts}


# ---------------------------------------------------------------------------
# Config upload
# ---------------------------------------------------------------------------

@api_router.post("/config/upload")
async def upload_config(file: UploadFile = File(...)):
    UPLOADS_DIR.mkdir(parents=True, exist_ok=True)
    raw = await file.read()

    # Save to disk
    dest = UPLOADS_DIR / file.filename
    with open(dest, "wb") as f:
        f.write(raw)

    # Parse with existing config module
    import yaml
    from credtest.config import load_config, validate_config
    from credtest.config import Config, GlobalConfig, TargetConfig
    import tempfile

    with tempfile.NamedTemporaryFile(suffix=".yaml", delete=False) as tmp:
        tmp.write(raw)
        tmp_path = tmp.name

    try:
        cfg = load_config(tmp_path)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"YAML parse error: {e}")
    finally:
        os.unlink(tmp_path)

    errors = validate_config(cfg)
    if errors:
        raise HTTPException(status_code=400, detail={"errors": errors})

    app_ids = []
    for target in cfg.targets:
        row_id = await database.upsert_target(target)
        app_ids.append({"id": row_id, "name": target.name})

    return {"targets": app_ids, "count": len(app_ids)}


# ---------------------------------------------------------------------------
# Wordlist upload
# ---------------------------------------------------------------------------

@api_router.post("/wordlist/upload")
async def upload_wordlist(file: UploadFile = File(...)):
    UPLOADS_DIR.mkdir(parents=True, exist_ok=True)
    raw = await file.read()
    dest = UPLOADS_DIR / file.filename
    with open(dest, "wb") as f:
        f.write(raw)
    lines = len([l for l in raw.decode("utf-8", errors="ignore").splitlines() if l.strip()])
    return {"filename": file.filename, "path": str(dest), "lines": lines}


# ---------------------------------------------------------------------------
# Recon
# ---------------------------------------------------------------------------

@api_router.post("/recon/{app_id}")
async def trigger_recon(app_id: int, background_tasks: BackgroundTasks):
    target = await database.get_target(app_id)
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")
    background_tasks.add_task(bg_tasks.run_recon, app_id)
    return {"status": "recon_started", "app_id": app_id}


@api_router.post("/recon/all")
async def trigger_recon_all(background_tasks: BackgroundTasks):
    targets = await database.get_all_targets()
    started = []
    for t in targets:
        if t["status"] in ("pending", "error", "ready"):
            background_tasks.add_task(bg_tasks.run_recon, t["id"])
            started.append(t["id"])
    return {"started": started, "count": len(started)}


# ---------------------------------------------------------------------------
# Test execution
# ---------------------------------------------------------------------------

@api_router.post("/test/{app_id}")
async def start_test(app_id: int, req: TestStartRequest, background_tasks: BackgroundTasks):
    target = await database.get_target(app_id)
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")

    # Resolve wordlist paths
    wordlists: dict[str, str] = {}
    if req.attack_mode in ("pitchfork", "cluster_bomb"):
        u_path = req.username_wordlist or (str(DEFAULT_USERNAMES) if req.use_default_usernames else str(DEFAULT_USERNAMES))
        p_path = req.password_wordlist or (str(DEFAULT_PASSWORDS) if req.use_default_passwords else str(DEFAULT_PASSWORDS))
        wordlists = {"username": u_path, "password": p_path}
    else:
        wordlists = {"wordlist": req.wordlist or str(DEFAULT_PASSWORDS)}

    # Estimate combo count
    total_combos = 0
    try:
        if req.attack_mode == "cluster_bomb":
            u_lines = sum(1 for l in open(wordlists["username"]) if l.strip() and not l.startswith("#"))
            p_lines = sum(1 for l in open(wordlists["password"]) if l.strip() and not l.startswith("#"))
            total_combos = u_lines * p_lines
        elif req.attack_mode == "pitchfork":
            u_lines = sum(1 for l in open(wordlists["username"]) if l.strip() and not l.startswith("#"))
            total_combos = u_lines
    except Exception:
        pass

    run_id = await database.create_test_run(app_id, req.attack_mode, wordlists, total_combos)
    background_tasks.add_task(bg_tasks.run_credential_test, run_id)
    return {"status": "test_started", "app_id": app_id, "run_id": run_id}


@api_router.post("/test/all")
async def start_test_all(req: TestStartRequest, background_tasks: BackgroundTasks):
    targets = await database.get_all_targets()
    started = []
    for t in targets:
        if t["status"] == "ready":
            wordlists: dict[str, str] = {}
            if req.attack_mode in ("pitchfork", "cluster_bomb"):
                wordlists = {
                    "username": req.username_wordlist or str(DEFAULT_USERNAMES),
                    "password": req.password_wordlist or str(DEFAULT_PASSWORDS),
                }
            else:
                wordlists = {"wordlist": req.wordlist or str(DEFAULT_PASSWORDS)}
            run_id = await database.create_test_run(t["id"], req.attack_mode, wordlists)
            background_tasks.add_task(bg_tasks.run_credential_test, run_id)
            started.append({"app_id": t["id"], "run_id": run_id})
    return {"started": started, "count": len(started)}


@api_router.post("/test/{run_id}/abort")
async def abort_test(run_id: int):
    aborted = bg_tasks.abort_run(run_id)
    return {"aborted": aborted, "run_id": run_id}


# ---------------------------------------------------------------------------
# Hold management
# ---------------------------------------------------------------------------

@api_router.post("/hold/{app_id}/release")
async def release_hold(app_id: int):
    target = await database.get_target(app_id)
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")
    await database.release_target_hold(app_id)
    await ws_manager.broadcast({"type": "status", "app_id": app_id, "status": "ready"})
    return {"app_id": app_id, "status": "ready"}


# ---------------------------------------------------------------------------
# Results
# ---------------------------------------------------------------------------

@api_router.get("/results/{app_id}")
async def get_results(app_id: int, page: int = 1, per_page: int = 50, success_only: bool = False):
    rows = await database.get_results_page(app_id, page, per_page, success_only)
    return {"results": [dict(r) for r in rows], "page": page, "per_page": per_page}


@api_router.get("/results/{app_id}/summary")
async def get_results_summary(app_id: int):
    return await database.get_results_summary(app_id)


# ---------------------------------------------------------------------------
# Export
# ---------------------------------------------------------------------------

@api_router.get("/export/{app_id}/csv")
async def export_csv(app_id: int):
    target = await database.get_target(app_id)
    name = target["name"] if target else str(app_id)

    async def generate():
        buf = io.StringIO()
        writer = None
        async for row in database.get_all_results_for_export(app_id):
            if writer is None:
                writer = csv.DictWriter(buf, fieldnames=list(row.keys()))
                writer.writeheader()
            writer.writerow(row)
            yield buf.getvalue()
            buf.seek(0)
            buf.truncate()

    return StreamingResponse(
        generate(),
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="{name}_results.csv"'},
    )


@api_router.get("/export/{app_id}/jsonl")
async def export_jsonl(app_id: int):
    target = await database.get_target(app_id)
    name = target["name"] if target else str(app_id)

    async def generate():
        async for row in database.get_all_results_for_export(app_id):
            yield json.dumps(row) + "\n"

    return StreamingResponse(
        generate(),
        media_type="application/x-ndjson",
        headers={"Content-Disposition": f'attachment; filename="{name}_results.jsonl"'},
    )


# ---------------------------------------------------------------------------
# Screenshot
# ---------------------------------------------------------------------------

@api_router.get("/screenshot/{app_id}")
async def serve_screenshot(app_id: int):
    recon = await database.get_latest_recon(app_id)
    if not recon or not recon["screenshot_path"]:
        target = await database.get_target(app_id)
        name = target["name"] if target else str(app_id)
        html = f"<html><body style='font-family:sans-serif;padding:2rem'><p>No preview available for <b>{name}</b>. Run recon first.</p></body></html>"
        return StreamingResponse(io.StringIO(html), media_type="text/html")

    path = Path(recon["screenshot_path"])
    if not path.exists():
        raise HTTPException(status_code=404, detail="Snapshot file not found")

    return FileResponse(
        path,
        media_type="text/html",
        headers={
            "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline' *; img-src *; font-src *",
            "X-Frame-Options": "SAMEORIGIN",
        },
    )
