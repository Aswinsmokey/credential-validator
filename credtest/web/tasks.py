from __future__ import annotations

import asyncio
import json
import time
from pathlib import Path

import httpx

from credtest.web import db as database
from credtest.web.routes.ws import ws_manager
from credtest.web.screenshot import capture_snapshot

LOGS_DIR = Path("data/logs")
DEFAULT_USERNAMES = "credtest/wordlists/top_usernames.txt"
DEFAULT_PASSWORDS = "credtest/wordlists/top_passwords.txt"
PER_TARGET_CONCURRENCY = 10
BATCH_SIZE = 20
MAX_QUEUED_TASKS = 200

# Registry of running tasks so we can abort them
_running_tasks: dict[int, asyncio.Task] = {}   # run_id → task


# ---------------------------------------------------------------------------
# Recon task
# ---------------------------------------------------------------------------

async def run_recon(target_id: int) -> None:
    target = await database.get_target(target_id)
    if not target:
        return

    await database.update_target_status(target_id, "recon_running")
    await ws_manager.broadcast({"type": "status", "app_id": target_id, "status": "recon_running"})

    try:
        # Run Playwright recon in a thread (sync API)
        from credtest.recon import recon as do_recon
        loop = asyncio.get_event_loop()
        recon_result = await loop.run_in_executor(
            None,
            lambda: do_recon(target["url"], verify_ssl=False, interactive=False),
        )

        # Capture HTML snapshot
        snapshot_path, html_hash = await capture_snapshot(target["url"], target["name"])

        # Detect protections
        csrf_detected = bool(recon_result.csrf_fields)
        captcha_detected = any("captcha" in n.lower() or "waf" in n.lower() for n in recon_result.notes)
        mfa_detected = any("mfa" in n.lower() or "2fa" in n.lower() for n in recon_result.notes)

        fields_json = json.dumps([
            {"name": f.name, "type": f.field_type, "required": f.required}
            for f in recon_result.fields
        ])

        await database.insert_recon_result(
            target_id=target_id,
            endpoint_url=recon_result.action,
            endpoint_method=recon_result.method,
            fields=fields_json,
            csrf_detected=int(csrf_detected),
            csrf_field_name=", ".join(recon_result.csrf_fields) if recon_result.csrf_fields else None,
            captcha_detected=int(captcha_detected),
            mfa_detected=int(mfa_detected),
            screenshot_path=snapshot_path,
            raw_html_hash=html_hash,
        )

        if captcha_detected or mfa_detected:
            reason = "captcha" if captcha_detected else "mfa"
            await database.update_target_hold(target_id, reason)
            new_status = "held"
        else:
            new_status = "ready"

        await database.update_target_status(target_id, new_status)
        await ws_manager.broadcast({
            "type": "recon_complete",
            "app_id": target_id,
            "status": new_status,
            "fields": json.loads(fields_json),
            "protections": {
                "csrf": csrf_detected,
                "captcha": captcha_detected,
                "mfa": mfa_detected,
            },
            "page_title": recon_result.page_title,
            "action_url": recon_result.action,
        })

    except Exception as e:
        await database.update_target_status(target_id, "error", error_msg=str(e))
        await ws_manager.broadcast({"type": "error", "app_id": target_id, "msg": str(e)})


# ---------------------------------------------------------------------------
# Credential test task
# ---------------------------------------------------------------------------

async def run_credential_test(run_id: int) -> None:
    LOGS_DIR.mkdir(parents=True, exist_ok=True)

    run = await database.get_test_run(run_id)
    if not run:
        return
    target = await database.get_target(run["target_id"])
    if not target:
        return

    await database.update_run_status(run_id, "running", started_at=time.time())
    await database.update_target_status(target["id"], "testing")
    await ws_manager.broadcast({"type": "status", "app_id": target["id"], "status": "testing"})

    log_path = LOGS_DIR / f"run_{run_id}.jsonl"
    log_file = open(log_path, "a", encoding="utf-8")

    wordlists = json.loads(run["wordlists"]) if run["wordlists"] else {}
    attack_mode = run["attack_mode"]

    # Build payload generator using existing attack_modes module
    from credtest import attack_modes
    from credtest.config import TargetConfig
    from credtest.classifier import Baseline, classify

    body_template = json.loads(target["body_template"]) if target["body_template"] else {}

    if attack_mode == "sniper":
        wl = wordlists.get("wordlist", DEFAULT_PASSWORDS)
        defaults = {}
        gen = attack_modes.sniper(wl, body_template, defaults)
    elif attack_mode == "battering_ram":
        wl = wordlists.get("wordlist", DEFAULT_PASSWORDS)
        gen = attack_modes.battering_ram(wl, body_template)
    elif attack_mode == "pitchfork":
        gen = attack_modes.pitchfork(wordlists, body_template)
    else:  # cluster_bomb
        gen = attack_modes.cluster_bomb(wordlists, body_template)

    # Baseline calibration
    dummy = {k: "__credtest_invalid__" for k in body_template}
    baseline = Baseline(status_code=200, body_length=0)
    try:
        async with httpx.AsyncClient(verify=False, follow_redirects=False, timeout=10.0) as probe:
            if target["content_type"] == "json":
                br = await probe.request(target["method"], target["url"], json=dummy)
            else:
                br = await probe.request(target["method"], target["url"], data=dummy)
            baseline = Baseline(
                status_code=br.status_code,
                body_length=len(br.content),
                cookies=set(br.cookies.keys()),
            )
    except Exception:
        pass

    semaphore = asyncio.Semaphore(PER_TARGET_CONCURRENCY)
    tested = 0
    successes = 0
    batch: list[dict] = []
    abort_flag = {"abort": False}

    # Register so abort endpoint can cancel
    current_task = asyncio.current_task()
    _running_tasks[run_id] = current_task

    limits = httpx.Limits(max_connections=PER_TARGET_CONCURRENCY, max_keepalive_connections=5)
    client = httpx.AsyncClient(
        verify=False,
        follow_redirects=False,
        timeout=httpx.Timeout(10.0, connect=5.0),
        limits=limits,
    )

    async def test_one(body: dict) -> None:
        nonlocal tested, successes

        if abort_flag["abort"]:
            return

        async with semaphore:
            # Check hold
            t = await database.get_target(target["id"])
            if t and t["status"] == "held":
                hold_until = t["hold_until"] or 0
                wait = hold_until - time.time()
                if wait > 0:
                    await asyncio.sleep(min(wait, 300))

            if abort_flag["abort"]:
                return

            try:
                if target["content_type"] == "json":
                    resp = await client.request(target["method"], target["url"], json=body)
                else:
                    resp = await client.request(target["method"], target["url"], data=body)
            except Exception:
                return

            classification = classify(resp, baseline, baseline.cookies)

            creds = {k: v for k, v in body.items() if "§" not in str(v)}
            username = creds.get("username", creds.get("user", next(iter(creds.values()), "")))
            password = creds.get("password", creds.get("pass", list(creds.values())[-1] if creds else ""))

            row = {
                "run_id": run_id,
                "target_id": target["id"],
                "username": username,
                "password": password,
                "status_code": resp.status_code,
                "content_length": len(resp.content),
                "latency_ms": int(resp.elapsed.total_seconds() * 1000) if resp.elapsed else 0,
                "redirect_url": resp.headers.get("location", ""),
                "auth_success": int(classification.auth_success),
                "auth_confidence": classification.auth_confidence,
                "auth_score": classification.auth_score,
                "rate_limited": int(classification.rate_limited),
                "captcha_hit": int(classification.captcha_detected),
                "signals": json.dumps(classification.signals),
            }

            log_file.write(json.dumps(row) + "\n")
            log_file.flush()

            batch.append(row)
            if len(batch) >= BATCH_SIZE:
                await database.insert_results_batch(batch.copy())
                batch.clear()

            tested += 1
            if classification.auth_success:
                successes += 1

            if classification.rate_limited or classification.captcha_detected:
                reason = "rate_limit" if classification.rate_limited else "captcha"
                await database.update_target_hold(target["id"], reason)
                await ws_manager.broadcast({"type": "hold", "app_id": target["id"], "reason": reason})

            if classification.auth_success or classification.rate_limited:
                await ws_manager.broadcast({
                    "type": "result",
                    "app_id": target["id"],
                    "run_id": run_id,
                    "username": username,
                    "password": password,
                    "success": classification.auth_success,
                    "confidence": classification.auth_confidence,
                    "score": classification.auth_score,
                })

            if tested % 50 == 0:
                await database.update_run_progress(run_id, tested, successes)
                await ws_manager.broadcast({
                    "type": "progress",
                    "app_id": target["id"],
                    "run_id": run_id,
                    "tested": tested,
                    "total": run["total_combos"],
                    "successes": successes,
                })

    try:
        tasks: list[asyncio.Task] = []
        for body in gen:
            if abort_flag["abort"]:
                break
            tasks.append(asyncio.create_task(test_one(body)))
            if len(tasks) >= MAX_QUEUED_TASKS:
                await asyncio.gather(*tasks)
                tasks.clear()
        if tasks:
            await asyncio.gather(*tasks)
    except asyncio.CancelledError:
        abort_flag["abort"] = True

    if batch:
        await database.insert_results_batch(batch)

    await client.aclose()
    log_file.close()

    final_status = "aborted" if abort_flag["abort"] else "done"
    await database.update_run_status(run_id, final_status, finished_at=time.time())
    await database.update_run_progress(run_id, tested, successes)

    target_status = "done" if final_status == "done" else "ready"
    await database.update_target_status(target["id"], target_status)

    await ws_manager.broadcast({
        "type": "run_complete",
        "app_id": target["id"],
        "run_id": run_id,
        "tested": tested,
        "successes": successes,
        "status": final_status,
    })

    _running_tasks.pop(run_id, None)


def abort_run(run_id: int) -> bool:
    task = _running_tasks.get(run_id)
    if task:
        task.cancel()
        return True
    return False
