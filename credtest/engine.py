from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import AsyncGenerator, Callable, Optional

import httpx

from credtest.attack_modes import battering_ram, cluster_bomb, pitchfork, sniper
from credtest.classifier import Baseline, Classification, classify
from credtest.config import GlobalConfig, TargetConfig


@dataclass
class AttemptResult:
    timestamp: str
    target: str
    url: str
    credentials: dict
    attack_mode: str
    response_status: int
    response_length: int
    redirect_location: str
    latency_ms: float
    classification: Classification


@dataclass
class TargetState:
    hold_until: float = 0.0
    hold_count: int = 0
    skipped: bool = False
    skip_reason: str = ""


def _make_payload_generator(target: TargetConfig):
    mode = target.attack_mode
    if mode == "sniper":
        return sniper(target.wordlist, target.body_template, target.defaults)
    if mode == "battering_ram":
        return battering_ram(target.wordlist, target.body_template)
    if mode == "pitchfork":
        return pitchfork(target.wordlists, target.body_template)
    if mode == "cluster_bomb":
        return cluster_bomb(target.wordlists, target.body_template)
    raise ValueError(f"Unknown attack_mode: {mode}")


def _extract_credentials(body: dict) -> dict:
    """Pull the actual credential values (non-marker fields stripped of §)."""
    return {k: v for k, v in body.items() if "§" not in str(v)}


async def _send_baseline(
    client: httpx.AsyncClient,
    target: TargetConfig,
    semaphore: asyncio.Semaphore,
    verify_ssl: bool,
) -> Baseline:
    """Send a deliberately bad credential to fingerprint the failure response."""
    dummy = {k: "__credtest_invalid__" for k in target.body_template}
    async with semaphore:
        try:
            if target.content_type == "json":
                resp = await client.request(target.method, target.url, json=dummy)
            else:
                resp = await client.request(target.method, target.url, data=dummy)
        except Exception:
            return Baseline(status_code=200, body_length=0)

    try:
        body_len = len(resp.content)
    except Exception:
        body_len = 0

    return Baseline(
        status_code=resp.status_code,
        body_length=body_len,
        cookies=set(resp.cookies.keys()),
    )


async def run_target(
    target: TargetConfig,
    global_config: GlobalConfig,
    client: httpx.AsyncClient,
    global_semaphore: asyncio.Semaphore,
    on_result: Callable[[AttemptResult], None],
) -> None:
    state = TargetState()
    verify_ssl = global_config.verify_ssl

    # Scope check
    if global_config.scope:
        from urllib.parse import urlparse
        host = urlparse(target.url).netloc
        if not any(host.endswith(s) for s in global_config.scope):
            state.skipped = True
            state.skip_reason = f"URL not in scope: {target.url}"
            return

    baseline = await _send_baseline(client, target, global_semaphore, verify_ssl)
    per_target_sem = asyncio.Semaphore(global_config.per_target_concurrency)

    async def _attempt(body: dict) -> None:
        nonlocal state

        if state.skipped:
            return

        # Wait out any hold
        now = time.monotonic()
        if state.hold_until > now:
            await asyncio.sleep(state.hold_until - now)

        if state.skipped:
            return

        credentials = _extract_credentials(body)
        t0 = time.monotonic()

        async with global_semaphore, per_target_sem:
            try:
                if target.content_type == "json":
                    resp = await client.request(target.method, target.url, json=body)
                else:
                    resp = await client.request(target.method, target.url, data=body)
            except httpx.TimeoutException:
                return
            except Exception:
                return

        latency_ms = (time.monotonic() - t0) * 1000
        prev_cookies = baseline.cookies

        classification = classify(resp, baseline, prev_cookies)

        if classification.action == "hold":
            state.hold_count += 1
            state.hold_until = time.monotonic() + global_config.retry_delay_seconds
            if state.hold_count >= global_config.max_retries:
                state.skipped = True
                state.skip_reason = "Max retries exceeded (rate limit / CAPTCHA)"
            return  # Don't emit a result for held attempts

        location = resp.headers.get("location", "")
        try:
            body_len = len(resp.content)
        except Exception:
            body_len = 0

        result = AttemptResult(
            timestamp=datetime.now(timezone.utc).isoformat(),
            target=target.name,
            url=str(resp.url),
            credentials=credentials,
            attack_mode=target.attack_mode,
            response_status=resp.status_code,
            response_length=body_len,
            redirect_location=location,
            latency_ms=round(latency_ms, 1),
            classification=classification,
        )
        on_result(result)

    # Feed payloads — run concurrently in batches
    tasks = []
    for body in _make_payload_generator(target):
        if state.skipped:
            break
        tasks.append(asyncio.ensure_future(_attempt(body)))
        if len(tasks) >= global_config.per_target_concurrency * 2:
            await asyncio.gather(*tasks)
            tasks = []

    if tasks:
        await asyncio.gather(*tasks)


async def run_all(
    targets: list[TargetConfig],
    global_config: GlobalConfig,
    on_result: Callable[[AttemptResult], None],
) -> None:
    limits = httpx.Limits(
        max_connections=global_config.concurrency,
        max_keepalive_connections=global_config.concurrency // 2,
    )
    timeout = httpx.Timeout(global_config.timeout_seconds, connect=5.0)
    verify = global_config.verify_ssl

    global_semaphore = asyncio.Semaphore(global_config.concurrency)

    async with httpx.AsyncClient(
        limits=limits,
        timeout=timeout,
        verify=verify,
        follow_redirects=False,
        http2=True,
    ) as client:
        await asyncio.gather(
            *(
                run_target(t, global_config, client, global_semaphore, on_result)
                for t in targets
            )
        )
