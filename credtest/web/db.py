from __future__ import annotations

import json
import os
import time
from pathlib import Path
from typing import Any

import aiosqlite

DB_PATH = Path("data/credtest.db")

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS targets (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    name         TEXT NOT NULL UNIQUE,
    url          TEXT NOT NULL,
    method       TEXT DEFAULT 'POST',
    content_type TEXT DEFAULT 'form',
    body_template TEXT,
    attack_mode  TEXT DEFAULT 'cluster_bomb',
    wordlists    TEXT,
    status       TEXT DEFAULT 'pending',
    hold_until   REAL,
    hold_reason  TEXT,
    hold_count   INTEGER DEFAULT 0,
    error_msg    TEXT,
    created_at   REAL DEFAULT (unixepoch('now')),
    updated_at   REAL DEFAULT (unixepoch('now'))
);

CREATE TABLE IF NOT EXISTS recon_results (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    target_id        INTEGER REFERENCES targets(id),
    endpoint_url     TEXT,
    endpoint_method  TEXT,
    fields           TEXT,
    csrf_detected    BOOLEAN DEFAULT 0,
    csrf_field_name  TEXT,
    captcha_detected BOOLEAN DEFAULT 0,
    captcha_type     TEXT,
    mfa_detected     BOOLEAN DEFAULT 0,
    rate_limit_detected BOOLEAN DEFAULT 0,
    screenshot_path  TEXT,
    raw_html_hash    TEXT,
    created_at       REAL DEFAULT (unixepoch('now'))
);

CREATE TABLE IF NOT EXISTS test_runs (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    target_id     INTEGER REFERENCES targets(id),
    attack_mode   TEXT NOT NULL,
    wordlists     TEXT,
    status        TEXT DEFAULT 'pending',
    total_combos  INTEGER DEFAULT 0,
    tested_count  INTEGER DEFAULT 0,
    success_count INTEGER DEFAULT 0,
    started_at    REAL,
    finished_at   REAL,
    created_at    REAL DEFAULT (unixepoch('now'))
);

CREATE TABLE IF NOT EXISTS results (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id          INTEGER REFERENCES test_runs(id),
    target_id       INTEGER REFERENCES targets(id),
    username        TEXT,
    password        TEXT,
    status_code     INTEGER,
    content_length  INTEGER,
    latency_ms      INTEGER,
    redirect_url    TEXT,
    auth_success    BOOLEAN,
    auth_confidence TEXT,
    auth_score      INTEGER,
    rate_limited    BOOLEAN DEFAULT 0,
    captcha_hit     BOOLEAN DEFAULT 0,
    signals         TEXT,
    created_at      REAL DEFAULT (unixepoch('now'))
);

CREATE INDEX IF NOT EXISTS idx_results_target  ON results(target_id);
CREATE INDEX IF NOT EXISTS idx_results_run     ON results(run_id);
CREATE INDEX IF NOT EXISTS idx_results_success ON results(auth_success);
CREATE INDEX IF NOT EXISTS idx_targets_status  ON targets(status);
"""

_connection: aiosqlite.Connection | None = None


async def get_db() -> aiosqlite.Connection:
    global _connection
    if _connection is None:
        DB_PATH.parent.mkdir(parents=True, exist_ok=True)
        _connection = await aiosqlite.connect(str(DB_PATH))
        _connection.row_factory = aiosqlite.Row
    return _connection


async def init() -> None:
    db = await get_db()
    await db.executescript(SCHEMA_SQL)
    await db.commit()


async def enable_wal() -> None:
    db = await get_db()
    await db.execute("PRAGMA journal_mode=WAL")
    await db.execute("PRAGMA synchronous=NORMAL")
    await db.execute("PRAGMA cache_size=-2000")
    await db.commit()


async def close() -> None:
    global _connection
    if _connection:
        await _connection.close()
        _connection = None


# ---------------------------------------------------------------------------
# Target helpers
# ---------------------------------------------------------------------------

async def upsert_target(target) -> int:
    db = await get_db()
    body_template = json.dumps(target.body_template) if target.body_template else None
    wordlists = json.dumps(target.wordlists) if target.wordlists else None
    now = time.time()
    async with db.execute(
        """
        INSERT INTO targets (name, url, method, content_type, body_template, attack_mode, wordlists, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(name) DO UPDATE SET
            url=excluded.url,
            method=excluded.method,
            content_type=excluded.content_type,
            body_template=excluded.body_template,
            attack_mode=excluded.attack_mode,
            wordlists=excluded.wordlists,
            updated_at=excluded.updated_at
        """,
        (target.name, target.url, target.method, target.content_type,
         body_template, target.attack_mode, wordlists, now),
    ) as cur:
        row_id = cur.lastrowid
    await db.commit()
    # For ON CONFLICT updates, lastrowid may be 0 — fetch by name
    if not row_id:
        async with db.execute("SELECT id FROM targets WHERE name=?", (target.name,)) as cur:
            row = await cur.fetchone()
            row_id = row["id"]
    return row_id


async def get_target(target_id: int) -> aiosqlite.Row | None:
    db = await get_db()
    async with db.execute("SELECT * FROM targets WHERE id=?", (target_id,)) as cur:
        return await cur.fetchone()


async def get_all_targets() -> list[aiosqlite.Row]:
    db = await get_db()
    async with db.execute("SELECT * FROM targets ORDER BY name") as cur:
        return await cur.fetchall()


async def update_target_status(target_id: int, status: str, error_msg: str = None) -> None:
    db = await get_db()
    await db.execute(
        "UPDATE targets SET status=?, error_msg=?, updated_at=? WHERE id=?",
        (status, error_msg, time.time(), target_id),
    )
    await db.commit()


async def update_target_hold(target_id: int, reason: str, delay_seconds: int = 60) -> None:
    db = await get_db()
    hold_until = time.time() + delay_seconds
    await db.execute(
        """UPDATE targets SET status='held', hold_until=?, hold_reason=?,
           hold_count=hold_count+1, updated_at=? WHERE id=?""",
        (hold_until, reason, time.time(), target_id),
    )
    await db.commit()


async def release_target_hold(target_id: int) -> None:
    db = await get_db()
    await db.execute(
        "UPDATE targets SET status='ready', hold_until=NULL, hold_reason=NULL, updated_at=? WHERE id=?",
        (time.time(), target_id),
    )
    await db.commit()


async def get_dashboard_counts() -> dict:
    db = await get_db()
    async with db.execute(
        "SELECT status, COUNT(*) as cnt FROM targets GROUP BY status"
    ) as cur:
        rows = await cur.fetchall()
    counts = {r["status"]: r["cnt"] for r in rows}
    counts["total"] = sum(counts.values())
    return counts


# ---------------------------------------------------------------------------
# Recon helpers
# ---------------------------------------------------------------------------

async def insert_recon_result(target_id: int, **kwargs) -> int:
    db = await get_db()
    kwargs["target_id"] = target_id
    cols = ", ".join(kwargs.keys())
    placeholders = ", ".join("?" * len(kwargs))
    async with db.execute(
        f"INSERT INTO recon_results ({cols}) VALUES ({placeholders})",
        list(kwargs.values()),
    ) as cur:
        row_id = cur.lastrowid
    await db.commit()
    return row_id


async def get_latest_recon(target_id: int) -> aiosqlite.Row | None:
    db = await get_db()
    async with db.execute(
        "SELECT * FROM recon_results WHERE target_id=? ORDER BY created_at DESC LIMIT 1",
        (target_id,),
    ) as cur:
        return await cur.fetchone()


# ---------------------------------------------------------------------------
# Test run helpers
# ---------------------------------------------------------------------------

async def create_test_run(target_id: int, attack_mode: str, wordlists: dict, total_combos: int = 0) -> int:
    db = await get_db()
    async with db.execute(
        """INSERT INTO test_runs (target_id, attack_mode, wordlists, total_combos)
           VALUES (?, ?, ?, ?)""",
        (target_id, attack_mode, json.dumps(wordlists), total_combos),
    ) as cur:
        row_id = cur.lastrowid
    await db.commit()
    return row_id


async def get_test_run(run_id: int) -> aiosqlite.Row | None:
    db = await get_db()
    async with db.execute("SELECT * FROM test_runs WHERE id=?", (run_id,)) as cur:
        return await cur.fetchone()


async def update_run_status(run_id: int, status: str, started_at: float = None, finished_at: float = None) -> None:
    db = await get_db()
    updates = ["status=?"]
    params: list[Any] = [status]
    if started_at is not None:
        updates.append("started_at=?")
        params.append(started_at)
    if finished_at is not None:
        updates.append("finished_at=?")
        params.append(finished_at)
    params.append(run_id)
    await db.execute(f"UPDATE test_runs SET {', '.join(updates)} WHERE id=?", params)
    await db.commit()


async def update_run_progress(run_id: int, tested: int, successes: int) -> None:
    db = await get_db()
    await db.execute(
        "UPDATE test_runs SET tested_count=?, success_count=? WHERE id=?",
        (tested, successes, run_id),
    )
    await db.commit()


async def get_latest_run(target_id: int) -> aiosqlite.Row | None:
    db = await get_db()
    async with db.execute(
        "SELECT * FROM test_runs WHERE target_id=? ORDER BY created_at DESC LIMIT 1",
        (target_id,),
    ) as cur:
        return await cur.fetchone()


# ---------------------------------------------------------------------------
# Results helpers
# ---------------------------------------------------------------------------

async def insert_results_batch(rows: list[dict]) -> None:
    if not rows:
        return
    db = await get_db()
    cols = list(rows[0].keys())
    placeholders = ", ".join("?" * len(cols))
    col_str = ", ".join(cols)
    await db.executemany(
        f"INSERT INTO results ({col_str}) VALUES ({placeholders})",
        [list(r.values()) for r in rows],
    )
    await db.commit()


async def get_results_page(target_id: int, page: int = 1, per_page: int = 50, success_only: bool = False) -> list[aiosqlite.Row]:
    db = await get_db()
    offset = (page - 1) * per_page
    where = "target_id=?"
    params: list[Any] = [target_id]
    if success_only:
        where += " AND auth_success=1"
    async with db.execute(
        f"SELECT * FROM results WHERE {where} ORDER BY created_at DESC LIMIT ? OFFSET ?",
        params + [per_page, offset],
    ) as cur:
        return await cur.fetchall()


async def get_results_summary(target_id: int) -> dict:
    db = await get_db()
    async with db.execute(
        """SELECT
            COUNT(*) as total,
            SUM(CASE WHEN auth_success=1 THEN 1 ELSE 0 END) as success,
            SUM(CASE WHEN rate_limited=1 THEN 1 ELSE 0 END) as rate_limited,
            SUM(CASE WHEN captcha_hit=1 THEN 1 ELSE 0 END) as captcha
           FROM results WHERE target_id=?""",
        (target_id,),
    ) as cur:
        row = await cur.fetchone()
    return dict(row) if row else {"total": 0, "success": 0, "rate_limited": 0, "captcha": 0}


async def get_all_results_for_export(target_id: int):
    db = await get_db()
    async with db.execute(
        "SELECT * FROM results WHERE target_id=? ORDER BY created_at",
        (target_id,),
    ) as cur:
        async for row in cur:
            yield dict(row)
