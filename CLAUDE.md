# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

**CredTest** is a Python CLI for authorized credential validation during pentest engagements. It replays credential sets against login forms across 100+ web apps, classifies responses heuristically, and pauses automatically on rate-limit/CAPTCHA detection.

## Installation

```bash
pip install httpx[http2] beautifulsoup4 lxml mechanicalsoup typer[all] rich pyyaml
```

## CLI Commands

```bash
# Analyze a login form (safe — no credentials sent)
python -m credtest recon --url https://target.internal/login

# Validate a config file
python -m credtest validate --config credtest.yaml

# Run credential tests
python -m credtest run --config credtest.yaml --output results/

# Show all results including failures
python -m credtest run --config credtest.yaml --verbose

# Target a single app from config
python -m credtest run --config credtest.yaml --target app-name
```

## Module Structure

```
credtest/
├── __main__.py     # Entry point
├── cli.py          # Typer CLI — commands: run, recon, validate
├── config.py       # YAML load + validation
├── attack_modes.py # 4 lazy generators using itertools
├── engine.py       # Async attack loop — httpx, hold/pause, baseline calibration
├── classifier.py   # Heuristic weighted scoring (no AI)
├── recon.py        # Form field detection via requests + BS4
├── output.py       # Rich tables, JSONL writer, CSV writer
└── wordlists/
```

## Architecture Notes

**Attack flow**: `engine.py` orchestrates everything — it sends a baseline (invalid credential) per target first to fingerprint failure responses, then feeds payloads from an `attack_modes` generator through a semaphore-gated `httpx.AsyncClient`, passing each response to `classifier.py`.

**Attack modes** are lazy Python generators (itertools-based) in `attack_modes.py`. Template injection uses `§marker§` syntax in `body_template` YAML fields.

**Classifier** is a pure heuristic weighted scorer. Thresholds and signal weights must be defined as module-level constants at the top of `classifier.py` so they're easy to tune. Regex patterns must be compiled at module load, not inside functions.

**Hold logic** is per-target: each target has an independent `hold_until` timestamp. Rate-limit or CAPTCHA detection pauses only that target while others continue. After `max_retries` consecutive holds, the target is skipped.

**Concurrency limits** (targeting AWS t3.micro, 1GB RAM):
- Global: `asyncio.Semaphore(50)`
- Per-target: 10 parallel requests
- `httpx.Limits(max_connections=50, max_keepalive_connections=20)`
- Timeout: `httpx.Timeout(10.0, connect=5.0)`

**Internal apps**: Use `verify=False` in httpx for self-signed certs, but always log a warning.

## Classifier Scoring Reference

| Signal | Score |
|---|---|
| JWT in body/cookie | +40 |
| Redirect to `/dashboard`, `/home`, `/admin` | +35 |
| JSON token field | +35 |
| New/changed session cookie | +30 |
| `success: true` in JSON | +30 |
| Success keywords | +20 |
| Status differs from baseline | +15 |
| Body length >30% different from baseline | +15 |
| Failure keywords | −20 |
| Redirect back to `/login` | −35 |

Thresholds: >50 = HIGH confidence success | >20 = MEDIUM | <−15 = failure

## Important Constraints

- **No AI at runtime** — classifier is deterministic/heuristic only
- **No CAPTCHA bypass** — detect and hold is correct; never add solving logic
- **No browser in Phase 1** — httpx + BS4 only (Playwright is Phase 2)
- **Scope validation** — the `--scope-check` flag must validate target URLs against an authorized scope list in config
- **Memory budget** — stay under ~150MB; attack mode generators must be lazy (never load full wordlist into memory)

## Config File Format

```yaml
global:
  concurrency: 50
  per_target_concurrency: 10
  timeout_seconds: 10
  retry_delay_seconds: 60
  max_retries: 3

targets:
  - name: "app-name"
    url: "https://target.internal/login"
    method: POST
    content_type: "form"        # form | json
    body_template:
      username: "§username§"
      password: "§password§"
    attack_mode: cluster_bomb   # sniper | battering_ram | pitchfork | cluster_bomb
    wordlists:
      username: "./wordlists/users.txt"
      password: "./wordlists/passwords.txt"
```

## Phase 2 (Not Yet Implemented)

CSRF token extraction/replay, Playwright support, checkpoint/resume, per-target custom headers, custom success/failure matchers, distributed mode.
