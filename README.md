# CredTest — Automated Credential Validation Framework

> **For authorized security audits and penetration testing engagements only.**
> Never use this tool against systems you do not have explicit written authorization to test.

CredTest is a fast, lightweight CLI that automates credential testing across web applications. It replays credential sets against login forms using multiple attack strategies, classifies each response heuristically, and pauses automatically when rate-limiting or CAPTCHA is detected — all without a browser.

---

## Features

- **4 Attack Modes** — Sniper, Battering Ram, Pitchfork, Cluster Bomb (Burp Intruder equivalents)
- **Heuristic Response Classifier** — weighted scoring across JWTs, redirects, cookies, keywords, and body deviation; no AI, fully deterministic
- **Auto-Hold Logic** — per-target pause on rate-limit or CAPTCHA detection; other targets continue unaffected
- **CSRF Detection** — detects CSRF tokens and reports them (Phase 1)
- **Recon Mode** — analyzes a login form and auto-suggests your `body_template` config before any credentials are sent
- **Async Engine** — `httpx` + `asyncio`, semaphore-gated concurrency tuned for AWS t3.micro (1 vCPU / 1GB RAM)
- **Multiple Output Formats** — Rich terminal tables, JSON Lines, CSV

---

## Installation

**Requirements:** Python 3.10+

```bash
git clone https://github.com/Aswinsmokey/credential-validator.git
cd credential-validator
pip install -e .
```

Or install dependencies directly:

```bash
pip install httpx[http2] beautifulsoup4 lxml mechanicalsoup "typer[all]" rich pyyaml requests
```

---

## Quick Start

### 1. Recon — analyze a login form first (no credentials sent)

```bash
python -m credtest recon --url https://target.internal/login
```

Example output:
```
Recon: https://target.internal/login

  Action URL: https://target.internal/login
  Method:     POST
  Fields:
    • username (text) (required)
    • password (password) (required)
    • _csrf (hidden) = abc123

  ⚠ CSRF fields: _csrf

  ℹ Suggested body_template: {'username': '§username§', 'password': '§password§'}
```

### 2. Create your config

Copy and edit the example:

```bash
cp credtest.yaml.example credtest.yaml
```

### 3. Validate config

```bash
python -m credtest validate --config credtest.yaml
```

### 4. Run

```bash
# Run all targets
python -m credtest run --config credtest.yaml --output results/

# Run a single target
python -m credtest run --config credtest.yaml --target app-name

# Show all attempts including failures
python -m credtest run --config credtest.yaml --verbose
```

---

## Configuration

```yaml
global:
  concurrency: 50              # max concurrent requests (total)
  per_target_concurrency: 10   # max concurrent requests per target
  timeout_seconds: 10
  retry_delay_seconds: 60      # hold duration on rate-limit/CAPTCHA
  max_retries: 3               # skip target after N consecutive holds
  verify_ssl: true
  scope:                       # only test URLs matching these hosts
    - target.internal
    - app.corp.local

targets:
  - name: "internal-app"
    url: "https://app.target.internal/login"
    method: POST
    content_type: form         # form | json
    body_template:
      username: "§username§"
      password: "§password§"
    attack_mode: cluster_bomb  # sniper | battering_ram | pitchfork | cluster_bomb
    wordlists:
      username: "./credtest/wordlists/top_usernames.txt"
      password: "./credtest/wordlists/top_passwords.txt"
```

### Attack Modes

| Mode | Wordlists | Behavior |
|---|---|---|
| `sniper` | 1 (`wordlist`) | Cycles one position at a time; others stay at `defaults` |
| `battering_ram` | 1 (`wordlist`) | Same word inserted into all positions simultaneously |
| `pitchfork` | N (`wordlists`) | Parallel iteration — `users[i]` paired with `passwords[i]` |
| `cluster_bomb` | N (`wordlists`) | Cartesian product — every username × every password |

Template injection uses `§marker§` syntax in `body_template` values.

---

## Output

### Terminal (Rich)

Successes shown in green, holds in yellow, failures suppressed unless `--verbose`.

### JSON Lines (`results/results.jsonl`)

One object per attempt:

```json
{
  "timestamp": "2024-01-15T10:23:41+00:00",
  "target": "internal-app",
  "url": "https://app.target.internal/login",
  "credentials": { "username": "admin", "password": "admin123" },
  "attack_mode": "cluster_bomb",
  "response": { "status_code": 302, "content_length": 0, "redirect_location": "/dashboard", "latency_ms": 142 },
  "classification": {
    "auth_success": true,
    "auth_confidence": "high",
    "auth_score": 65,
    "rate_limited": false,
    "captcha_detected": false,
    "csrf_detected": true,
    "csrf_fields": ["_csrf"],
    "signals": ["Redirect to success: /dashboard", "New session cookie(s): JSESSIONID"]
  },
  "action": "success"
}
```

### CSV (`results/results.csv`)

Flat summary — one row per attempt with columns: `timestamp, target, username, password, success, confidence, score, rate_limited, captcha, csrf, action`

---

## Classifier Scoring

The classifier sends a baseline (invalid credential) first to fingerprint each target's failure response, then scores subsequent responses by deviation:

| Signal | Score |
|---|---|
| JWT (`eyJ…`) in body or cookie | +40 |
| Redirect to `/dashboard`, `/home`, `/admin`, etc. | +35 |
| JSON token field (`access_token`, `jwt`, etc.) | +35 |
| New / changed session cookie | +30 |
| JSON `"success": true` | +30 |
| Success keywords (`welcome`, `logout`, etc.) | +20 |
| Status code differs from baseline | +15 |
| Body length deviates >30% from baseline | +15 |
| Failure keywords (`invalid password`, etc.) | −20 |
| Redirect back to `/login` | −35 |

**Confidence thresholds:** Score > 50 → HIGH · > 20 → MEDIUM · < −15 → failure

Classifier thresholds are defined as constants at the top of [`credtest/classifier.py`](credtest/classifier.py) for easy tuning.

---

## Project Structure

```
credtest/
├── __main__.py       # Entry point (python -m credtest)
├── cli.py            # Typer CLI — run / recon / validate
├── config.py         # YAML loader + validator
├── attack_modes.py   # 4 lazy payload generators (itertools-based)
├── engine.py         # Async attack loop, baseline calibration, hold logic
├── classifier.py     # Heuristic weighted response classifier
├── recon.py          # Login form analysis (requests + BeautifulSoup)
├── output.py         # Rich tables, JSONL writer, CSV writer
└── wordlists/
    ├── top_usernames.txt
    └── top_passwords.txt
```

---

## Constraints & Design Decisions

- **No AI at runtime** — classifier is purely deterministic/heuristic
- **No browser (Phase 1)** — `httpx` + BeautifulSoup only; no Playwright
- **No CAPTCHA bypass** — detect and hold is the correct behavior
- **Scope enforcement** — URLs are validated against the `scope` list in config
- **Memory-efficient** — attack mode generators are lazy; wordlists are never fully loaded into memory simultaneously
- **t3.micro compatible** — tuned to stay under ~150MB memory footprint

---

## Roadmap

- [ ] CSRF token extraction and automatic replay
- [ ] Playwright support for JavaScript-rendered login pages
- [ ] Checkpoint / resume from last tested credential index
- [ ] Per-target custom headers (`Authorization`, `Referer`, `Origin`)
- [ ] Custom success/failure matchers per target
- [ ] Distributed mode across multiple instances

---

## Legal

This tool is intended **exclusively** for authorized penetration testing and security audits. The user is responsible for ensuring they have explicit written authorization before testing any system. Unauthorized use is illegal and unethical.
