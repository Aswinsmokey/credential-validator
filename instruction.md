## 🔐 CredTest — Automated Credential Validation Framework (MVP)

### Project Context
This is an internal pentest engagement tool for authorized security audits. The goal is to build a Python-based credential testing framework that automates login testing across 100+ web applications with multiple credential sets. All testing is done only against systems you have explicit written authorization to test.

---

### What We're Building
A CLI tool called **`credtest`** that:
1. Reads a YAML config listing target apps + credentials
2. Analyzes each app's login form (field names, endpoint, method)
3. Replays credentials using 4 attack modes (like Burp Intruder)(user can select the mode)
4. Classifies each response — success, failure, rate limited, CAPTCHA, CSRF
5. Pauses automatically if rate limiting or CAPTCHA is detected
6. Outputs results as terminal table + JSON lines + CSV

---

### Hard Constraints
- **Free tools only** — no paid APIs, no SaaS, no LLM calls
- **No AI** in the runtime logic — pure heuristic/deterministic classifiers
- **No browser (Phase 1)** — requests + BeautifulSoup only, no Playwright (too heavy for t3.micro)
- **Runs on AWS t3.micro** — 1 vCPU, 1GB RAM. Max ~150MB memory footprint
- **MVP first** — build, test on 2–3 apps, iterate

---

### Tech Stack
```
pip install httpx[http2] beautifulsoup4 lxml mechanicalsoup typer[all] rich pyyaml
```

| Library | Role |
|---|---|
| `httpx[http2]` | Async HTTP client for credential replay |
| `beautifulsoup4` + `lxml` | HTML parsing, form field detection |
| `mechanicalsoup` | Session/cookie handling for recon |
| `typer[all]` | CLI interface |
| `rich` | Terminal tables, progress display |
| `pyyaml` | Config file parsing |

---

### Attack Modes (Burp Intruder equivalents)
All implemented as Python generators using `itertools` — lazy, memory-efficient:

| Mode | Behavior |
|---|---|
| **Sniper** | One wordlist, cycle through each position one at a time, others stay at default |
| **Battering Ram** | One wordlist, same payload inserted into ALL positions simultaneously |
| **Pitchfork** | Multiple wordlists, parallel iteration — `users[0]` paired with `passwords[0]`, etc. |
| **Cluster Bomb** | Multiple wordlists, cartesian product — every username × every password combo |

Body template uses `§marker§` syntax:
```yaml
body_template:
  username: "§username§"
  password: "§password§"
```

---

### Response Classifier (No AI — Heuristic Weighted Scoring)

**Step 1 — Baseline**: Send a deliberately invalid credential first to fingerprint the failure response (status, body length, hash).

**Step 2 — Score each response** (deviations from baseline = higher suspicion of success):

| Signal | Score |
|---|---|
| JWT (`eyJ...`) in body or cookie | +40 |
| Redirect to `/dashboard`, `/home`, `/admin`, etc. | +35 |
| JSON token field (`access_token`, `jwt`, etc.) | +35 |
| New/changed session cookie | +30 |
| JSON `success: true` | +30 |
| Success keywords (`welcome`, `logout`, etc.) | +20 |
| Status differs from baseline | +15 |
| Body length differs >30% from baseline | +15 |
| Failure keywords (`invalid password`, etc.) | −20 |
| Redirect back to `/login` | −35 |

**Thresholds**: Score >50 = ✅ HIGH confidence success | >20 = ⚠️ MEDIUM | <−15 = ❌ failure

**Step 3 — Detection Checks** (run before scoring, can short-circuit):

- **Rate Limiting**: HTTP 429, `Retry-After` header, `X-RateLimit-Remaining: 0`, body text matching `too many requests / slow down / throttled` → **HOLD target**
- **CAPTCHA**: reCAPTCHA/hCaptcha/Turnstile JS includes, `g-recaptcha`/`cf-turnstile` divs, keywords like `human verification / not a robot` → **HOLD target**
- **CSRF**: Hidden input fields named `csrfmiddlewaretoken`, `_csrf`, `authenticity_token`, etc., CSRF meta tags, `csrftoken` cookies → **REPORT only (Phase 1), don't attempt to handle**

---

### Hold / Pause Logic
- When rate limiting or CAPTCHA detected on a target → pause that target for `retry_delay_seconds` (default: 60s)
- Other targets continue unaffected
- After `max_retries` consecutive holds on same target → skip remaining credentials for it and log reason
- State is per-target — independent `hold_until` timestamp per target

---

### Concurrency Limits for t3.micro
```python
asyncio.Semaphore(50)           # max 50 concurrent requests total
per_target_concurrency = 10     # max 10 parallel requests per target
httpx.Limits(max_connections=50, max_keepalive_connections=20)
timeout = httpx.Timeout(10.0, connect=5.0)
```

---

### Config File Format (YAML)
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
    content_type: "form"       # form | json
    body_template:
      username: "§username§"
      password: "§password§"
    attack_mode: cluster_bomb  # sniper | battering_ram | pitchfork | cluster_bomb
    wordlists:
      username: "./wordlists/users.txt"
      password: "./wordlists/passwords.txt"
    # For sniper/battering_ram — use:
    # wordlist: "./wordlists/combined.txt"
    # defaults:
    #   username: "admin"
    #   password: "password"
```

---

### Output Format
**Terminal**: Rich table showing target, credentials tested, result classification, signals detected — successes in green, holds in yellow, failures suppressed unless `--verbose`

**JSON Lines** (one object per attempt):
```json
{
  "timestamp": "...",
  "target": "app-name",
  "url": "https://target.internal/login",
  "credentials": {"username": "admin", "password": "admin123"},
  "attack_mode": "cluster_bomb",
  "response": {"status_code": 302, "content_length": 0, "redirect_location": "/dashboard", "latency_ms": 142},
  "classification": {
    "auth_success": true,
    "auth_confidence": "high",
    "auth_score": 65,
    "rate_limited": false,
    "captcha_detected": false,
    "csrf_detected": true,
    "csrf_fields": ["_csrf"],
    "signals": ["Redirect to success: /dashboard", "Session cookie set: JSESSIONID"]
  },
  "action": "success"
}
```

**CSV**: Flat summary — one row per attempt, columns: `timestamp, target, username, password, success, confidence, rate_limited, captcha, csrf, action`

---

### Module Structure
```
credtest/
├── __main__.py        # python -m credtest entry point
├── cli.py             # Typer CLI — commands: run, recon, validate
├── config.py          # YAML load + validation
├── attack_modes.py    # 4 generators: sniper, battering_ram, pitchfork, cluster_bomb
├── engine.py          # Async attack loop — httpx, hold/pause, baseline
├── classifier.py      # Heuristic classifier — rate limit, captcha, csrf, auth success
├── recon.py           # Form analysis — requests + BS4, field detection
├── output.py          # Rich tables, JSONL writer, CSV writer
└── wordlists/
    ├── top_usernames.txt
    └── top_passwords.txt
```

---

### CLI Commands
```bash
# Analyze a login form before attacking (safe, no credentials sent)
python -m credtest recon --url https://target.internal/login

# Validate config file
python -m credtest validate --config credtest.yaml

# Run credential tests
python -m credtest run --config credtest.yaml --output results/

# Run with verbose (show all failures too)
python -m credtest run --config credtest.yaml --verbose

# Target a single app
python -m credtest run --config credtest.yaml --target app-name
```

---

### Phase 1 MVP Scope (Build This First)
- [x] YAML config loader
- [x] `recon` command — form field auto-detection
- [x] 4 attack mode generators
- [x] Async httpx engine with semaphore-gated concurrency
- [x] Baseline calibration per target
- [x] Heuristic response classifier
- [x] Rate limit + CAPTCHA detection and hold logic
- [x] CSRF detection (report only, no handling)
- [x] Rich terminal output + JSONL + CSV

### Phase 2 (After MVP Validation)
- [ ] CSRF token extraction and automatic replay
- [ ] Playwright support for JS-rendered login pages (run on separate machine or larger instance)
- [ ] Checkpoint/resume from last tested credential index
- [ ] Per-target custom headers (Authorization, Referer, Origin)
- [ ] Custom success/failure matchers per target (override classifier)
- [ ] Distributed mode across multiple instances

---

### Important Notes for Claude
- This tool is **for authorized internal security audits only** — always add `--scope-check` validation that the URL matches a configured authorized scope list
- Do **not** add any features that bypass CAPTCHA or automate CAPTCHA solving — detect and pause is the correct behavior
- The classifier is heuristic — expect ~5–10% ambiguous results that need manual review
- Keep the `classifier.py` thresholds as constants at the top of the file so they're easy to tune during MVP testing
- All regex patterns should be compiled once at module load, not inside functions
- Use `verify=False` in httpx for internal apps with self-signed certs, but log a warning
- The `§marker§` syntax in body templates must be documented clearly — it's the core config UX

---

That's everything. Paste this into your Claude Project system prompt and you'll have full context every session — architecture decisions, constraints, exact module boundaries, and the classifier logic all in one place. Good luck with the build! 🔨