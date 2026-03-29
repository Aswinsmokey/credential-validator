from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Optional

import httpx

# ---------------------------------------------------------------------------
# Tunable constants — adjust during MVP testing
# ---------------------------------------------------------------------------
SCORE_JWT = 40
SCORE_SUCCESS_REDIRECT = 35
SCORE_JSON_TOKEN = 35
SCORE_SESSION_COOKIE_CHANGE = 30
SCORE_JSON_SUCCESS_TRUE = 30
SCORE_SUCCESS_KEYWORDS = 20
SCORE_STATUS_DIFFERS = 15
SCORE_BODY_LENGTH_DIFFERS = 15
SCORE_FAILURE_KEYWORDS = -20
SCORE_LOGIN_REDIRECT = -35

THRESHOLD_HIGH = 50
THRESHOLD_MEDIUM = 20
THRESHOLD_FAILURE = -15

BODY_LENGTH_DEVIATION = 0.30  # 30%

# ---------------------------------------------------------------------------
# Compiled patterns — module-level, never inside functions
# ---------------------------------------------------------------------------
_RE_JWT = re.compile(r"eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+")

_RE_SUCCESS_REDIRECT = re.compile(
    r"/(dashboard|home|admin|portal|app|welcome|account|profile|main|index)(\b|/)",
    re.IGNORECASE,
)
_RE_LOGIN_REDIRECT = re.compile(r"/login", re.IGNORECASE)

_RE_JSON_TOKEN = re.compile(
    r'"(access_token|id_token|jwt|token|auth_token|bearer)"\s*:', re.IGNORECASE
)
_RE_JSON_SUCCESS = re.compile(r'"success"\s*:\s*true', re.IGNORECASE)

_RE_SUCCESS_KEYWORDS = re.compile(
    r"\b(welcome|log\s*out|logout|sign\s*out|signout|dashboard|my account|your account)\b",
    re.IGNORECASE,
)
_RE_FAILURE_KEYWORDS = re.compile(
    r"\b(invalid (password|credentials?|username|email)|incorrect (password|credentials?)|"
    r"wrong password|authentication failed|login failed|bad credentials|"
    r"user not found|account not found|no account|please try again)\b",
    re.IGNORECASE,
)

# Rate limiting
_RE_RATE_LIMIT_BODY = re.compile(
    r"\b(too many requests|slow down|throttled|rate limit|try again later)\b",
    re.IGNORECASE,
)

# CAPTCHA
_RE_CAPTCHA_URL = re.compile(
    r"(recaptcha|hcaptcha|turnstile|challenges\.cloudflare)", re.IGNORECASE
)
_RE_CAPTCHA_ELEMENT = re.compile(
    r'(g-recaptcha|cf-turnstile|h-captcha|data-sitekey)', re.IGNORECASE
)
_RE_CAPTCHA_BODY = re.compile(
    r"\b(human verification|not a robot|prove you.{0,10}human|captcha)\b", re.IGNORECASE
)

# CSRF field names
_RE_CSRF_FIELD = re.compile(
    r"\b(csrfmiddlewaretoken|_csrf|csrf_token|authenticity_token|_token|"
    r"requestverificationtoken|xsrf-token|x-csrf-token)\b",
    re.IGNORECASE,
)
_RE_CSRF_META = re.compile(r'<meta[^>]+name=["\']csrf', re.IGNORECASE)
_RE_CSRF_COOKIE = re.compile(r"csrftoken|xsrf-token", re.IGNORECASE)


@dataclass
class Baseline:
    status_code: int
    body_length: int
    cookies: set[str] = field(default_factory=set)


@dataclass
class Classification:
    auth_success: bool
    auth_confidence: str  # high | medium | low | failure
    auth_score: int
    rate_limited: bool
    captcha_detected: bool
    csrf_detected: bool
    csrf_fields: list[str]
    signals: list[str]
    action: str  # success | hold | skip | failure


def _check_rate_limit(response: httpx.Response) -> tuple[bool, list[str]]:
    signals = []
    if response.status_code == 429:
        signals.append("HTTP 429 Too Many Requests")
        return True, signals
    if "retry-after" in response.headers:
        signals.append("Retry-After header present")
        return True, signals
    remaining = response.headers.get("x-ratelimit-remaining", "")
    if remaining == "0":
        signals.append("X-RateLimit-Remaining: 0")
        return True, signals
    try:
        body = response.text
    except Exception:
        body = ""
    if _RE_RATE_LIMIT_BODY.search(body):
        signals.append("Rate limit keyword in body")
        return True, signals
    return False, signals


def _check_captcha(response: httpx.Response) -> tuple[bool, list[str]]:
    signals = []
    try:
        body = response.text
    except Exception:
        body = ""

    found = False
    if _RE_CAPTCHA_URL.search(str(response.url)):
        signals.append("CAPTCHA URL pattern")
        found = True
    if _RE_CAPTCHA_ELEMENT.search(body):
        signals.append("CAPTCHA element in body")
        found = True
    if _RE_CAPTCHA_BODY.search(body):
        signals.append("CAPTCHA keyword in body")
        found = True
    return found, signals


def _check_csrf(response: httpx.Response) -> tuple[bool, list[str]]:
    signals = []
    try:
        body = response.text
    except Exception:
        body = ""

    fields = _RE_CSRF_FIELD.findall(body)
    if fields:
        unique = list(dict.fromkeys(f.lower() for f in fields))
        signals.extend(f"CSRF field: {f}" for f in unique)
    if _RE_CSRF_META.search(body):
        signals.append("CSRF meta tag")
    for cookie_name in response.cookies:
        if _RE_CSRF_COOKIE.search(cookie_name):
            signals.append(f"CSRF cookie: {cookie_name}")
    return bool(signals), signals


def classify(
    response: httpx.Response,
    baseline: Baseline,
    prev_cookies: Optional[set[str]] = None,
) -> Classification:
    signals: list[str] = []
    score = 0

    # --- Detection checks (may trigger hold/skip) ---
    rate_limited, rl_signals = _check_rate_limit(response)
    signals.extend(rl_signals)

    captcha_detected, cap_signals = _check_captcha(response)
    signals.extend(cap_signals)

    csrf_detected, csrf_signals = _check_csrf(response)
    csrf_fields = [s.replace("CSRF field: ", "") for s in csrf_signals if "CSRF field:" in s]
    signals.extend(csrf_signals)

    if rate_limited or captcha_detected:
        return Classification(
            auth_success=False,
            auth_confidence="low",
            auth_score=score,
            rate_limited=rate_limited,
            captcha_detected=captcha_detected,
            csrf_detected=csrf_detected,
            csrf_fields=csrf_fields,
            signals=signals,
            action="hold",
        )

    # --- Auth scoring ---
    try:
        body = response.text
    except Exception:
        body = ""

    if _RE_JWT.search(body):
        score += SCORE_JWT
        signals.append("JWT token in body")
    for cookie_name, cookie_val in response.cookies.items():
        if _RE_JWT.search(cookie_val):
            score += SCORE_JWT
            signals.append(f"JWT token in cookie: {cookie_name}")
            break

    location = response.headers.get("location", "")
    if location:
        if _RE_SUCCESS_REDIRECT.search(location):
            score += SCORE_SUCCESS_REDIRECT
            signals.append(f"Redirect to success: {location}")
        elif _RE_LOGIN_REDIRECT.search(location):
            score += SCORE_LOGIN_REDIRECT
            signals.append(f"Redirect back to login: {location}")

    if _RE_JSON_TOKEN.search(body):
        score += SCORE_JSON_TOKEN
        signals.append("JSON token field in response")

    current_cookies = set(response.cookies.keys())
    if prev_cookies is not None:
        new_cookies = current_cookies - prev_cookies
        if new_cookies:
            score += SCORE_SESSION_COOKIE_CHANGE
            signals.append(f"New session cookie(s): {', '.join(new_cookies)}")
    elif current_cookies:
        score += SCORE_SESSION_COOKIE_CHANGE
        signals.append(f"Session cookie(s) set: {', '.join(current_cookies)}")

    if _RE_JSON_SUCCESS.search(body):
        score += SCORE_JSON_SUCCESS_TRUE
        signals.append("JSON success: true")

    if _RE_SUCCESS_KEYWORDS.search(body):
        score += SCORE_SUCCESS_KEYWORDS
        signals.append("Success keyword in body")

    if response.status_code != baseline.status_code:
        score += SCORE_STATUS_DIFFERS
        signals.append(f"Status {response.status_code} differs from baseline {baseline.status_code}")

    try:
        body_len = len(response.content)
    except Exception:
        body_len = 0
    if baseline.body_length > 0:
        deviation = abs(body_len - baseline.body_length) / baseline.body_length
        if deviation > BODY_LENGTH_DEVIATION:
            score += SCORE_BODY_LENGTH_DIFFERS
            signals.append(f"Body length {body_len} vs baseline {baseline.body_length} ({deviation:.0%} diff)")

    if _RE_FAILURE_KEYWORDS.search(body):
        score += SCORE_FAILURE_KEYWORDS
        signals.append("Failure keyword in body")

    if score > THRESHOLD_HIGH:
        confidence = "high"
        auth_success = True
        action = "success"
    elif score > THRESHOLD_MEDIUM:
        confidence = "medium"
        auth_success = True
        action = "success"
    elif score < THRESHOLD_FAILURE:
        confidence = "failure"
        auth_success = False
        action = "failure"
    else:
        confidence = "low"
        auth_success = False
        action = "failure"

    return Classification(
        auth_success=auth_success,
        auth_confidence=confidence,
        auth_score=score,
        rate_limited=False,
        captcha_detected=False,
        csrf_detected=csrf_detected,
        csrf_fields=csrf_fields,
        signals=signals,
        action=action,
    )
