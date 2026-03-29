from __future__ import annotations

import re
import warnings
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlparse

import requests
from bs4 import BeautifulSoup

# Silence InsecureRequestWarning when verify=False is used
warnings.filterwarnings("ignore", message="Unverified HTTPS request")

# Browser-like headers to avoid bot-detection blocks
_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/124.0.0.0 Safari/537.36"
    ),
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5",
}

# Patterns that indicate a JS-rendered SPA (no server-side HTML form)
_RE_SPA_INDICATORS = re.compile(
    r"(react|angular|vue|next\.js|nuxt|ember|backbone|__NEXT_DATA__|ng-app|data-reactroot)",
    re.IGNORECASE,
)


@dataclass
class FormField:
    name: str
    field_type: str
    required: bool
    value: str = ""  # pre-filled default


@dataclass
class ReconResult:
    url: str
    method: str
    action: str          # resolved form action URL
    content_type: str    # form | json (always form for HTML forms)
    fields: list[FormField] = field(default_factory=list)
    csrf_fields: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)


_RE_CSRF_NAME = re.compile(
    r"^(csrfmiddlewaretoken|_csrf|csrf_token|authenticity_token|_token|"
    r"requestverificationtoken|xsrf.token|x-csrf-token)$",
    re.IGNORECASE,
)

_PASSWORD_NAMES = re.compile(r"pass(word)?|pw|secret", re.IGNORECASE)
_USERNAME_NAMES = re.compile(r"user(name)?|email|login|uid|account", re.IGNORECASE)


def _resolve_url(base: str, action: str) -> str:
    if not action or action == "#":
        return base
    return urljoin(base, action)


def _pick_login_form(forms: list) -> object | None:
    """Heuristic: prefer forms that contain a password field."""
    for form in forms:
        if form.find("input", {"type": "password"}):
            return form
    return forms[0] if forms else None


def recon(url: str, verify_ssl: bool = True, debug: bool = False) -> ReconResult:
    session = requests.Session()
    session.headers.update(_HEADERS)
    notes_ssl: list[str] = []

    try:
        resp = session.get(url, timeout=15, verify=verify_ssl, allow_redirects=True)
        resp.raise_for_status()
    except requests.exceptions.SSLError:
        resp = session.get(url, timeout=15, verify=False, allow_redirects=True)
        notes_ssl = ["SSL verification failed — using verify=False"]
    except requests.exceptions.ConnectionError as e:
        return ReconResult(
            url=url, method="POST", action=url, content_type="form",
            notes=[f"Connection error: {e}"],
        )

    # Try lxml first, fall back to html.parser for malformed HTML
    try:
        soup = BeautifulSoup(resp.text, "lxml")
    except Exception:
        soup = BeautifulSoup(resp.text, "html.parser")

    forms = soup.find_all("form")

    if not forms:
        notes = list(notes_ssl)

        # Diagnose WHY there's no form
        if resp.status_code in (401, 403):
            notes.append(f"HTTP {resp.status_code} — server blocked the request (try adding custom headers or cookies)")
        elif resp.status_code >= 400:
            notes.append(f"HTTP {resp.status_code} — unexpected error response")

        is_spa = bool(_RE_SPA_INDICATORS.search(resp.text))
        if is_spa:
            notes.append(
                "JavaScript-rendered page detected (React/Angular/Vue/Next.js) — "
                "forms are built by JS at runtime. requests cannot see them.\n"
                "  Fix: manually inspect the login form in your browser (DevTools → Network tab)\n"
                "  and configure body_template directly in your credtest.yaml."
            )
        else:
            notes.append(
                "No <form> elements found in server-rendered HTML.\n"
                "  Possible causes:\n"
                "  1. Login form is on a different URL (check for redirects)\n"
                "  2. Page requires a session cookie — visit in browser first\n"
                "  3. Content is dynamically loaded via JavaScript\n"
                "  4. Anti-bot protection (Cloudflare, Akamai) blocking requests"
            )

        if debug:
            snippet = resp.text[:500].replace("\n", " ")
            notes.append(f"[debug] Response snippet: {snippet}")

        return ReconResult(
            url=url,
            method="POST",
            action=url,
            content_type="form",
            notes=notes,
        )

    form = _pick_login_form(forms)
    action = _resolve_url(url, form.get("action", ""))
    method = (form.get("method") or "POST").upper()

    fields: list[FormField] = []
    csrf_fields: list[str] = []
    notes = list(notes_ssl)

    for inp in form.find_all(["input", "textarea", "select"]):
        name = inp.get("name", "").strip()
        if not name:
            continue
        ftype = inp.get("type", "text").lower()
        if ftype == "submit":
            continue

        value = inp.get("value", "")
        required = inp.has_attr("required")

        if _RE_CSRF_NAME.match(name):
            csrf_fields.append(name)
            ftype = "hidden"

        fields.append(FormField(name=name, field_type=ftype, required=required, value=value))

    if csrf_fields:
        notes.append(f"CSRF fields detected: {', '.join(csrf_fields)} — handle manually (Phase 2)")

    # Suggest body_template markers
    suggestions: dict[str, str] = {}
    for f in fields:
        if f.field_type == "hidden":
            continue
        if _USERNAME_NAMES.search(f.name):
            suggestions[f.name] = "§username§"
        elif _PASSWORD_NAMES.search(f.name):
            suggestions[f.name] = "§password§"

    if suggestions:
        notes.append(
            "Suggested body_template: "
            + str({k: v for k, v in suggestions.items()})
        )

    if len(forms) > 1:
        notes.append(f"{len(forms)} forms found — selected the one with a password field")

    return ReconResult(
        url=url,
        method=method,
        action=action,
        content_type="form",
        fields=fields,
        csrf_fields=csrf_fields,
        notes=notes,
    )
