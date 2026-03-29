from __future__ import annotations

import re
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlparse

from bs4 import BeautifulSoup
from playwright.sync_api import sync_playwright
from playwright.sync_api import TimeoutError as PWTimeout


# ---------------------------------------------------------------------------
# Compiled patterns — module-level
# ---------------------------------------------------------------------------
_RE_CSRF_NAME = re.compile(
    r"^(csrfmiddlewaretoken|_csrf|csrf_token|authenticity_token|_token|"
    r"requestverificationtoken|xsrf.token|x-csrf-token)$",
    re.IGNORECASE,
)

_PASSWORD_NAMES = re.compile(r"pass(word)?|pw|secret", re.IGNORECASE)
_USERNAME_NAMES = re.compile(r"user(name)?|email|login|uid|account", re.IGNORECASE)

_RE_JS_ENDPOINT = re.compile(
    r"""(?:fetch|axios\.post|\.post|action\s*[:=])\s*['"`]([^'"`\s]{3,100})['"`]""",
    re.IGNORECASE,
)


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------
@dataclass
class FormField:
    name: str
    field_type: str
    required: bool
    value: str = ""


@dataclass
class ReconResult:
    url: str
    method: str
    action: str
    content_type: str
    fields: list[FormField] = field(default_factory=list)
    csrf_fields: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    page_title: str = ""
    js_action_hints: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Playwright fetch
# ---------------------------------------------------------------------------
def _fetch_with_playwright(
    url: str,
    verify_ssl: bool,
    cookies: dict[str, str],
) -> tuple[str, str]:
    """Launch headless Chromium, wait for networkidle, return (html, final_url)."""
    with sync_playwright() as pw:
        browser = pw.chromium.launch(headless=True)
        ctx_args: dict = {}
        if not verify_ssl:
            ctx_args["ignore_https_errors"] = True
        context = browser.new_context(**ctx_args)

        if cookies:
            domain = urlparse(url).netloc
            context.add_cookies([
                {"name": k, "value": v, "domain": domain, "path": "/"}
                for k, v in cookies.items()
            ])

        page = context.new_page()
        try:
            page.goto(url, wait_until="networkidle", timeout=20000)
        except PWTimeout:
            # Grab whatever rendered so far
            pass

        html = page.content()
        final_url = page.url
        browser.close()

    return html, final_url


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _resolve_url(base: str, action: str) -> str:
    if not action or action == "#":
        return base
    return urljoin(base, action)


def _pick_login_form(forms: list) -> object | None:
    for form in forms:
        if form.find("input", {"type": "password"}):
            return form
    return forms[0] if forms else None


def _extract_fields(container) -> tuple[list[FormField], list[str]]:
    """Parse input/textarea/select elements from a BS4 tag. Returns (fields, csrf_fields)."""
    fields: list[FormField] = []
    csrf_fields: list[str] = []

    for inp in container.find_all(["input", "textarea", "select"]):
        name = inp.get("name", "").strip()
        if not name:
            continue
        ftype = inp.get("type", "text").lower()
        if ftype in ("submit", "button", "image", "reset"):
            continue

        value = inp.get("value", "")
        required = inp.has_attr("required")

        if _RE_CSRF_NAME.match(name):
            csrf_fields.append(name)
            ftype = "hidden"

        fields.append(FormField(name=name, field_type=ftype, required=required, value=value))

    return fields, csrf_fields


def _suggest_template(fields: list[FormField]) -> dict[str, str]:
    suggestions: dict[str, str] = {}
    for f in fields:
        if f.field_type == "hidden":
            continue
        if _USERNAME_NAMES.search(f.name):
            suggestions[f.name] = "§username§"
        elif _PASSWORD_NAMES.search(f.name):
            suggestions[f.name] = "§password§"
    return suggestions


def _scan_js_hints(soup, base_url: str) -> list[str]:
    hints: list[str] = []
    for script in soup.find_all("script"):
        for m in _RE_JS_ENDPOINT.finditer(script.get_text()):
            candidate = m.group(1)
            if not candidate.startswith(("http://", "https://", "data:", "//")):
                candidate = _resolve_url(base_url, candidate)
            if candidate not in hints:
                hints.append(candidate)
    # Also check data-action / data-url / data-endpoint attributes
    for attr in ("data-action", "data-url", "data-endpoint"):
        for tag in soup.find_all(attrs={attr: True}):
            hint = tag.get(attr, "").strip()
            if hint and hint not in hints:
                hints.append(hint)
    return hints[:10]


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------
def recon(
    url: str,
    verify_ssl: bool = True,
    debug: bool = False,
    cookies: dict[str, str] | None = None,
) -> ReconResult:
    notes: list[str] = []
    if not verify_ssl:
        notes.append("SSL verification disabled — ignoring certificate errors")

    try:
        html, effective_url = _fetch_with_playwright(url, verify_ssl, cookies or {})
    except Exception as e:
        return ReconResult(
            url=url, method="POST", action=url, content_type="form",
            notes=[f"Playwright error: {e}\n  Ensure Playwright is installed: pip install playwright && playwright install chromium"],
        )

    try:
        soup = BeautifulSoup(html, "lxml")
    except Exception:
        soup = BeautifulSoup(html, "html.parser")

    # Page title — always useful for diagnosis
    title_tag = soup.find("title")
    page_title = title_tag.get_text(strip=True) if title_tag else ""

    if effective_url != url:
        notes.append(f"Followed redirect → {effective_url}")

    forms = soup.find_all("form")

    # ------------------------------------------------------------------
    # Happy path: form(s) found
    # ------------------------------------------------------------------
    if forms:
        form = _pick_login_form(forms)
        action = _resolve_url(effective_url, form.get("action", ""))
        method = (form.get("method") or "POST").upper()

        fields, csrf_fields = _extract_fields(form)

        if csrf_fields:
            notes.append(f"CSRF fields detected: {', '.join(csrf_fields)} — handle manually (Phase 2)")

        suggestions = _suggest_template(fields)
        if suggestions:
            notes.append("Suggested body_template: " + str(suggestions))

        if len(forms) > 1:
            notes.append(f"{len(forms)} forms found — selected the one with a password field")

        if debug:
            notes.append(f"[debug] HTML snippet: {html[:600].replace(chr(10), ' ')}")

        return ReconResult(
            url=url,
            method=method,
            action=action,
            content_type="form",
            fields=fields,
            csrf_fields=csrf_fields,
            notes=notes,
            page_title=page_title,
        )

    # ------------------------------------------------------------------
    # No <form> found even after JS render — scan for orphan inputs
    # ------------------------------------------------------------------
    orphan_fields, orphan_csrf = _extract_fields(soup)
    js_hints = _scan_js_hints(soup, effective_url)

    if orphan_fields:
        notes.append(
            f"No <form> wrapper found, but {len(orphan_fields)} input field(s) detected.\n"
            "  This is common with React/Vue custom form components.\n"
            "  Use these field names in your body_template and set the URL manually."
        )
        suggestions = _suggest_template(orphan_fields)
        if suggestions:
            notes.append("Suggested body_template: " + str(suggestions))
        if orphan_csrf:
            notes.append(f"CSRF fields detected: {', '.join(orphan_csrf)}")
    else:
        notes.append(
            "No <form> or input fields found even after full JS render.\n"
            "  Possible causes:\n"
            "  1. Login requires a session cookie — re-run with --cookies 'name=value'\n"
            "  2. SSO/OAuth flow — try reconning the redirected URL directly\n"
            "  3. Input fields rendered inside a Shadow DOM (not accessible via DOM)\n"
            "  4. Uncommon JS framework not yet handled"
        )

    if js_hints:
        notes.append(
            "JS endpoint hints found — one of these may be the login API endpoint:\n"
            + "\n".join(f"  • {h}" for h in js_hints)
        )

    if debug or not orphan_fields:
        notes.append(f"[debug] HTML snippet: {html[:800].replace(chr(10), ' ')}")

    return ReconResult(
        url=url,
        method="POST",
        action=effective_url,
        content_type="form",
        fields=orphan_fields,
        csrf_fields=orphan_csrf,
        notes=notes,
        page_title=page_title,
        js_action_hints=js_hints,
    )
