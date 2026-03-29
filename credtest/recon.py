from __future__ import annotations

import re
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlparse

from bs4 import BeautifulSoup
from playwright.sync_api import sync_playwright
from playwright.sync_api import TimeoutError as PWTimeout


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Only field types the user actually types into — hidden/system fields excluded
VISIBLE_TYPES = {"text", "email", "password", "number", "tel", "search", ""}

# High-confidence username field names — auto-map without prompting
_USERNAME_AUTO = re.compile(
    r"^(user(name)?|email|login|uid|account|empno|empid|mail|userid|id|identifier)$",
    re.IGNORECASE,
)

# Medium-confidence — auto-map only when it's the sole non-password text field
_USERNAME_MAYBE = re.compile(
    r"user|email|login|uid|account|emp|mail",
    re.IGNORECASE,
)

_PASSWORD_NAMES = re.compile(r"pass(word)?|pw|secret", re.IGNORECASE)

_RE_CSRF_NAME = re.compile(
    r"^(csrfmiddlewaretoken|_csrf|csrf_token|authenticity_token|_token|"
    r"requestverificationtoken|xsrf.token|x-csrf-token)$",
    re.IGNORECASE,
)

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
class FieldMapping:
    """Resolved username/password field names ready for body_template."""
    username_field: str
    password_field: str
    extra_fields: list[str]          # visible fields to include as-is
    skipped_fields: list[str]        # fields the user chose to exclude
    confirmed: bool = False          # True when user interactively confirmed


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
    mapping: FieldMapping | None = None


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


def _extract_visible_fields(container) -> tuple[list[FormField], list[str]]:
    """
    Extract only user-visible input fields (no hidden/system fields).
    Returns (visible_fields, csrf_field_names).
    """
    fields: list[FormField] = []
    csrf_fields: list[str] = []

    for inp in container.find_all(["input", "textarea", "select"]):
        name = inp.get("name", "").strip()
        if not name:
            continue
        ftype = inp.get("type", "text").lower()

        # Drop non-interactive types
        if ftype in ("submit", "button", "image", "reset", "hidden"):
            # But still track CSRF hidden fields separately
            if ftype == "hidden" and _RE_CSRF_NAME.match(name):
                csrf_fields.append(name)
            continue

        # Only keep visible input types
        if ftype not in VISIBLE_TYPES:
            continue

        value = inp.get("value", "")
        required = inp.has_attr("required")
        fields.append(FormField(name=name, field_type=ftype, required=required, value=value))

    return fields, csrf_fields


def _auto_map(fields: list[FormField]) -> FieldMapping | None:
    """
    Try to auto-map username and password fields without user interaction.
    Returns None if mapping is ambiguous and interactive prompt is needed.

    Confidence rules:
    - Password: any field matching _PASSWORD_NAMES → auto-map
    - Username (HIGH confidence): field name matches _USERNAME_AUTO → auto-map
    - Username (MEDIUM): only one non-password text field → auto-map
    - Username (LOW): multiple ambiguous text fields → return None (prompt needed)
    """
    password_field = next(
        (f.name for f in fields if _PASSWORD_NAMES.search(f.name)), None
    )
    if not password_field:
        return None

    non_password = [f for f in fields if f.name != password_field]

    # High-confidence: name matches known username patterns
    for f in non_password:
        if _USERNAME_AUTO.match(f.name):
            extra = [x.name for x in non_password if x.name != f.name]
            return FieldMapping(
                username_field=f.name,
                password_field=password_field,
                extra_fields=extra,
                skipped_fields=[],
                confirmed=True,
            )

    # Medium-confidence: exactly one non-password field
    if len(non_password) == 1:
        return FieldMapping(
            username_field=non_password[0].name,
            password_field=password_field,
            extra_fields=[],
            skipped_fields=[],
            confirmed=True,
        )

    # Ambiguous — needs interactive prompt
    return None


def _interactive_map(fields: list[FormField], url: str) -> FieldMapping:
    """
    Interactive CLI prompt to resolve ambiguous field mappings.
    Only called when auto-mapping fails.
    """
    print(f"\nDetected fields on {url}:")
    for i, f in enumerate(fields, 1):
        print(f"  [{i}] {f.name:<20} ({f.field_type})")

    # Auto-detect password field
    password_field = next(
        (f.name for f in fields if _PASSWORD_NAMES.search(f.name)), None
    )
    non_password = [f for f in fields if f.name != password_field]

    if password_field:
        print(f"\n  ✓ Password field auto-mapped → {password_field} → §password§")

    # Ask which field is the username
    print("\n  Which field is the username/identity?")
    for i, f in enumerate(non_password, 1):
        print(f"    [{i}] {f.name}")

    while True:
        try:
            choice = input("  > ").strip()
            idx = int(choice) - 1
            if 0 <= idx < len(non_password):
                username_field = non_password[idx].name
                break
        except (ValueError, KeyboardInterrupt):
            pass
        print("  Invalid choice, try again.")

    # Ask which fields to skip
    remaining = [f for f in non_password if f.name != username_field]
    skipped: list[str] = []
    if remaining:
        print(f"\n  Other fields: {', '.join(f.name for f in remaining)}")
        print("  Enter numbers to SKIP (or press Enter to include all):")
        for i, f in enumerate(remaining, 1):
            print(f"    [{i}] {f.name}")
        raw = input("  > ").strip()
        if raw:
            for part in raw.split():
                try:
                    idx = int(part) - 1
                    if 0 <= idx < len(remaining):
                        skipped.append(remaining[idx].name)
                except ValueError:
                    pass

    extra = [f.name for f in remaining if f.name not in skipped]

    print(f"\n  Saved mapping:")
    print(f"    {username_field}: §username§")
    if password_field:
        print(f"    {password_field}: §password§")
    for name in extra:
        print(f"    {name}: (included as-is)")
    for name in skipped:
        print(f"    {name}: [excluded]")
    print()

    return FieldMapping(
        username_field=username_field,
        password_field=password_field or "",
        extra_fields=extra,
        skipped_fields=skipped,
        confirmed=True,
    )


def _scan_js_hints(soup, base_url: str) -> list[str]:
    hints: list[str] = []
    for script in soup.find_all("script"):
        for m in _RE_JS_ENDPOINT.finditer(script.get_text()):
            candidate = m.group(1)
            if not candidate.startswith(("http://", "https://", "data:", "//")):
                candidate = _resolve_url(base_url, candidate)
            if candidate not in hints:
                hints.append(candidate)
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
    interactive: bool = True,
) -> ReconResult:
    """
    Fetch a login page with Playwright, extract visible fields only,
    auto-map or interactively map username/password fields.

    Args:
        interactive: If True, prompt the user when field mapping is ambiguous.
                     Set to False when running bulk recon (--url-file).
    """
    notes: list[str] = []
    if not verify_ssl:
        notes.append("SSL verification disabled — ignoring certificate errors")

    try:
        html, effective_url = _fetch_with_playwright(url, verify_ssl, cookies or {})
    except Exception as e:
        return ReconResult(
            url=url, method="POST", action=url, content_type="form",
            notes=[f"Playwright error: {e}\n  Ensure: pip install playwright && playwright install chromium"],
        )

    try:
        soup = BeautifulSoup(html, "lxml")
    except Exception:
        soup = BeautifulSoup(html, "html.parser")

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

        fields, csrf_fields = _extract_visible_fields(form)

        if csrf_fields:
            notes.append(f"CSRF fields detected: {', '.join(csrf_fields)} — handle manually (Phase 2)")
        if len(forms) > 1:
            notes.append(f"{len(forms)} forms found — selected the one with a password field")
        if debug:
            notes.append(f"[debug] HTML snippet: {html[:600].replace(chr(10), ' ')}")

        # Field mapping
        mapping = _auto_map(fields)
        if mapping is None and interactive:
            mapping = _interactive_map(fields, url)
        elif mapping is None:
            # Non-interactive (bulk mode) — best-effort suggestion only
            notes.append(
                "Field mapping ambiguous — re-run this URL with --url for interactive mapping"
            )

        if mapping:
            template: dict[str, str] = {}
            template[mapping.username_field] = "§username§"
            if mapping.password_field:
                template[mapping.password_field] = "§password§"
            for name in mapping.extra_fields:
                f = next((x for x in fields if x.name == name), None)
                if f:
                    template[name] = f.value or name
            notes.append("Suggested body_template: " + str(template))

        return ReconResult(
            url=url,
            method=method,
            action=action,
            content_type="form",
            fields=fields,
            csrf_fields=csrf_fields,
            notes=notes,
            page_title=page_title,
            mapping=mapping,
        )

    # ------------------------------------------------------------------
    # No <form> — scan for orphan inputs
    # ------------------------------------------------------------------
    orphan_fields, orphan_csrf = _extract_visible_fields(soup)
    js_hints = _scan_js_hints(soup, effective_url)

    if orphan_fields:
        notes.append(
            f"No <form> wrapper found, but {len(orphan_fields)} visible input(s) detected.\n"
            "  Common with React/Vue custom form components.\n"
            "  Use these field names in body_template and set the URL manually."
        )
        mapping = _auto_map(orphan_fields)
        if mapping is None and interactive:
            mapping = _interactive_map(orphan_fields, url)
        if mapping:
            template = {mapping.username_field: "§username§"}
            if mapping.password_field:
                template[mapping.password_field] = "§password§"
            notes.append("Suggested body_template: " + str(template))
        if orphan_csrf:
            notes.append(f"CSRF fields: {', '.join(orphan_csrf)}")
    else:
        notes.append(
            "No visible input fields found even after full JS render.\n"
            "  1. Login requires a session cookie — re-run with --cookies 'name=value'\n"
            "  2. SSO/OAuth flow — try reconning the redirected URL directly\n"
            "  3. Inputs inside Shadow DOM (not accessible via DOM)\n"
            "  4. Uncommon JS framework"
        )
        mapping = None

    if js_hints:
        notes.append(
            "JS endpoint hints — one may be the login API:\n"
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
        mapping=mapping,
    )
