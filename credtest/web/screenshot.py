from __future__ import annotations

import hashlib
from pathlib import Path
from urllib.parse import urljoin

import httpx
from bs4 import BeautifulSoup

SCREENSHOTS_DIR = Path("data/screenshots")


async def capture_snapshot(url: str, target_name: str) -> tuple[str, str]:
    """
    Fetch login page HTML, rewrite relative URLs to absolute, save to disk.
    Returns (snapshot_path, html_hash).
    Uses sandboxed iframe — JS will not execute in the browser.
    """
    SCREENSHOTS_DIR.mkdir(parents=True, exist_ok=True)

    headers = {
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/124.0.0.0 Safari/537.36"
        )
    }

    try:
        async with httpx.AsyncClient(
            verify=False,
            follow_redirects=True,
            timeout=10.0,
            headers=headers,
        ) as client:
            resp = await client.get(url)
        html = resp.text
    except Exception as e:
        html = f"<html><body><p>Could not fetch preview: {e}</p></body></html>"

    html_hash = hashlib.sha256(html.encode()).hexdigest()[:16]

    # Rewrite relative asset URLs to absolute so iframe renders CSS/images
    try:
        soup = BeautifulSoup(html, "lxml")
        for tag in soup.find_all(["link", "img"]):
            for attr in ["href", "src"]:
                val = tag.get(attr, "")
                if val and not val.startswith(("http", "//", "data:")):
                    tag[attr] = urljoin(url, val)
        # Add <base> tag for any remaining relative URLs
        if soup.head:
            base = soup.new_tag("base", href=url)
            soup.head.insert(0, base)
        html_out = str(soup)
    except Exception:
        html_out = html

    # Sanitize target name for filesystem
    safe_name = "".join(c if c.isalnum() or c in "-_" else "_" for c in target_name)
    snapshot_path = str(SCREENSHOTS_DIR / f"{safe_name}.html")

    with open(snapshot_path, "w", encoding="utf-8") as f:
        f.write(html_out)

    return snapshot_path, html_hash
