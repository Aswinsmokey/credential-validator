from __future__ import annotations

import itertools
import re
from typing import Generator

_RE_MARKERS = re.compile(r"§(\w+)§")


def _read_wordlist(path: str) -> list[str]:
    with open(path) as f:
        return [line.strip() for line in f if line.strip() and not line.startswith("#")]


def _apply_payload(template: dict, payload: dict) -> dict:
    """Replace §marker§ placeholders in template values with payload values."""
    result = {}
    for key, value in template.items():
        if isinstance(value, str):
            for marker, replacement in payload.items():
                value = value.replace(f"§{marker}§", str(replacement))
        result[key] = value
    return result


def sniper(
    wordlist_path: str,
    body_template: dict,
    defaults: dict,
) -> Generator[dict, None, None]:
    """One wordlist. For each position, cycle through all words; other positions hold defaults."""
    words = _read_wordlist(wordlist_path)
    markers = _RE_MARKERS.findall(str(body_template))

    for marker in markers:
        for word in words:
            payload = dict(defaults)
            payload[marker] = word
            yield _apply_payload(body_template, payload)


def battering_ram(
    wordlist_path: str,
    body_template: dict,
) -> Generator[dict, None, None]:
    """One wordlist. Each word is inserted into ALL positions simultaneously."""
    words = _read_wordlist(wordlist_path)
    markers = _RE_MARKERS.findall(str(body_template))

    for word in words:
        payload = {marker: word for marker in markers}
        yield _apply_payload(body_template, payload)


def pitchfork(
    wordlists: dict[str, str],
    body_template: dict,
) -> Generator[dict, None, None]:
    """Multiple wordlists, parallel iteration — wordlists[0][i] paired with wordlists[1][i]."""
    loaded = {marker: _read_wordlist(path) for marker, path in wordlists.items()}
    markers = list(loaded.keys())

    for combo in zip(*loaded.values()):
        payload = dict(zip(markers, combo))
        yield _apply_payload(body_template, payload)


def cluster_bomb(
    wordlists: dict[str, str],
    body_template: dict,
) -> Generator[dict, None, None]:
    """Multiple wordlists, cartesian product — every combination across all wordlists."""
    loaded = {marker: _read_wordlist(path) for marker, path in wordlists.items()}
    markers = list(loaded.keys())

    for combo in itertools.product(*loaded.values()):
        payload = dict(zip(markers, combo))
        yield _apply_payload(body_template, payload)
