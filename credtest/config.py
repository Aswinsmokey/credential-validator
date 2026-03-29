from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import yaml


@dataclass
class GlobalConfig:
    concurrency: int = 50
    per_target_concurrency: int = 10
    timeout_seconds: float = 10.0
    retry_delay_seconds: int = 60
    max_retries: int = 3
    scope: list[str] = field(default_factory=list)
    verify_ssl: bool = True


@dataclass
class TargetConfig:
    name: str
    url: str
    method: str = "POST"
    content_type: str = "form"  # form | json
    body_template: dict = field(default_factory=dict)
    attack_mode: str = "cluster_bomb"
    wordlists: dict = field(default_factory=dict)   # marker -> path (pitchfork/cluster_bomb)
    wordlist: Optional[str] = None                  # single path (sniper/battering_ram)
    defaults: dict = field(default_factory=dict)    # marker -> default value (for sniper)


@dataclass
class Config:
    global_config: GlobalConfig
    targets: list[TargetConfig]


def load_config(path: str | Path) -> Config:
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"Config file not found: {path}")

    with open(path) as f:
        data = yaml.safe_load(f)

    g = data.get("global", {})
    global_cfg = GlobalConfig(
        concurrency=g.get("concurrency", 50),
        per_target_concurrency=g.get("per_target_concurrency", 10),
        timeout_seconds=g.get("timeout_seconds", 10.0),
        retry_delay_seconds=g.get("retry_delay_seconds", 60),
        max_retries=g.get("max_retries", 3),
        scope=g.get("scope", []),
        verify_ssl=g.get("verify_ssl", True),
    )

    targets = []
    for t in data.get("targets", []):
        targets.append(TargetConfig(
            name=t["name"],
            url=t["url"],
            method=t.get("method", "POST").upper(),
            content_type=t.get("content_type", "form"),
            body_template=t.get("body_template", {}),
            attack_mode=t.get("attack_mode", "cluster_bomb"),
            wordlists=t.get("wordlists", {}),
            wordlist=t.get("wordlist"),
            defaults=t.get("defaults", {}),
        ))

    return Config(global_config=global_cfg, targets=targets)


_VALID_ATTACK_MODES = {"sniper", "battering_ram", "pitchfork", "cluster_bomb"}
_VALID_CONTENT_TYPES = {"form", "json"}
_VALID_METHODS = {"GET", "POST", "PUT", "PATCH"}
_RE_MARKERS = re.compile(r"§(\w+)§")


def validate_config(config: Config) -> list[str]:
    errors: list[str] = []

    for t in config.targets:
        prefix = f"Target '{t.name}'"

        if not t.name:
            errors.append("A target is missing 'name'")
        if not t.url:
            errors.append(f"{prefix}: missing 'url'")
        if t.attack_mode not in _VALID_ATTACK_MODES:
            errors.append(f"{prefix}: invalid attack_mode '{t.attack_mode}'")
        if t.content_type not in _VALID_CONTENT_TYPES:
            errors.append(f"{prefix}: invalid content_type '{t.content_type}'")
        if t.method not in _VALID_METHODS:
            errors.append(f"{prefix}: invalid method '{t.method}'")

        if t.attack_mode in ("sniper", "battering_ram"):
            if not t.wordlist:
                errors.append(f"{prefix}: attack_mode '{t.attack_mode}' requires 'wordlist'")
            elif not Path(t.wordlist).exists():
                errors.append(f"{prefix}: wordlist not found: {t.wordlist}")
        else:
            if not t.wordlists:
                errors.append(f"{prefix}: attack_mode '{t.attack_mode}' requires 'wordlists'")
            else:
                for marker, wl_path in t.wordlists.items():
                    if not Path(wl_path).exists():
                        errors.append(f"{prefix}: wordlist for '{marker}' not found: {wl_path}")

        if t.body_template:
            markers = set(_RE_MARKERS.findall(str(t.body_template)))
            if t.attack_mode in ("pitchfork", "cluster_bomb"):
                covered = set(t.wordlists.keys()) | set(t.defaults.keys())
                missing = markers - covered
                if missing:
                    errors.append(f"{prefix}: template markers with no wordlist: {missing}")

    return errors
