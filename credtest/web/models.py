from __future__ import annotations

from typing import Optional
from pydantic import BaseModel


class TestStartRequest(BaseModel):
    attack_mode: str = "cluster_bomb"
    username_wordlist: Optional[str] = None   # path to uploaded file
    password_wordlist: Optional[str] = None
    wordlist: Optional[str] = None            # single wordlist for sniper/battering_ram
    use_default_usernames: bool = False
    use_default_passwords: bool = False


class AddTargetRequest(BaseModel):
    name: str
    url: str
    method: str = "POST"
    content_type: str = "form"
    username_field: str = "username"
    password_field: str = "password"
    attack_mode: str = "cluster_bomb"


class HoldReleaseResponse(BaseModel):
    app_id: int
    status: str


class TargetSummary(BaseModel):
    id: int
    name: str
    url: str
    status: str
    hold_reason: Optional[str] = None
    error_msg: Optional[str] = None
