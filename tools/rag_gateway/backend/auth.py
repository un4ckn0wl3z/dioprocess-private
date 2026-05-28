from __future__ import annotations

import hashlib
from dataclasses import dataclass

from fastapi import Header, HTTPException, status

from .config import KeyPolicy, get_settings


@dataclass(frozen=True)
class AuthContext:
    key_id: str
    key_hash: str
    scopes: set[str]


def _extract_key(authorization: str | None, x_api_key: str | None) -> str | None:
    if x_api_key:
        return x_api_key.strip()
    if authorization:
        token = authorization.strip()
        if token.lower().startswith("bearer "):
            return token[7:].strip()
    return None


def require_scope(required_scope: str):
    def dependency(
        authorization: str | None = Header(default=None),
        x_api_key: str | None = Header(default=None),
    ) -> AuthContext:
        settings = get_settings()
        key = _extract_key(authorization, x_api_key)
        if not key:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing API key")

        policy: KeyPolicy | None = settings.api_keys.get(key)
        if policy is None:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid API key")

        if required_scope not in policy.scopes:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Insufficient scope")

        digest = hashlib.sha256(key.encode("utf-8")).hexdigest()[:12]
        return AuthContext(key_id=policy.key_id, key_hash=digest, scopes=policy.scopes)

    return dependency
