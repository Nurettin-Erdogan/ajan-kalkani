"""Olay izleri ve onay önizlemeleri için ortak redaksiyon kuralları."""

from __future__ import annotations

import re
from typing import Any


_SECRET_VALUE = re.compile(r"(?i)(sk-[a-z0-9._-]{8,}|bearer\s+[a-z0-9._-]{8,})")
_SENSITIVE_KEYS = {
    "api_key",
    "authorization",
    "content",
    "credential",
    "password",
    "payload",
    "secret",
    "token",
}


def redact(
    value: Any,
    key: str | None = None,
    *,
    force_sensitive: bool = False,
) -> Any:
    """Hassas anahtar adlarını, bilinen sır biçimlerini ve gerekirse tüm skalerleri maskeler.

    `force_sensitive`, çağrının provenance etiketleri hassas olduğunda kullanılır:
    değerin biçimi ne olursa olsun bütün skaler değerler `[REDACTED]` olur.
    """
    if key and any(marker in key.lower() for marker in _SENSITIVE_KEYS):
        return "[REDACTED]"
    if isinstance(value, dict):
        return {
            str(item_key): redact(
                item_value,
                str(item_key),
                force_sensitive=force_sensitive,
            )
            for item_key, item_value in value.items()
        }
    if isinstance(value, (list, tuple)):
        return [redact(item, force_sensitive=force_sensitive) for item in value]
    if force_sensitive:
        return "[REDACTED]"
    if isinstance(value, str):
        return _SECRET_VALUE.sub("[REDACTED]", value)
    return value
