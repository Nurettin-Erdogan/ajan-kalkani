"""Vercel entrypoint for the public, synthetic Ajan Kalkanı demo."""

from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path


PROJECT_SRC = Path(__file__).resolve().parent / "src"
if str(PROJECT_SRC) not in sys.path:
    sys.path.insert(0, str(PROJECT_SRC))


def configure_serverless_storage() -> None:
    """Use Vercel's writable scratch directory unless an explicit DB is set.

    Vercel Functions have a read-only deployment filesystem and a writable,
    ephemeral ``/tmp`` directory. The public demo only stores synthetic,
    redacted sandbox records, so scratch storage is the honest default there.
    Self-hosted installations keep the normal persistent ``data/`` default.
    """

    if os.getenv("VERCEL") and not os.getenv("AJAN_KALKANI_AUDIT_DB"):
        database = Path(tempfile.gettempdir()) / "ajan-kalkani-audit.sqlite3"
        os.environ["AJAN_KALKANI_AUDIT_DB"] = str(database)


configure_serverless_storage()

from ajan_kalkani.api import app  # noqa: E402


__all__ = ["app"]
