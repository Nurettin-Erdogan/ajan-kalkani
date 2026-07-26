"""SQLite bağlantıları için ortak, eşzamanlı güvenli başlangıç katmanı."""

from __future__ import annotations

import sqlite3
from collections.abc import Callable
from pathlib import Path
from threading import RLock


_SETUP_LOCK = RLock()
_CONFIGURED_DATABASES: set[str] = set()
_INITIALIZED_SCHEMAS: set[tuple[str, str]] = set()


def open_sqlite(
    path: Path,
    *,
    schema: str,
    initialize: Callable[[sqlite3.Connection], None],
) -> sqlite3.Connection:
    """Bir veritabanını hazırlar ve kısa ömürlü bir bağlantı döndürür.

    Audit ve gateway aynı SQLite dosyasını kullanır. İlk istekler paralel
    geldiğinde WAL ve şema komutlarının birbirini kilitlememesi için süreç
    içindeki başlangıç işlemleri tek kilit altında yalnızca bir kez çalışır.
    SQLite'ın busy timeout'u farklı süreçlerdeki kısa yazma yarışlarını da
    beklemeye dönüştürür.
    """

    path = path.expanduser()
    path.parent.mkdir(parents=True, exist_ok=True)
    database_key = str(path.resolve())

    with _SETUP_LOCK:
        if not path.exists():
            _CONFIGURED_DATABASES.discard(database_key)
            _INITIALIZED_SCHEMAS.difference_update(
                key for key in _INITIALIZED_SCHEMAS if key[0] == database_key
            )

        connection = sqlite3.connect(path, timeout=30)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA busy_timeout=30000")
        connection.execute("PRAGMA foreign_keys=ON")

        try:
            if database_key not in _CONFIGURED_DATABASES:
                connection.execute("PRAGMA journal_mode=WAL")
                _CONFIGURED_DATABASES.add(database_key)

            schema_key = (database_key, schema)
            if schema_key not in _INITIALIZED_SCHEMAS:
                initialize(connection)
                connection.commit()
                _INITIALIZED_SCHEMAS.add(schema_key)
        except Exception:
            connection.close()
            raise

    return connection
