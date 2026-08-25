import importlib.util
from pathlib import Path
import tempfile


ENTRYPOINT = Path(__file__).parents[1] / "app.py"
SPEC = importlib.util.spec_from_file_location("vercel_entrypoint", ENTRYPOINT)
assert SPEC is not None and SPEC.loader is not None
vercel_entrypoint = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(vercel_entrypoint)


def test_vercel_entrypoint_exports_fastapi_app() -> None:
    assert vercel_entrypoint.app.title == "Ajan Kalkanı API"


def test_vercel_entrypoint_uses_writable_scratch_storage(monkeypatch) -> None:
    monkeypatch.setenv("VERCEL", "1")
    monkeypatch.delenv("AJAN_KALKANI_AUDIT_DB", raising=False)

    vercel_entrypoint.configure_serverless_storage()

    database = Path(vercel_entrypoint.os.environ["AJAN_KALKANI_AUDIT_DB"])
    assert database.parent == Path(tempfile.gettempdir())
    assert database.name == "ajan-kalkani-audit.sqlite3"


def test_vercel_entrypoint_preserves_explicit_storage(monkeypatch, tmp_path) -> None:
    configured = tmp_path / "custom.sqlite3"
    monkeypatch.setenv("VERCEL", "1")
    monkeypatch.setenv("AJAN_KALKANI_AUDIT_DB", str(configured))

    vercel_entrypoint.configure_serverless_storage()

    assert Path(vercel_entrypoint.os.environ["AJAN_KALKANI_AUDIT_DB"]) == configured
