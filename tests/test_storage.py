from concurrent.futures import ThreadPoolExecutor
from threading import Barrier

from ajan_kalkani.audit import AuditStore
from ajan_kalkani.gateway import GatewayStore


def test_audit_and_gateway_initialize_shared_database_concurrently(tmp_path) -> None:
    database = tmp_path / "shared.sqlite3"
    worker_count = 12
    barrier = Barrier(worker_count)

    def read_store(index: int) -> list[object]:
        barrier.wait()
        if index % 2:
            return AuditStore(database).list_runs()
        return GatewayStore(database).list_sessions()

    with ThreadPoolExecutor(max_workers=worker_count) as executor:
        results = list(executor.map(read_store, range(worker_count)))

    assert results == [[] for _ in range(worker_count)]
    assert AuditStore(database).verify_integrity()["valid"] is True
