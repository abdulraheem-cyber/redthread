from __future__ import annotations

import threading

import pytest

from labs.labshop import LabServer


@pytest.fixture(scope="session")
def lab():
    server = LabServer(port=0)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
