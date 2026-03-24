"""Tests for client log delivery behavior."""

import logging
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

CLIENT_ROOT = Path(__file__).resolve().parents[2] / "client"
sys.modules.pop("flamix", None)
sys.path.insert(0, str(CLIENT_ROOT))

import flamix.client.client as client_module
from flamix.client.client import FlamixClient
from flamix.common.protocol_types import MessageType


class DummyProtocol:
    def __init__(self):
        self.payloads = []

    def create_message(self, message_type, payload):
        self.payloads.append((message_type, payload))
        return b"log-report"


class DummyWriter:
    def __init__(self, drain_error=None):
        self.drain_error = drain_error
        self.writes = []

    def write(self, data):
        self.writes.append(data)

    async def drain(self):
        if self.drain_error is not None:
            raise self.drain_error


def emit_business_log(message):
    app_logger = logging.getLogger("tests.log_delivery")
    app_logger.setLevel(logging.INFO)
    app_logger.info(message)


@pytest.fixture
def client():
    instance = FlamixClient(
        client_id="test-client",
        system_status_enabled=False,
        logs_enabled=True,
    )
    yield instance
    if instance._log_handler:
        logging.getLogger().removeHandler(instance._log_handler)
        instance._log_handler = None


@pytest.mark.asyncio
async def test_send_logs_retains_buffer_until_successful_retry(client):
    client.connected = True
    client.protocol = DummyProtocol()
    client.writer = DummyWriter(drain_error=BrokenPipeError("send failed"))

    emit_business_log("business log entry")
    assert len(client._log_buffer) == 1

    await client.send_logs()

    assert len(client._log_buffer) == 1
    assert client.protocol.payloads[-1][0] == MessageType.LOG_REPORT
    assert client.protocol.payloads[-1][1]["logs"][0]["message"] == "business log entry"
    assert client.connected is False

    client.connected = True
    client.writer = DummyWriter()

    await client.send_logs()

    assert len(client._log_buffer) == 0
    assert len(client.writer.writes) == 1


@pytest.mark.asyncio
async def test_send_logs_does_not_rebuffer_transport_messages(client):
    client.connected = True
    client.protocol = DummyProtocol()
    client.writer = DummyWriter()

    emit_business_log("user-visible event")

    await client.send_logs()
    await client.send_logs()

    assert len(client.protocol.payloads) == 1
    sent_logs = client.protocol.payloads[0][1]["logs"]
    assert [entry["message"] for entry in sent_logs] == ["user-visible event"]
    assert len(client._log_buffer) == 0


@pytest.mark.asyncio
async def test_connect_starts_message_handler_after_initial_delivery(monkeypatch):
    events = []
    responses = [
        SimpleNamespace(
            header=SimpleNamespace(message_type=MessageType.DH_KEY_RESPONSE),
            payload={"public_key": "01", "session_id": "session-1"},
        ),
        SimpleNamespace(
            header=SimpleNamespace(message_type=MessageType.AUTH_RESPONSE),
            payload={"success": True},
        ),
    ]

    class FakeProtocol:
        def __init__(self, session_key, session_id):
            self.session_key = session_key
            self.session_id = session_id

        def create_message(self, message_type, payload):
            return f"{message_type.name}:{payload}".encode("utf-8")

        async def read_message(self, reader):
            return responses.pop(0)

    class FakeDiffieHellman:
        def get_public_key_bytes(self):
            return b"\x02"

        def compute_shared_secret(self, server_public_key):
            return b"\x03"

        @staticmethod
        def generate_session_key(shared_secret):
            return b"\x00" * 32

    writer = DummyWriter()

    async def fake_open_connection(*args, **kwargs):
        return object(), writer

    async def fake_send_system_status(self):
        events.append("status")

    async def fake_send_logs(self):
        events.append("logs")

    def fake_start_message_handler(self):
        events.append("handler")

    def fake_start_periodic_tasks(self):
        events.append("periodic")

    monkeypatch.setattr(client_module, "ClientProtocol", FakeProtocol)
    monkeypatch.setattr(client_module, "DiffieHellman", FakeDiffieHellman)
    monkeypatch.setattr(client_module.asyncio, "open_connection", fake_open_connection)
    monkeypatch.setattr(
        client_module.ClientSecurity,
        "create_ssl_context",
        lambda self, verify_ssl=True: object(),
    )
    monkeypatch.setattr(FlamixClient, "send_system_status", fake_send_system_status)
    monkeypatch.setattr(FlamixClient, "send_logs", fake_send_logs)
    monkeypatch.setattr(FlamixClient, "start_message_handler", fake_start_message_handler)
    monkeypatch.setattr(FlamixClient, "_start_periodic_tasks", fake_start_periodic_tasks)

    client = FlamixClient(client_id="test-client")
    try:
        connected = await client.connect()
    finally:
        if client._log_handler:
            logging.getLogger().removeHandler(client._log_handler)
            client._log_handler = None

    assert connected is True
    assert client.connected is True
    assert events == ["status", "logs", "handler", "periodic"]
