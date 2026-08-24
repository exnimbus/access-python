from __future__ import annotations

import json
import ssl
import urllib.request
from datetime import UTC, datetime
from typing import Any, cast

import pytest

from uplink import Access, edge
from uplink.common import drpc
from uplink.common.pb import edgeauth_pb2
from uplink.edge import access as edge_access


class _Access:
    def serialize(self) -> str:
        return "serialized-access"


class _Connection:
    def __init__(self, data: bytes) -> None:
        self.data = bytearray(data)
        self.sent = b""
        self.closed = False

    def recv(self, length: int) -> bytes:
        result = bytes(self.data[:length])
        del self.data[:length]
        return result

    def sendall(self, data: bytes) -> None:
        self.sent += data

    def close(self) -> None:
        self.closed = True


def _access() -> Access:
    return cast(Access, _Access())


def _response(expiration: datetime | None = None) -> bytes:
    response = edgeauth_pb2.EdgeRegisterAccessResponse(
        access_key_id="access-key",
        secret_key="secret-key",
        endpoint="https://gateway.test",
    )
    if expiration is not None:
        response.free_tier_restricted_expiration.FromDatetime(expiration)
    return drpc._frame(2, 1, 1, response.SerializeToString())


def test_insecure_drpc_registration_wire_and_expiration(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    expiration = datetime(2026, 1, 2, 3, 4, 5, tzinfo=UTC)
    conn = _Connection(_response(expiration))
    dialed: list[tuple[tuple[str, int], float]] = []

    def connect(address: tuple[str, int], timeout: float) -> Any:
        dialed.append((address, timeout))
        return conn

    monkeypatch.setattr(edge_access.socket, "create_connection", connect)
    credentials = edge.Config("insecure://auth.test:7777", timeout=3).register_access(
        _access(), edge.RegisterAccessOptions(public=True)
    )

    request = edgeauth_pb2.EdgeRegisterAccessRequest(
        access_grant="serialized-access", public=True
    ).SerializeToString()
    assert conn.sent == (
        drpc._frame(1, 1, 0, b"/EdgeAuth/RegisterAccess")
        + drpc._frame(2, 1, 1, request)
        + drpc._frame(6, 1, 2, b"")
    )
    assert dialed == [(("auth.test", 7777), 3)]
    assert conn.closed
    assert credentials.access_key_id == "access-key"
    assert credentials.secret_key == "secret-key"
    assert credentials.endpoint == "https://gateway.test"
    assert credentials.free_tier_restricted_expiration == expiration


def test_tls_drpc_uses_hostname_and_pem_text(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    conn = _Connection(_response())
    seen: dict[str, object] = {}

    class Context:
        def wrap_socket(self, raw: Any, server_hostname: str) -> Any:
            seen["raw"] = raw
            seen["hostname"] = server_hostname
            return raw

    def context(*, cadata: str | None = None) -> Any:
        seen["cadata"] = cadata
        return Context()

    def connect(*_args: object, **_kwargs: object) -> Any:
        return conn

    monkeypatch.setattr(edge_access.socket, "create_connection", connect)
    monkeypatch.setattr(edge_access.ssl, "create_default_context", context)

    edge.Config("auth.test:443", certificate_pem=b"PEM").register_access(_access())

    assert seen == {"cadata": "PEM", "raw": conn, "hostname": "auth.test"}


def test_legacy_http_registration_and_timeout(monkeypatch: pytest.MonkeyPatch) -> None:
    expiration = "2026-01-02T03:04:05Z"
    seen: dict[str, object] = {}

    class Response:
        def __enter__(self) -> Response:
            return self

        def __exit__(self, *_args: object) -> None:
            pass

        def read(self) -> bytes:
            return json.dumps(
                {
                    "access_key_id": "access-key",
                    "secret_key": "secret-key",
                    "endpoint": "https://gateway.test",
                    "freeTierRestrictedExpiration": expiration,
                }
            ).encode()

    def urlopen(
        request: urllib.request.Request, *, context: object, timeout: float
    ) -> Any:
        seen.update(url=request.full_url, data=request.data, timeout=timeout)
        return Response()

    monkeypatch.setattr(edge_access.urllib.request, "urlopen", urlopen)
    credentials = edge.Config("http://auth.test/", timeout=4).register_access(
        _access(), edge.RegisterAccessOptions(public=True)
    )

    assert seen == {
        "url": "http://auth.test/v1/access",
        "data": b'{"access_grant": "serialized-access", "public": true}',
        "timeout": 4,
    }
    assert credentials.free_tier_restricted_expiration == datetime(
        2026, 1, 2, 3, 4, 5, tzinfo=UTC
    )


def test_registration_errors_are_distinct(monkeypatch: pytest.MonkeyPatch) -> None:
    with pytest.raises(ValueError, match="positive"):
        edge.Config("auth.test:443", timeout=0)

    def denied(*_args: object, **_kwargs: object) -> Any:
        return _Connection(drpc._frame(3, 1, 1, b"denied"))

    monkeypatch.setattr(edge_access.socket, "create_connection", denied)
    with pytest.raises(edge.AuthServiceError, match="denied"):
        edge.Config("insecure://auth.test:7777").register_access(_access())

    def malformed(*_args: object, **_kwargs: object) -> Any:
        return _Connection(drpc._frame(2, 1, 1, b"\xff"))

    monkeypatch.setattr(edge_access.socket, "create_connection", malformed)
    with pytest.raises(ValueError, match="malformed"):
        edge.Config("insecure://auth.test:7777").register_access(_access())

    def timed_out(*_args: object, **_kwargs: object) -> Any:
        raise TimeoutError("slow")

    monkeypatch.setattr(edge_access.socket, "create_connection", timed_out)
    with pytest.raises(TimeoutError, match="timed out"):
        edge.Config("auth.test:443").register_access(_access())

    def refused(*_args: object, **_kwargs: object) -> Any:
        raise ConnectionRefusedError("offline")

    monkeypatch.setattr(edge_access.socket, "create_connection", refused)
    with pytest.raises(ConnectionError, match="communicate"):
        edge.Config("auth.test:443").register_access(_access())

    conn = _Connection(_response())

    def connect(*_args: object, **_kwargs: object) -> Any:
        return conn

    monkeypatch.setattr(edge_access.socket, "create_connection", connect)

    class BadCertificate:
        def wrap_socket(self, *_args: object, **_kwargs: object) -> Any:
            raise ssl.SSLCertVerificationError("untrusted")

    def bad_certificate(**_kwargs: object) -> Any:
        return BadCertificate()

    monkeypatch.setattr(edge_access.ssl, "create_default_context", bad_certificate)
    with pytest.raises(ssl.SSLCertVerificationError, match="untrusted"):
        edge.Config("auth.test:443").register_access(_access())
