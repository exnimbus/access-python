# Copyright (C) 2026 Storj Labs, Inc.
# See LICENSE for copying information.

"""The minimal dRPC unary framing shared by metainfo and Edge Auth."""

from typing import Any

_MAX_RESPONSE = 4 * 1024 * 1024
_INVOKE = 1
_MESSAGE = 2
_ERROR = 3
_CLOSE = 5
_CLOSE_SEND = 6


class RemoteError(ConnectionError):
    """An error returned by the remote dRPC service."""


def invoke(conn: Any, rpc: str, request: bytes) -> bytes:
    conn.sendall(
        _frame(_INVOKE, 1, 0, rpc.encode())
        + _frame(_MESSAGE, 1, 1, request)
        + _frame(_CLOSE_SEND, 1, 2, b"")
    )
    return _read_response(conn)


def _read_response(conn: Any) -> bytes:
    chunks: list[bytes] = []
    size = 0
    while True:
        kind, stream, message, done, data = _read_frame(conn)
        if stream != 1:
            raise ConnectionError("unexpected dRPC stream")
        if kind == _ERROR:
            raise RemoteError(data.decode("utf-8", "replace"))
        if kind == _MESSAGE:
            if message != 1:
                raise ConnectionError("unexpected dRPC message")
            size += len(data)
            if size > _MAX_RESPONSE:
                raise ConnectionError("dRPC response exceeds 4 MiB")
            chunks.append(data)
            if done:
                return b"".join(chunks)
            continue
        if kind in (_CLOSE, _CLOSE_SEND):
            raise ConnectionError("dRPC stream closed before response")
        raise ConnectionError("unexpected dRPC frame")


def _read_frame(conn: Any) -> tuple[int, int, int, bool, bytes]:
    control = _read_exact(conn, 1)[0]
    kind = (control & 0x7E) >> 1
    stream = _read_varint(conn)
    message = _read_varint(conn)
    length = _read_varint(conn)
    if length > _MAX_RESPONSE:
        raise ConnectionError("dRPC frame exceeds 4 MiB")
    return kind, stream, message, bool(control & 1), _read_exact(conn, length)


def _read_varint(conn: Any) -> int:
    value = 0
    for shift in range(0, 64, 7):
        byte = _read_exact(conn, 1)[0]
        value |= (byte & 0x7F) << shift
        if byte < 128:
            return value
    raise ConnectionError("invalid dRPC varint")


def _read_exact(conn: Any, length: int) -> bytes:
    data = bytearray()
    while len(data) < length:
        chunk: bytes = conn.recv(length - len(data))
        if not chunk:
            raise ConnectionError("unexpected EOF")
        data.extend(chunk)
    return bytes(data)


def _frame(
    kind: int, stream: int, message: int, data: bytes, done: bool = True
) -> bytes:
    control = kind << 1 | int(done)
    return (
        bytes([control])
        + _varint(stream)
        + _varint(message)
        + _varint(len(data))
        + data
    )


def _varint(value: int) -> bytes:
    data = bytearray()
    while value >= 128:
        data.append(value & 0x7F | 0x80)
        value >>= 7
    data.append(value)
    return bytes(data)
