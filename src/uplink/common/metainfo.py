# Copyright (C) 2026 Storj Labs, Inc.
# See LICENSE for copying information.

"""The one Metainfo call needed to create an access grant."""

from __future__ import annotations

import hashlib
import socket
from datetime import UTC, datetime, timedelta
from typing import Any, cast

from uplink.common.pb import project_info_pb2
from uplink.common.storj import NodeURL, node_id_from_bytes

_HEADER = b"DRPC!!!1"
_MAX_RESPONSE = 4 * 1024 * 1024
_INVOKE = 1
_MESSAGE = 2
_ERROR = 3
_CLOSE = 5
_CLOSE_SEND = 6


def project_salt(
    node: NodeURL, api_key: bytes, user_agent: str, timeout: float
) -> bytes:
    """Fetch a project salt with Storj peer identity verification."""
    request = project_info_pb2.ProjectInfoRequest()
    request.header.api_key = api_key
    request.header.user_agent = user_agent.encode()
    try:
        raw = socket.create_connection(_split_address(node.address), timeout=timeout)
        raw.sendall(_HEADER)
        conn = _tls_connection(raw)
        try:
            conn.set_connect_state()
            conn.do_handshake()
            _verify_peer(conn, node)
            _send_request(conn, cast(bytes, request.SerializeToString()))
            response = _read_response(conn)
        finally:
            conn.close()
    except (ConnectionError, ValueError):
        raise
    except Exception as exc:
        raise ConnectionError("could not fetch project salt") from exc

    result = project_info_pb2.ProjectInfoResponse()
    try:
        result.ParseFromString(response)
    except Exception as exc:
        raise ValueError("malformed project info response") from exc
    if not result.project_salt:
        raise ValueError("project info response is missing project salt")
    return result.project_salt


def _split_address(address: str) -> tuple[str, int]:
    host, separator, port = address.rpartition(":")
    if not separator:
        return address, 7777
    if not host or not port:
        raise ValueError("invalid satellite address")
    return host, int(port)


def _tls_connection(raw: socket.socket) -> Any:
    from OpenSSL import SSL, crypto

    cert, key, ca = _client_identity()
    context = SSL.Context(SSL.TLS_CLIENT_METHOD)
    context.set_min_proto_version(SSL.TLS1_2_VERSION)

    def accept_peer(*_args: object) -> bool:
        return True

    context.set_verify(SSL.VERIFY_PEER, accept_peer)
    context.use_certificate(crypto.load_certificate(crypto.FILETYPE_PEM, cert))
    context.use_privatekey(crypto.load_privatekey(crypto.FILETYPE_PEM, key))
    context.add_extra_chain_cert(crypto.load_certificate(crypto.FILETYPE_PEM, ca))
    return SSL.Connection(context, raw)


def _client_identity() -> tuple[bytes, bytes, bytes]:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    now = datetime.now(UTC)
    subject = x509.Name([x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Storj")])
    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(hours=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(True, False, False, False, False, True, True, False, False),
            critical=True,
        )
        .sign(ca_key, hashes.SHA256())
    )
    leaf_key = ec.generate_private_key(ec.SECP256R1())
    leaf = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca.subject)
        .public_key(leaf_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(hours=1))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH]),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )
    return (
        leaf.public_bytes(serialization.Encoding.PEM),
        leaf_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ),
        ca.public_bytes(serialization.Encoding.PEM),
    )


def _verify_peer(conn: Any, node: NodeURL) -> None:
    from cryptography.hazmat.primitives import hashes, serialization

    chain: list[Any] = cast(list[Any], conn.get_peer_cert_chain())
    if len(chain) < 2:
        raise ConnectionError("peer did not provide an identity chain")
    certs: list[Any] = [cert.to_cryptography() for cert in chain]
    for child, parent in zip(certs, certs[1:]):
        _verify_signature(
            cast(Any, parent.public_key()),
            cast(bytes, child.signature),
            cast(bytes, child.tbs_certificate_bytes),
            cast(Any, child.signature_hash_algorithm),
        )
    root: Any = certs[-1]
    _verify_signature(
        cast(Any, root.public_key()),
        cast(bytes, root.signature),
        cast(bytes, root.tbs_certificate_bytes),
        cast(Any, root.signature_hash_algorithm),
    )
    public_key: bytes = root.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    identity = bytearray(hashlib.sha256(hashlib.sha256(public_key).digest()).digest())
    identity[-1] = 0  # Storj V0 identity semantics.
    if node.id is None or str(node_id_from_bytes(bytes(identity))) != str(node.id):
        raise ConnectionError("peer ID did not match requested ID")


def _verify_signature(
    public_key: Any, signature: bytes, data: bytes, algorithm: Any
) -> None:
    from cryptography.hazmat.primitives.asymmetric import ec, padding

    name: str = public_key.__class__.__name__
    if name.startswith("RSA"):
        public_key.verify(signature, data, padding.PKCS1v15(), algorithm)
    elif name.startswith("EllipticCurve") or name == "ECPublicKey":
        public_key.verify(signature, data, ec.ECDSA(algorithm))
    else:
        public_key.verify(signature, data)


def _send_request(conn: Any, request: bytes) -> None:
    # ponytail: one call has no retry or pool; add them when a second satellite operation exists.
    conn.sendall(
        _frame(_INVOKE, 1, 0, b"/metainfo.Metainfo/ProjectInfo")
        + _frame(_MESSAGE, 1, 1, request)
        + _frame(_CLOSE_SEND, 1, 2, b"")
    )


def _read_response(conn: Any) -> bytes:
    chunks: list[bytes] = []
    size = 0
    message_started = False
    while True:
        kind, stream, message, done, data = _read_frame(conn)
        if stream != 1:
            raise ConnectionError("unexpected DRPC stream")
        if kind == _ERROR:
            raise ConnectionError(data.decode("utf-8", "replace"))
        if kind == _MESSAGE:
            if message != 1 or (not message_started and message != 1):
                raise ConnectionError("unexpected DRPC message")
            message_started = True
            size += len(data)
            if size > _MAX_RESPONSE:
                raise ConnectionError("project info response exceeds 4 MiB")
            chunks.append(data)
            if done:
                return b"".join(chunks)
            continue
        if kind in (_CLOSE, _CLOSE_SEND):
            raise ConnectionError("DRPC stream closed before project info response")
        raise ConnectionError("unexpected DRPC frame")


def _read_frame(conn: Any) -> tuple[int, int, int, bool, bytes]:
    control = _read_exact(conn, 1)[0]
    kind = (control & 0x7E) >> 1
    stream = _read_varint(conn)
    message = _read_varint(conn)
    length = _read_varint(conn)
    if length > _MAX_RESPONSE:
        raise ConnectionError("DRPC frame exceeds 4 MiB")
    return kind, stream, message, bool(control & 1), _read_exact(conn, length)


def _read_varint(conn: Any) -> int:
    value = 0
    for shift in range(0, 64, 7):
        byte = _read_exact(conn, 1)[0]
        value |= (byte & 0x7F) << shift
        if byte < 128:
            return value
    raise ConnectionError("invalid DRPC varint")


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
