# Copyright (C) 2026 Storj Labs, Inc.
# See LICENSE for copying information.

"""The one Metainfo call needed to create an access grant."""

from __future__ import annotations

import hashlib
import errno
import socket
import time
from datetime import UTC, datetime, timedelta
from typing import Any, cast
from urllib.parse import urlsplit

from uplink.common import drpc
from uplink.common.pb import project_info_pb2
from uplink.common.storj import NodeURL, node_id_from_bytes
from uplink.errors import SatelliteError

_HEADER = b"DRPC!!!1"
_RETRY_DELAYS = (0.1, 0.2, 0.4, 0.8, 1.6, 3.0)
_RETRY_ERRNOS = {
    errno.ECONNABORTED,
    errno.ECONNREFUSED,
    errno.ECONNRESET,
    errno.EHOSTUNREACH,
    errno.ENETUNREACH,
    errno.ETIMEDOUT,
}


def project_salt(
    node: NodeURL, api_key: bytes, user_agent: str, timeout: float
) -> bytes:
    """Fetch a project salt with Storj peer identity verification."""
    request = project_info_pb2.ProjectInfoRequest()
    request.header.api_key = api_key
    request.header.user_agent = user_agent.encode()
    try:
        response = _request(
            node,
            timeout,
            "/metainfo.Metainfo/ProjectInfo",
            cast(bytes, request.SerializeToString()),
        )
    except ConnectionError as exc:
        raise ConnectionError("could not fetch project salt") from exc

    result = project_info_pb2.ProjectInfoResponse()
    try:
        result.ParseFromString(response)
    except Exception as exc:
        raise ValueError("malformed project info response") from exc
    if not result.project_salt:
        raise ValueError("project info response is missing project salt")
    return result.project_salt


def revoke_api_key(
    node: NodeURL,
    authorizing_api_key: bytes,
    api_key_to_revoke: bytes,
    user_agent: str,
    timeout: float,
) -> None:
    request = project_info_pb2.RevokeAPIKeyRequest(api_key=api_key_to_revoke)
    request.header.api_key = authorizing_api_key
    request.header.user_agent = user_agent.encode()
    response = _request(
        node,
        timeout,
        "/metainfo.Metainfo/RevokeAPIKey",
        cast(bytes, request.SerializeToString()),
    )
    try:
        project_info_pb2.RevokeAPIKeyResponse.FromString(response)
    except Exception as exc:
        raise ValueError("malformed revoke API key response") from exc


def _request(node: NodeURL, timeout: float, rpc: str, request: bytes) -> bytes:
    for delay in (*_RETRY_DELAYS, None):
        try:
            return _request_once(node, timeout, rpc, request)
        except drpc.RemoteError as exc:
            if exc.code == 3:
                raise ValueError(str(exc)) from exc
            if exc.code == 4:
                raise TimeoutError(str(exc)) from exc
            if exc.code in (7, 16):
                raise PermissionError(str(exc)) from exc
            raise SatelliteError(str(exc)) from exc
        except OSError as exc:
            if delay is None or not _needs_retry(exc):
                raise
            time.sleep(delay)
    raise AssertionError("unreachable")


def _request_once(node: NodeURL, timeout: float, rpc: str, request: bytes) -> bytes:
    try:
        raw = socket.create_connection(_split_address(node.address), timeout=timeout)
        raw.sendall(_HEADER)
        conn = _tls_connection(raw)
        try:
            conn.set_connect_state()
            conn.do_handshake()
            _verify_peer(conn, node)
            return drpc.invoke(conn, rpc, request)
        finally:
            conn.close()
    except (ConnectionError, TimeoutError, ValueError, drpc.RemoteError):
        raise
    except Exception as exc:
        raise ConnectionError("could not communicate with satellite") from exc


def _needs_retry(exc: OSError) -> bool:
    return (
        isinstance(
            exc,
            (
                ConnectionAbortedError,
                ConnectionRefusedError,
                ConnectionResetError,
                TimeoutError,
            ),
        )
        or exc.errno in _RETRY_ERRNOS
    )


def _split_address(address: str) -> tuple[str, int]:
    try:
        parsed = urlsplit(f"//{address}")
        port = parsed.port or 7777
    except ValueError as exc:
        raise ValueError("invalid satellite address") from exc
    if (
        parsed.hostname is None
        or parsed.username is not None
        or parsed.netloc.endswith(":")
        or parsed.path
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError("invalid satellite address")
    return parsed.hostname, port


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
