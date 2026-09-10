from __future__ import annotations

import hashlib
import errno
from typing import Any

import pytest

import uplink
import uplink.access as access_module
from uplink.common import base58, drpc, encryption, grant, macaroon, metainfo
from uplink.common.paths import Unencrypted
from uplink.common.storj import CipherSuite, Key, NodeURL, node_id_from_bytes


def _api_key() -> str:
    return base58.check_encode(macaroon.new_api_key(b"secret").serialize_raw(), 0)


def _satellite() -> str:
    return base58.check_encode(bytes(32), 0) + "@satellite.test:7777"


def _access() -> tuple[uplink.Access, grant.EncryptionAccess]:
    enc_access = grant.EncryptionAccess(Key.newzero())
    enc_access.default_path_cipher = CipherSuite.ENC_AESGCM
    return (
        uplink.Access(
            NodeURL.parse(_satellite()), macaroon.new_api_key(b"secret"), enc_access
        ),
        enc_access,
    )


def test_derive_root_key_matches_go_vector() -> None:
    assert bytes(
        access_module._derive_root_key("correct horse battery staple", bytes(range(16)))
    ) == bytes.fromhex(
        "a44a5100258be6fcec24cb7a3a5845f417db91038752e15fa58027190246bf18"
    )


def test_derive_encryption_key_matches_go_vector() -> None:
    key = uplink.derive_encryption_key("correct horse battery staple", bytes(range(16)))
    assert bytes(key._key) == bytes.fromhex(
        "10e3648f7704fee34dea43e60aadfaac1e52d46e1e9fe09b6137ebdef4c25b49"
    )


def test_request_access_config_and_module(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[tuple[bytes, str, float]] = []

    def salt(_node: object, api_key: bytes, agent: str, timeout: float) -> bytes:
        calls.append((api_key, agent, timeout))
        return b"salt"

    def derive(_passphrase: str, _salt: bytes) -> Key:
        return Key.newzero()

    monkeypatch.setattr(access_module.metainfo, "project_salt", salt)
    monkeypatch.setattr(access_module, "_derive_root_key", derive)
    result = uplink.Config("agent", 3.0).request_access_with_passphrase(
        _satellite(), _api_key(), ""
    )
    assert result.enc_access.default_key == Key.newzero()
    assert result.enc_access.default_path_cipher == CipherSuite.ENC_AESGCM
    assert calls[0][1:] == ("agent", 3.0)
    disabled = uplink.Config(
        disable_object_key_encryption=True
    ).request_access_with_passphrase(_satellite(), _api_key(), "")
    assert disabled.enc_access.default_key == Key.newzero()
    assert disabled.enc_access.default_path_cipher == CipherSuite.ENC_NULL
    assert uplink.request_access_with_passphrase(
        _satellite(), _api_key(), ""
    ).serialize()


def test_revoke_access_config_and_module(monkeypatch: pytest.MonkeyPatch) -> None:
    authorizer, _ = _access()
    revoked, _ = _access()
    calls: list[tuple[NodeURL, bytes, bytes, str, float]] = []

    def revoke(
        node: NodeURL,
        authorizing_key: bytes,
        revoked_key: bytes,
        agent: str,
        timeout: float,
    ) -> None:
        calls.append((node, authorizing_key, revoked_key, agent, timeout))

    monkeypatch.setattr(metainfo, "revoke_api_key", revoke)
    uplink.Config("agent", 3.0).revoke_access(authorizer, revoked)
    uplink.revoke_access(authorizer, revoked)

    assert calls[0] == (
        authorizer.satellite_url,
        authorizer.api_key.serialize_raw(),
        revoked.api_key.serialize_raw(),
        "agent",
        3.0,
    )
    assert calls[1][-2:] == ("", 20.0)


def test_override_encryption_key() -> None:
    access, enc_access = _access()
    override = Key(b"override".ljust(Key.SIZE, b"\0"))
    expected = encryption.encrypt_path_with_store_cipher(
        b"bucket", Unencrypted(b"tenant/"), enc_access.store
    )

    access.override_encryption_key(b"bucket", b"tenant//", override)

    _, _, base = enc_access.store.lookup_unencrypted(b"bucket", Unencrypted(b"tenant/"))
    assert base is not None
    assert base.unencrypted == Unencrypted(b"tenant/")
    assert base.encrypted == expected
    assert base.key == override

    derived = uplink.derive_encryption_key("tenant", b"salt")
    access.override_encryption_key(b"bucket", b"other/", derived)
    _, _, base = enc_access.store.lookup_unencrypted(b"bucket", Unencrypted(b"other"))
    assert base is not None and base.key == derived._key


def test_permission_helpers_and_deprecated_lock_mapping() -> None:
    assert uplink.read_only_permission().allow_download
    assert uplink.read_only_permission().allow_list
    assert uplink.write_only_permission().allow_upload
    assert uplink.write_only_permission().allow_delete
    full = uplink.full_permission()
    assert full.allow_bypass_governance_retention

    access, _ = _access()
    assert access.satellite_address == _satellite()
    shared = access.share(uplink.Permission(allow_lock=True))
    caveat = shared.api_key._caveats()[-1]
    assert caveat.disallow_locks
    assert not caveat.disallow_put_retention
    assert not caveat.disallow_get_retention
    assert not caveat.disallow_put_bucket_object_lock_configuration
    assert not caveat.disallow_get_bucket_object_lock_configuration


@pytest.mark.parametrize("prefix", [b"", b"tenant"])
def test_override_encryption_key_rejects_invalid_prefix(prefix: bytes) -> None:
    access, _ = _access()

    with pytest.raises(ValueError, match="prefix must end with slash"):
        access.override_encryption_key(b"bucket", prefix, Key.generate())


def test_override_encryption_key_preserves_store_on_conflict() -> None:
    access, enc_access = _access()
    encrypted = encryption.encrypt_path_with_store_cipher(
        b"bucket", Unencrypted(b"tenant"), enc_access.store
    )
    enc_access.store.add(b"bucket", Unencrypted(b"other"), encrypted, Key.generate())
    before = access.serialize()

    with pytest.raises(ValueError, match="conflicting"):
        access.override_encryption_key(b"bucket", b"tenant/", Key.generate())

    assert access.serialize() == before


def test_request_access_restricted_key_limits_encryption(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    key = macaroon.new_api_key(b"secret")
    caveat = macaroon.Caveat()
    encryption_access = grant.EncryptionAccess(Key.newzero())
    encryption_access.default_path_cipher = CipherSuite.ENC_AESGCM
    encrypted = encryption.encrypt_path_with_store_cipher(
        b"bucket", Unencrypted(b"prefix"), encryption_access.store
    )
    allowed = macaroon.CaveatPath(bucket=b"bucket", encrypted_path_prefix=encrypted.raw)
    caveat.allowed_paths.append(allowed)
    encoded = base58.check_encode(key.restrict(caveat).serialize_raw(), 0)

    def salt(_node: object, _key: bytes, _agent: str, _timeout: float) -> bytes:
        return b"salt"

    def derive(_passphrase: str, _salt: bytes) -> Key:
        return Key.newzero()

    monkeypatch.setattr(access_module.metainfo, "project_salt", salt)
    monkeypatch.setattr(access_module, "_derive_root_key", derive)
    result = uplink.request_access_with_passphrase(_satellite(), encoded, "passphrase")
    assert result.enc_access.default_key is None
    _, _, base = result.enc_access.store.lookup_encrypted(b"bucket", encrypted)
    assert base is not None and base.key != Key.newzero()
    reparsed = uplink.parse_access(result.serialize())
    assert reparsed.api_key.serialize_raw() == result.api_key.serialize_raw()


@pytest.mark.parametrize(
    "address,key", [("unknown.test", _api_key()), (_satellite(), "not-base58")]
)
def test_request_access_rejects_invalid_inputs_before_transport(
    monkeypatch: pytest.MonkeyPatch, address: str, key: str
) -> None:
    def salt(_node: object, _key: bytes, _agent: str, _timeout: float) -> bytes:
        raise AssertionError("transport called")

    monkeypatch.setattr(access_module.metainfo, "project_salt", salt)
    with pytest.raises(ValueError):
        uplink.request_access_with_passphrase(address, key, "passphrase")


def test_config_rejects_non_positive_timeout() -> None:
    with pytest.raises(ValueError):
        uplink.Config(dial_timeout=0)


def test_request_access_maps_transport_and_derivation_errors(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def transport(_node: NodeURL, _key: bytes, _agent: str, _timeout: float) -> bytes:
        raise ConnectionError("offline")

    monkeypatch.setattr(access_module.metainfo, "project_salt", transport)
    with pytest.raises(ConnectionError, match="offline"):
        uplink.request_access_with_passphrase(_satellite(), _api_key(), "passphrase")

    def salt(_node: NodeURL, _key: bytes, _agent: str, _timeout: float) -> bytes:
        return b"salt"

    def fail(_passphrase: str, _salt: bytes) -> Key:
        raise RuntimeError("argon2")

    monkeypatch.setattr(access_module.metainfo, "project_salt", salt)
    monkeypatch.setattr(access_module, "_derive_root_key", fail)
    with pytest.raises(ValueError, match="root key"):
        uplink.request_access_with_passphrase(_satellite(), _api_key(), "passphrase")


class _Connection:
    def __init__(self, data: bytes) -> None:
        self.data = bytearray(data)

    def recv(self, length: int) -> bytes:
        out = bytes(self.data[:1])
        del self.data[:1]
        return out

    def sendall(self, data: bytes) -> None:
        self.sent = data


def test_drpc_response_reassembles_and_rejects_bad_order() -> None:
    response = b"abc"
    conn = _Connection(
        drpc._frame(2, 1, 1, response[:1], False) + drpc._frame(2, 1, 1, response[1:])
    )
    assert drpc._read_response(conn) == response
    with pytest.raises(ConnectionError):
        drpc._read_response(_Connection(drpc._frame(1, 1, 0, b"bad")))


def test_drpc_request_wire_and_errors() -> None:
    conn = _Connection(drpc._frame(2, 1, 1, b""))
    request = metainfo.project_info_pb2.ProjectInfoRequest()
    request.header.api_key = b"key"
    request.header.user_agent = b"agent"
    assert (
        drpc.invoke(conn, "/metainfo.Metainfo/ProjectInfo", request.SerializeToString())
        == b""
    )
    assert conn.sent == (
        b"\x03\x01\x00\x1e/metainfo.Metainfo/ProjectInfo"
        b"\x05\x01\x01\x0e\x7a\x0c\x0a\x03key\x12\x05agent"
        b"\x0d\x01\x02\x00"
    )
    with pytest.raises(drpc.RemoteError, match="denied") as raised:
        drpc._read_response(
            _Connection(drpc._frame(3, 1, 1, (7).to_bytes(8, "big") + b"denied"))
        )
    assert raised.value.code == 7
    with pytest.raises(ConnectionError, match="frame exceeds 4 MiB"):
        drpc._read_response(
            _Connection(drpc._frame(2, 1, 1, b"x" * (4 * 1024 * 1024 + 1)))
        )
    with pytest.raises(ConnectionError, match="response exceeds 4 MiB"):
        drpc._read_response(
            _Connection(
                drpc._frame(2, 1, 1, b"x" * (3 * 1024 * 1024), False)
                + drpc._frame(2, 1, 1, b"x" * (3 * 1024 * 1024))
            )
        )


def test_revoke_api_key_wire(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: list[tuple[str, bytes]] = []

    def request(_node: NodeURL, _timeout: float, rpc: str, payload: bytes) -> bytes:
        captured.append((rpc, payload))
        return metainfo.project_info_pb2.RevokeAPIKeyResponse().SerializeToString()

    monkeypatch.setattr(metainfo, "_request", request)
    metainfo.revoke_api_key(
        NodeURL.parse(_satellite()), b"authorizer", b"revoked", "agent", 3.0
    )

    rpc, payload = captured[0]
    parsed = metainfo.project_info_pb2.RevokeAPIKeyRequest.FromString(payload)
    assert rpc == "/metainfo.Metainfo/RevokeAPIKey"
    assert parsed.header.api_key == b"authorizer"
    assert parsed.header.user_agent == b"agent"
    assert parsed.api_key == b"revoked"

    def malformed(*_args: object) -> bytes:
        return b"\xff"

    monkeypatch.setattr(metainfo, "_request", malformed)
    with pytest.raises(ValueError, match="malformed revoke"):
        metainfo.revoke_api_key(
            NodeURL.parse(_satellite()), b"authorizer", b"revoked", "agent", 3.0
        )


def test_metainfo_retries_network_errors(monkeypatch: pytest.MonkeyPatch) -> None:
    attempts = 0
    delays: list[float] = []

    def flaky(_node: NodeURL, _timeout: float, _rpc: str, _payload: bytes) -> bytes:
        nonlocal attempts
        attempts += 1
        if attempts < 3:
            raise ConnectionResetError(errno.ECONNRESET, "reset")
        return b"response"

    monkeypatch.setattr(metainfo, "_request_once", flaky)
    monkeypatch.setattr(metainfo.time, "sleep", delays.append)

    assert metainfo._request(NodeURL(), 1, "rpc", b"request") == b"response"
    assert attempts == 3
    assert delays == [0.1, 0.2]


@pytest.mark.parametrize(
    "code,error",
    [
        (3, ValueError),
        (4, TimeoutError),
        (7, PermissionError),
        (16, PermissionError),
        (13, uplink.SatelliteError),
    ],
)
def test_metainfo_maps_remote_status(
    monkeypatch: pytest.MonkeyPatch, code: int, error: type[Exception]
) -> None:
    def rejected(*_args: object) -> bytes:
        raise drpc.RemoteError("rejected", code)

    monkeypatch.setattr(metainfo, "_request_once", rejected)
    with pytest.raises(error, match="rejected"):
        metainfo._request(NodeURL(), 1, "rpc", b"request")


def test_metainfo_preserves_timeout(monkeypatch: pytest.MonkeyPatch) -> None:
    def timeout(*_args: object, **_kwargs: object) -> _Raw:
        raise TimeoutError("timed out")

    monkeypatch.setattr(metainfo.socket, "create_connection", timeout)
    with pytest.raises(TimeoutError, match="timed out"):
        metainfo._request_once(NodeURL.parse(_satellite()), 1, "rpc", b"request")


class _Raw:
    def sendall(self, _data: bytes) -> None:
        pass


class _TLS(_Connection):
    def set_connect_state(self) -> None:
        self.connected = True

    def do_handshake(self) -> None:
        pass

    def close(self) -> None:
        pass


@pytest.mark.parametrize("payload", [b"", b"\xff"])
def test_project_salt_rejects_missing_or_malformed_response(
    monkeypatch: pytest.MonkeyPatch, payload: bytes
) -> None:
    def connection(*_args: object, **_kwargs: object) -> _Raw:
        return _Raw()

    def tls(_raw: object) -> _TLS:
        return _TLS(drpc._frame(2, 1, 1, payload))

    def verify(_conn: Any, _node: NodeURL) -> None:
        pass

    monkeypatch.setattr(metainfo.socket, "create_connection", connection)
    monkeypatch.setattr(metainfo, "_tls_connection", tls)
    monkeypatch.setattr(metainfo, "_verify_peer", verify)
    node = NodeURL.parse(_satellite())
    with pytest.raises(ValueError):
        metainfo.project_salt(node, b"key", "agent", 1)


def test_project_salt_success(monkeypatch: pytest.MonkeyPatch) -> None:
    response = metainfo.project_info_pb2.ProjectInfoResponse(project_salt=b"salt")

    def request(_node: NodeURL, _timeout: float, _rpc: str, _data: bytes) -> bytes:
        return response.SerializeToString()

    monkeypatch.setattr(metainfo, "_request", request)
    assert (
        metainfo.project_salt(NodeURL.parse(_satellite()), b"key", "agent", 1)
        == b"salt"
    )


def test_project_salt_maps_socket_error(monkeypatch: pytest.MonkeyPatch) -> None:
    def fail(*_args: object, **_kwargs: object) -> _Raw:
        raise OSError("offline")

    monkeypatch.setattr(metainfo.socket, "create_connection", fail)
    with pytest.raises(ConnectionError, match="could not fetch"):
        metainfo.project_salt(NodeURL.parse(_satellite()), b"key", "agent", 1)


def test_satellite_address_supports_ipv6() -> None:
    assert metainfo._split_address("[2001:db8::1]:7777") == ("2001:db8::1", 7777)


@pytest.mark.parametrize(
    "address",
    ["host:bad", "", "user@host:7777", "host:", "host/path", "host?x", "host#x"],
)
def test_satellite_address_rejects_invalid_values(address: str) -> None:
    with pytest.raises(ValueError, match="invalid satellite address"):
        metainfo._split_address(address)


def test_tls_connection_builds_client_identity() -> None:
    raw = metainfo.socket.socket()
    with pytest.warns(DeprecationWarning):
        conn = metainfo._tls_connection(raw)
    conn.close()


def test_peer_identity_verification() -> None:
    from OpenSSL import crypto
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization

    leaf, _key, ca = metainfo._client_identity()
    root = x509.load_pem_x509_certificate(ca)
    public = root.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    identity = bytearray(hashlib.sha256(hashlib.sha256(public).digest()).digest())
    identity[-1] = 0
    node = NodeURL()
    node.id = node_id_from_bytes(bytes(identity))

    class Peer:
        def __init__(self, chain: list[object]) -> None:
            self.chain = chain

        def get_peer_cert_chain(self) -> list[object]:
            return self.chain

    good = Peer(
        [
            crypto.load_certificate(crypto.FILETYPE_PEM, leaf),
            crypto.load_certificate(crypto.FILETYPE_PEM, ca),
        ]
    )
    metainfo._verify_peer(good, node)
    node.id = node_id_from_bytes(bytes(32))
    with pytest.raises(ConnectionError, match="peer ID"):
        metainfo._verify_peer(good, node)
    broken = Peer([crypto.load_certificate(crypto.FILETYPE_PEM, leaf), good.chain[0]])
    with pytest.raises(Exception):
        metainfo._verify_peer(broken, node)

    with pytest.raises(ConnectionError, match="identity chain"):
        metainfo._verify_peer(Peer([]), node)


def test_signature_verification_dispatches_by_key_type() -> None:
    class RSAKey:
        def verify(self, *_args: object) -> None:
            self.calls = len(_args)

    class OtherKey(RSAKey):
        pass

    rsa = RSAKey()
    other = OtherKey()
    metainfo._verify_signature(rsa, b"signature", b"data", object())
    metainfo._verify_signature(other, b"signature", b"data", object())
    assert (rsa.calls, other.calls) == (4, 2)
