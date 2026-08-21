from __future__ import annotations

import shutil
import subprocess
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

import pytest

from uplink.common import base58, encryption, macaroon, paths
from uplink.common.grant import Access, EncryptionAccess, Permission, SharePrefix
from uplink.common.pb import encryption_access_pb2, scope_pb2
from uplink.common.storj import CipherSuite, Key

HERE = Path(__file__).parent
SATELLITE = "satellite.example.test:7777"
HEAD = bytes(range(32))
SECRET = bytes(range(32, 64))
DEFAULT_KEY = Key(bytes(range(64, 96)))
NONCE = bytes.fromhex("01020304")
NOT_BEFORE = datetime(2025, 1, 2, 3, 4, 5, tzinfo=timezone.utc)
NOT_AFTER = datetime(2025, 1, 2, 5, 4, 5, tzinfo=timezone.utc)
TTL = timedelta(minutes=90)
PREFIXES = ((b"bucket-alpha", b"photos/2024"), (b"bucket-beta", b"docs"))
GO_ENCRYPTED_PATHS = (
    bytes.fromhex(
        "023f0edbc905d3955e0ba4fb91950907b6dedef3a01bdff582a2a7d49d941fdd"
        "f4876a2f02ddf1d15bb5c87e97b0b5eaad68696657439520ad2b66dfbf3776ea"
        "050101667e9d"
    ),
    bytes.fromhex("02fb77ee96f357d93599f523cbf9d43b4f3eb5e397863676e0d62d1e20a925cfeb"),
)


def _unrestricted() -> Access:
    api_key = macaroon.APIKey(macaroon.new_unrestricted_from_parts(HEAD, SECRET))
    enc_access = EncryptionAccess(DEFAULT_KEY)
    enc_access.default_path_cipher = CipherSuite.ENC_AESGCM
    return Access(SATELLITE, api_key, enc_access)


def _restricted(access: Access) -> Access:
    permission = Permission(
        allow_download=True,
        allow_list=True,
        allow_put_object_retention=True,
        allow_get_object_legal_hold=True,
        allow_bypass_governance_retention=True,
        allow_get_bucket_object_lock_configuration=True,
        allow_get_bucket_notification_configuration=True,
        not_before=NOT_BEFORE,
        not_after=NOT_AFTER,
        max_object_ttl=TTL,
    )

    def fixed_nonce(caveat: macaroon.Caveat) -> macaroon.Caveat:
        caveat.nonce = NONCE
        return caveat

    with patch.object(macaroon, "caveat_with_nonce", fixed_nonce):
        return access.restrict(
            permission,
            [SharePrefix(bucket, prefix) for bucket, prefix in PREFIXES],
        )


def _fixtures() -> dict[str, str]:
    unrestricted = _unrestricted()
    return {
        "unrestricted": unrestricted.serialize(),
        "restricted": _canonical(_restricted(unrestricted).serialize()),
    }


def _read_fixture(name: str) -> dict[str, str]:
    lines = (HERE / "fixtures" / name).read_text().splitlines()
    assert len(lines) == 2
    values: dict[str, str] = {}
    for expected, line in zip(("unrestricted", "restricted"), lines, strict=True):
        key, separator, value = line.partition("=")
        assert (key, separator, bool(value)) == (expected, "=", True)
        values[key] = value
    return values


def _write_fixture(name: str, values: dict[str, str]) -> None:
    (HERE / "fixtures" / name).write_text(
        "".join(f"{key}={values[key]}\n" for key in ("unrestricted", "restricted"))
    )


def _canonical(encoded: str) -> str:
    data, version = base58.check_decode(encoded)
    assert version == 0
    scope = scope_pb2.Scope()
    scope.ParseFromString(data)

    def entry_key(
        entry: encryption_access_pb2.EncryptionAccess.StoreEntry,
    ) -> tuple[bytes, bytes, bytes]:
        return entry.bucket, entry.unencrypted_path, entry.encrypted_path

    entries = sorted(
        scope.encryption_access.store_entries,
        key=entry_key,
    )
    del scope.encryption_access.store_entries[:]
    scope.encryption_access.store_entries.extend(entries)
    return base58.check_encode(scope.SerializeToString(), 0)


def _expected_entries() -> list[tuple[bytes, bytes, bytes, bytes, CipherSuite]]:
    store = _unrestricted().enc_access.store
    result: list[tuple[bytes, bytes, bytes, bytes, CipherSuite]] = []
    for (bucket, raw_path), encrypted in zip(PREFIXES, GO_ENCRYPTED_PATHS, strict=True):
        path = paths.Unencrypted(raw_path)
        key = encryption.derive_path_key(bucket, path, store)
        result.append((bucket, raw_path, encrypted, bytes(key), CipherSuite.ENC_AESGCM))
    return sorted(result)


def _store_entries(
    access: Access,
) -> list[tuple[bytes, bytes, bytes, bytes, CipherSuite]]:
    result: list[tuple[bytes, bytes, bytes, bytes, CipherSuite]] = []

    def append(
        bucket: bytes,
        unencrypted: paths.Unencrypted,
        encrypted: paths.Encrypted,
        key: Key,
        cipher: CipherSuite,
    ) -> None:
        result.append((bucket, unencrypted.raw, encrypted.raw, bytes(key), cipher))

    access.enc_access.store.iterate_with_cipher(append)
    return sorted(result)


def _assert_common(access: Access) -> None:
    assert access.satellite_address == SATELLITE
    assert access.api_key.mac.head == HEAD
    assert access.api_key.mac.validate_and_tails(SECRET)[0]
    assert access.enc_access.default_path_cipher == CipherSuite.ENC_AESGCM


def test_go_fixtures() -> None:
    values = _read_fixture("go.txt")

    unrestricted = Access.parse(values["unrestricted"])
    _assert_common(unrestricted)
    assert unrestricted.api_key.mac.caveats == []
    assert unrestricted.enc_access.default_key == DEFAULT_KEY
    assert _store_entries(unrestricted) == []
    assert unrestricted.serialize() == values["unrestricted"]

    restricted = Access.parse(values["restricted"])
    _assert_common(restricted)
    assert restricted.enc_access.default_key is None
    assert _store_entries(restricted) == _expected_entries()
    assert _canonical(restricted.serialize()) == _canonical(values["restricted"])

    assert len(restricted.api_key.mac.caveats) == 1
    caveat = macaroon.Caveat()
    caveat.ParseFromString(restricted.api_key.mac.caveats[0])
    assert not caveat.disallow_reads
    assert caveat.disallow_writes
    assert not caveat.disallow_lists
    assert caveat.disallow_deletes
    assert caveat.disallow_locks
    assert not caveat.disallow_put_retention
    assert caveat.disallow_get_retention
    assert caveat.disallow_put_legal_hold
    assert not caveat.disallow_get_legal_hold
    assert not caveat.disallow_bypass_governance_retention
    assert caveat.disallow_put_bucket_object_lock_configuration
    assert not caveat.disallow_get_bucket_object_lock_configuration
    assert caveat.disallow_put_bucket_notification_configuration
    assert not caveat.disallow_get_bucket_notification_configuration
    assert caveat.not_before.ToDatetime(tzinfo=timezone.utc) == NOT_BEFORE
    assert caveat.not_after.ToDatetime(tzinfo=timezone.utc) == NOT_AFTER
    assert caveat.max_object_ttl.ToTimedelta() == TTL
    assert caveat.nonce == NONCE
    assert [
        (path.bucket, path.encrypted_path_prefix) for path in caveat.allowed_paths
    ] == [(bucket, encrypted) for bucket, _, encrypted, _, _ in _expected_entries()]


@pytest.mark.skipif(shutil.which("go") is None, reason="Go is not installed")
def test_go_verifies_python_fixtures() -> None:
    subprocess.run(["go", "run", ".", "verify"], cwd=HERE, check=True)


if __name__ == "__main__":
    _write_fixture("python.txt", _fixtures())
    subprocess.run(["go", "run", ".", "generate"], cwd=HERE, check=True)
