# Copyright (C) 2023 Storj Labs, Inc.
# See LICENSE for copying information.

import pytest
from copy import copy
from datetime import datetime, timedelta
from uplink.common import macaroon, storj
from uplink.common.grant import (
    Access,
    EncryptionAccess,
    Permission,
    SharePrefix,
)
from uplink.common.macaroon import Action, ActionType, UnauthorizedError
from uplink.common.storj import CipherSuite, Key
from uplink.common.encryption import Store
from uplink.common.encryption.store import Base
from uplink.common import paths

ep = paths.Encrypted
up = paths.Unencrypted


PATH_CIPHERS = [
    CipherSuite.ENC_NULL,
    CipherSuite.ENC_AESGCM,
    CipherSuite.ENC_SECRETBOX,
]


def test_example_store() -> None:
    s = Store(default_path_cipher=CipherSuite.ENC_AESGCM)

    # Add a fairly complicated tree to the store.
    s.add(b"b1", up(b"u1/u2/u3"), ep(b"e1/e2/e3"), make_key("k3"))
    s.add(b"b1", up(b"u1/u2/u3/u4"), ep(b"e1/e2/e3/e4"), make_key("k4"))
    s.add(b"b1", up(b"u1/u5"), ep(b"e1/e5"), make_key("k5"))
    s.add(b"b1", up(b"u6"), ep(b"e6"), make_key("k6"))
    s.add(b"b1", up(b"u6/u7/u8"), ep(b"e6/e7/e8"), make_key("k8"))
    s.add(b"b2", up(b"u1"), ep(b"e1'"), make_key("k1"))
    s.add(b"b3", up(), ep(), make_key("m1"))

    # Look up some complicated queries by the unencrypted path.
    assert (
        render_lookup(*s.lookup_unencrypted(b"b1", up(b"u1")))
        == "<{b'e2': b'u2', b'e5': b'u5'}, [], nil>"
    )
    assert (
        render_lookup(*s.lookup_unencrypted(b"b1", up(b"u1/u2/u3")))
        == "<{b'e4': b'u4'}, [], <'u1/u2/u3', 'e1/e2/e3', b'k3', False>>"
    )
    assert (
        render_lookup(*s.lookup_unencrypted(b"b1", up(b"u1/u2/u3/u6")))
        == "<{}, [b'u6'], <'u1/u2/u3', 'e1/e2/e3', b'k3', False>>"
    )
    assert (
        render_lookup(*s.lookup_unencrypted(b"b1", up(b"u1/u2/u3/u4")))
        == "<{}, [], <'u1/u2/u3/u4', 'e1/e2/e3/e4', b'k4', False>>"
    )
    assert (
        render_lookup(*s.lookup_unencrypted(b"b1", up(b"u6/u7")))
        == "<{b'e8': b'u8'}, [b'u7'], <'u6', 'e6', b'k6', False>>"
    )
    assert (
        render_lookup(*s.lookup_unencrypted(b"b2", up(b"u1")))
        == "<{}, [], <'u1', 'e1'', b'k1', False>>"
    )
    assert (
        render_lookup(*s.lookup_unencrypted(b"b3", up()))
        == "<{}, [], <'', '', b'm1', False>>"
    )
    assert (
        render_lookup(*s.lookup_unencrypted(b"b3", up(b"z1")))
        == "<{}, [b'z1'], <'', '', b'm1', False>>"
    )

    # Look up some complicated queries by the encrypted path.

    assert (
        render_lookup(*s.lookup_encrypted(b"b1", ep(b"e1")))
        == "<{b'u2': b'e2', b'u5': b'e5'}, [], nil>"
    )
    assert (
        render_lookup(*s.lookup_encrypted(b"b1", ep(b"e1/e2/e3")))
        == "<{b'u4': b'e4'}, [], <'u1/u2/u3', 'e1/e2/e3', b'k3', False>>"
    )
    assert (
        render_lookup(*s.lookup_encrypted(b"b1", ep(b"e1/e2/e3/e6")))
        == "<{}, [b'e6'], <'u1/u2/u3', 'e1/e2/e3', b'k3', False>>"
    )
    assert (
        render_lookup(*s.lookup_encrypted(b"b1", ep(b"e1/e2/e3/e4")))
        == "<{}, [], <'u1/u2/u3/u4', 'e1/e2/e3/e4', b'k4', False>>"
    )
    assert (
        render_lookup(*s.lookup_encrypted(b"b1", ep(b"e6/e7")))
        == "<{b'u8': b'e8'}, [b'e7'], <'u6', 'e6', b'k6', False>>"
    )
    assert (
        render_lookup(*s.lookup_encrypted(b"b2", ep(b"e1'")))
        == "<{}, [], <'u1', 'e1'', b'k1', False>>"
    )
    assert (
        render_lookup(*s.lookup_encrypted(b"b3", ep()))
        == "<{}, [], <'', '', b'm1', False>>"
    )
    assert (
        render_lookup(*s.lookup_encrypted(b"b3", ep(b"z1")))
        == "<{}, [b'z1'], <'', '', b'm1', False>>"
    )


def test_example_set_default_key() -> None:
    dk = make_key("dk")
    s = Store(default_path_cipher=CipherSuite.ENC_AESGCM, default_key=dk)

    s.add(b"b1", up(b"u1/u2/u3"), ep(b"e1/e2/e3"), make_key("k3"))

    assert (
        render_lookup(*s.lookup_unencrypted(b"b1", up(b"u1")))
        == "<{}, [b'u1'], <'', '', b'dk', True>>"
    )
    assert (
        render_lookup(*s.lookup_unencrypted(b"b1", up(b"u1/u2")))
        == "<{}, [b'u1', b'u2'], <'', '', b'dk', True>>"
    )
    assert (
        render_lookup(*s.lookup_unencrypted(b"b1", up(b"u1/u2/u3")))
        == "<{}, [], <'u1/u2/u3', 'e1/e2/e3', b'k3', False>>"
    )
    assert (
        render_lookup(*s.lookup_unencrypted(b"b1", up(b"u1/u2/u3/u4")))
        == "<{}, [b'u4'], <'u1/u2/u3', 'e1/e2/e3', b'k3', False>>"
    )

    assert (
        render_lookup(*s.lookup_encrypted(b"b1", ep(b"e1")))
        == "<{}, [b'e1'], <'', '', b'dk', True>>"
    )
    assert (
        render_lookup(*s.lookup_encrypted(b"b1", ep(b"e1/e2")))
        == "<{}, [b'e1', b'e2'], <'', '', b'dk', True>>"
    )
    assert (
        render_lookup(*s.lookup_encrypted(b"b1", ep(b"e1/e2/e3")))
        == "<{}, [], <'u1/u2/u3', 'e1/e2/e3', b'k3', False>>"
    )
    assert (
        render_lookup(*s.lookup_encrypted(b"b1", ep(b"e1/e2/e3/e4")))
        == "<{}, [b'e4'], <'u1/u2/u3', 'e1/e2/e3', b'k3', False>>"
    )


def test_store_errors() -> None:
    key = Key.newzero()
    for path_cipher in PATH_CIPHERS:
        s = Store()

        # Too many encrypted parts
        with pytest.raises(ValueError):
            s.add_with_cipher(b"b1", up(b"u1"), ep(b"e1/e2/e3"), key, path_cipher)

        # Too many unencrypted parts
        with pytest.raises(ValueError):
            s.add_with_cipher(b"b1", up(b"u1/u2/u3"), ep(b"e1"), key, path_cipher)

        # Mismatches
        s.add_with_cipher(b"b1", up(b"u1"), ep(b"e1"), key, path_cipher)

        with pytest.raises(ValueError):
            s.add_with_cipher(b"b1", up(b"u2"), ep(b"e1"), key, path_cipher)
        with pytest.raises(ValueError):
            s.add_with_cipher(b"b1", up(b"u1"), ep(b"f1"), key, path_cipher)


def test_store_error_state() -> None:
    s = Store()

    # Do an empty lookup.
    revealed1, consumed1, base1 = s.lookup_unencrypted(b"b1", up(b"u1/u2"))

    # Attempt to do an addition that fails.
    for path_cipher in PATH_CIPHERS:
        with pytest.raises(ValueError):
            s.add_with_cipher(
                b"b1", up(b"u1/u2"), ep(b"e1/e2/e3"), Key.newzero(), path_cipher
            )

    # Ensure that we get the same results as before
    revealed2, consumed2, base2 = s.lookup_unencrypted(b"b1", up(b"u1/u2"))

    assert revealed1 == revealed2
    assert consume_iter(consumed1) == consume_iter(consumed2)
    assert base1 == base2


def test_store_iterate() -> None:
    for path_cipher in PATH_CIPHERS:
        for bypass in [False, True]:
            s = Store(encryption_bypass=bypass)

            expected: list[
                tuple[bytes, paths.Unencrypted, paths.Encrypted, Key, CipherSuite]
            ] = [
                (b"b1", up(b"u1/u2/u3"), ep(b"e1/e2/e3"), make_key("k3"), path_cipher),
                (
                    b"b1",
                    up(b"u1/u2/u3/u4"),
                    ep(b"e1/e2/e3/e4"),
                    make_key("k4"),
                    path_cipher,
                ),
                (b"b1", up(b"u1/u5"), ep(b"e1/e5"), make_key("k5"), path_cipher),
                (b"b1", up(b"u6"), ep(b"e6"), make_key("k6"), path_cipher),
                (b"b1", up(b"u6/u7/u8"), ep(b"e6/e7/e8"), make_key("k8"), path_cipher),
                (b"b2", up(b"u1"), ep(b"e1'"), make_key("k1"), path_cipher),
                (b"b3", up(), ep(), make_key("m1"), path_cipher),
            ]

            for entry in expected:
                s.add_with_cipher(entry[0], entry[1], entry[2], entry[3], entry[4])

            got: list[
                tuple[bytes, paths.Unencrypted, paths.Encrypted, Key, CipherSuite]
            ] = []

            def append_result(
                bucket: bytes,
                unenc: paths.Unencrypted,
                enc: paths.Encrypted,
                key: Key,
                path_cipher: CipherSuite,
            ) -> None:
                got.append((bucket, unenc, enc, key, path_cipher))

            s.iterate_with_cipher(append_result)
            assert expected == got


def test_store_encryption_bypass() -> None:
    s = Store(default_key=make_key(), default_path_cipher=CipherSuite.ENC_AESGCM)

    _, _, base = s.lookup_unencrypted(b"bucket", paths.Unencrypted())
    assert base is not None and base.path_cipher == CipherSuite.ENC_AESGCM

    s.encryption_bypass = True

    _, _, base = s.lookup_unencrypted(b"bucket", paths.Unencrypted())
    assert base is not None and base.path_cipher == CipherSuite.ENC_NULL_BASE64URL


@pytest.mark.skip
def test_store_clone() -> None:
    # clone is not implemented yet
    pass


def make_key(s: str = "") -> Key:
    data = bytearray(s.encode())
    data.extend(b"\x00" * (Key.SIZE - len(s)))
    return Key(data=bytes(data))


def consume_iter(iter: paths.Iterator) -> str:
    parts: list[bytes] = []
    while not iter.done:
        parts.append(iter.next())
    return f"{parts}"


def render_lookup(
    revealed: dict[bytes, bytes], remaining: paths.Iterator, base: Base | None
) -> str:
    if base is None:
        return f"<{revealed}, {consume_iter(remaining)}, nil>"
    return f"<{revealed}, {consume_iter(remaining)}, <'{base.unencrypted}', '{base.encrypted}', {bytes(base.key)[:2]!r}, {base.default}>>"
