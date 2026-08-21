# Copyright (C) 2023 Storj Labs, Inc.
# See LICENSE for copying information.

import pytest
from uplink.common import encryption, macaroon
from uplink.common.macaroon import new_api_key
from uplink.common.grant import EncryptionAccess
from uplink.common.storj import CipherSuite, Key
from uplink.common.paths import Encrypted, Unencrypted
from typing import List


# these strings can be of the form <bucket>|<path> or just <path> where the
# bucket will be implied to be the string "bucket".
@pytest.mark.parametrize(
    "groups,valid,invalid",
    [
        (  # no limit means any path is valid
            [],
            ["a", "b", "c", "a/a", "b/b", "c/c"],  # valid
            [],
        ),
        (  # limited to a
            [["a"]],
            ["a", "a/b", "a/b/c"],
            ["b", "b/a", "c/a"],
        ),
        (  # multiple layers
            [
                ["a", "f"],
                ["c", "a/b", "f/e"],
                ["a/b/c", "c", "f"],
            ],
            ["a/b/c", "a/b/c/d", "f/e", "f/e/e"],
            ["a", "a/b", "f", "c", "c/d"],
        ),
        (  # check distinct buckets
            [
                ["bucket1|", "bucket2|", "bucket3|"],
                ["bucket2|", "bucket3|", "bucket4|"],
            ],
            ["bucket2|anything/here", "bucket3|", "bucket3|whatever"],
            ["bucket1|", "bucket1|path/ignored", "bucket4|huh", "bucket5|"],
        ),
        (  # check buckets with paths
            [
                ["b1|p1", "b1|p2", "b2|p3", "b2|p4"],
                ["b1|p1", "b1|p2", "b2|p3"],
            ],
            ["b1|p1", "b1|p1/whatever", "b1|p2", "b2|p3/foo"],
            ["b3|", "b2|p4", "b1|p3"],
        ),
    ],
)
def test_limit_to(groups, valid, invalid):
    def split(prefix: str):
        idx = prefix.find("|")
        if idx >= 0:
            return prefix[:idx].encode(), prefix[idx + 1 :].encode()
        return b"bucket", prefix.encode()

    def to_caveat(group: List[str]):
        caveat = macaroon.Caveat()
        for prefix in group:
            bucket, path = split(prefix)
            allowed_path = macaroon.CaveatPath()
            allowed_path.bucket = bucket
            allowed_path.encrypted_path_prefix = path
            caveat.allowed_paths.append(allowed_path)
        return caveat

    api_key = macaroon.new_api_key(bytes())

    for group in groups:
        api_key = api_key.restrict(to_caveat(group))

    enc_access = EncryptionAccess(Key.newzero())
    enc_access.default_path_cipher = CipherSuite.ENC_NULL
    enc_access.limit_to(api_key)

    for valid in valid:
        bucket, path = split(valid)
        _, _, base = enc_access.store.lookup_encrypted(bucket, Encrypted(path))
        assert base is not None

    for invalid in invalid:
        bucket, path = split(invalid)
        _, _, base = enc_access.store.lookup_encrypted(bucket, Encrypted(path))
        assert base is None


def test_limit_to_fails_closed_for_malformed_caveat():
    api_key = new_api_key(bytes())
    api_key.mac.caveats.append(b"\xff")
    enc_access = EncryptionAccess(Key.newzero())
    enc_access.store.add_with_cipher(
        b"bucket",
        Unencrypted(b"stored"),
        Encrypted(b"stored"),
        Key.newzero(),
        CipherSuite.ENC_NULL,
    )

    enc_access.limit_to(api_key)

    entries = []
    enc_access.store.iterate_with_cipher(lambda *entry: entries.append(entry))
    assert enc_access.default_key is None
    assert entries == []


def test_limit_to_preserves_unrestricted_store():
    enc_access = EncryptionAccess(Key.newzero())
    store = enc_access.store

    enc_access.limit_to(new_api_key(bytes()))

    assert enc_access.store is store
    assert enc_access.default_key == Key.newzero()


def test_limit_to_preserves_cipher_for_valid_restrictions():
    enc_access = EncryptionAccess(Key.newzero())
    enc_access.default_path_cipher = CipherSuite.ENC_AESGCM
    encrypted = encryption.encrypt_path_with_store_cipher(
        b"bucket", Unencrypted(b"valid"), enc_access.store
    )
    caveat = macaroon.Caveat()
    path = caveat.allowed_paths.add()
    path.bucket = b"bucket"
    path.encrypted_path_prefix = encrypted.raw

    enc_access.limit_to(new_api_key(bytes()).restrict(caveat))

    assert enc_access.default_path_cipher == CipherSuite.ENC_AESGCM
    assert enc_access.store.lookup_encrypted(b"bucket", encrypted)[2] is not None


def test_limit_to_skips_unusable_prefix():
    enc_access = EncryptionAccess(Key.newzero())
    enc_access.default_path_cipher = CipherSuite.ENC_AESGCM
    encrypted = encryption.encrypt_path_with_store_cipher(
        b"bucket", Unencrypted(b"valid"), enc_access.store
    )
    caveat = macaroon.Caveat()
    for prefix in (b"invalid", encrypted.raw):
        path = caveat.allowed_paths.add()
        path.bucket = b"bucket"
        path.encrypted_path_prefix = prefix

    enc_access.limit_to(new_api_key(bytes()).restrict(caveat))

    assert (
        enc_access.store.lookup_encrypted(b"bucket", Encrypted(b"invalid"))[2] is None
    )
    assert enc_access.store.lookup_encrypted(b"bucket", encrypted)[2] is not None
