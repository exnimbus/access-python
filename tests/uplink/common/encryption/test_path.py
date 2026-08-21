# Copyright (C) 2023 Storj Labs, Inc.
# See LICENSE for copying information.

from collections.abc import Iterable
import pytest
import uplink.common.encryption.path as encryption_path
import itertools
from base64 import urlsafe_b64encode
from uplink.common.storj import Key, CipherSuite
from uplink.common.encryption import (
    PathBuilder,
    Store,
    encrypt_path,
    encrypt_path_with_store_cipher,
    decrypt_path_with_store_cipher,
    derive_path_key,
)
from uplink.common.paths import Unencrypted, Encrypted, Iterator

_ALL_CIPHERS = [
    CipherSuite.ENC_NULL,
    CipherSuite.ENC_AESGCM,
    CipherSuite.ENC_SECRETBOX,
]


def _with_all_ciphers(paths: list[bytes]) -> Iterable[tuple[CipherSuite, bytes]]:
    return itertools.product(_ALL_CIPHERS, paths)


def _new_store(key: Key, path_cipher: CipherSuite) -> Store:
    store = Store()
    store.add_with_cipher(b"bucket", Unencrypted(), Encrypted(), key, path_cipher)
    return store


@pytest.mark.parametrize(
    "path_cipher,raw_path",
    _with_all_ciphers(
        [
            b"",
            b"/",
            b"//",
            b"file.txt",
            b"file.txt/",
            b"fold1/file.txt",
            b"fold1/fold2/file.txt",
            b"/fold1/fold2/fold3/file.txt",
            b"/fold1/fold2/fold3/file.txt/",
        ]
    ),
)
def test_store_encryption(path_cipher: CipherSuite, raw_path: bytes) -> None:
    store = _new_store(Key.generate(), path_cipher)
    path = Unencrypted(raw_path)

    enc_path = encrypt_path_with_store_cipher(b"bucket", path, store)
    if path_cipher != CipherSuite.ENC_NULL:
        assert not enc_path.raw.endswith(b"/")

    dec_path = decrypt_path_with_store_cipher(b"bucket", enc_path, store)
    assert raw_path == dec_path.raw


@pytest.mark.parametrize(
    "path_cipher,raw_path",
    _with_all_ciphers(
        [
            b"",
            b"/",
            b"//",
            b"file.txt",
            b"file.txt/",
            b"fold1/file.txt",
            b"fold1/fold2/file.txt",
            b"/fold1/fold2/fold3/file.txt",
            b"/fold1/fold2/fold3/file.txt/",
        ]
    ),
)
def test_store_encryption_bucket_root(
    path_cipher: CipherSuite, raw_path: bytes
) -> None:
    dk = Key.generate()

    root_store = Store(dk, path_cipher)

    bucket_store = Store()
    bucket_key = derive_path_key(b"bucket", Unencrypted(), root_store)
    bucket_store.add_with_cipher(
        b"bucket", Unencrypted(), Encrypted(), bucket_key, path_cipher
    )

    path = Unencrypted(raw_path)

    root_enc_path = encrypt_path_with_store_cipher(b"bucket", path, root_store)
    bucket_enc_path = encrypt_path_with_store_cipher(b"bucket", path, bucket_store)

    assert root_enc_path == bucket_enc_path


@pytest.mark.parametrize(
    "path_cipher,raw_path",
    _with_all_ciphers(
        [
            b"",
            b"/",
            b"//",
            b"file.txt",
            b"file.txt/",
            b"fold1/file.txt",
            b"fold1/fold2/file.txt",
            b"/fold1/fold2/fold3/file.txt",
            b"/fold1/fold2/fold3/file.txt/",
        ]
    ),
)
def test_store_encryption_multiple_bases(
    path_cipher: CipherSuite, raw_path: bytes
) -> None:
    pb = PathBuilder()
    iter = Iterator(raw_path)
    while not iter.done:
        pb.append(iter.next())
        prefix = pb.unencrypted

        dk = Key.generate()

        root_store = Store(dk, path_cipher)
        prefix_store = Store(dk, path_cipher)

        prefix_key = derive_path_key(b"bucket", prefix, root_store)
        enc_prefix = encrypt_path(b"bucket", prefix, path_cipher, root_store)

        prefix_store.add_with_cipher(
            b"bucket", prefix, enc_prefix, prefix_key, path_cipher
        )

        path = Unencrypted(raw_path)

        root_enc_path = encrypt_path_with_store_cipher(b"bucket", path, root_store)
        prefix_enc_path = encrypt_path_with_store_cipher(b"bucket", path, prefix_store)

        assert root_enc_path == prefix_enc_path


def test_decrypt_path_decryption_bypass() -> None:
    enc_store = Store(Key.generate(), CipherSuite.ENC_AESGCM)

    bucket_name = b"test-bucket"

    file_paths = [
        b"a",
        b"aa",
        b"b",
        b"bb",
        b"c",
        b"a/xa",
        b"a/xaa",
        b"a/xb",
        b"a/xbb",
        b"a/xc",
        b"b/ya",
        b"b/yaa",
        b"b/yb",
        b"b/ybb",
        b"b/yc",
    ]

    for path in file_paths:
        enc_store.encryption_bypass = False
        encrypted_path = encrypt_path_with_store_cipher(
            bucket_name, Unencrypted(path), enc_store
        )

        expected_path = b""
        iterator = encrypted_path.iterator()
        while not iterator.done:
            next = iterator.next()
            expected_path += urlsafe_b64encode(next) + b"/"

        expected_path = expected_path.removesuffix(b"/")

        enc_store.encryption_bypass = True
        actual_path = decrypt_path_with_store_cipher(
            bucket_name, encrypted_path, enc_store
        )

        assert Unencrypted(expected_path) == actual_path


def test_encrypt_path_encryption_bypass() -> None:
    enc_store = Store(Key.generate(), CipherSuite.ENC_AESGCM)

    bucket_name = b"test-bucket"

    file_paths = [
        b"a",
        b"aa",
        b"b",
        b"bb",
        b"c",
        b"a/xa",
        b"a/xaa",
        b"a/xb",
        b"a/xbb",
        b"a/xc",
        b"b/ya",
        b"b/yaa",
        b"b/yb",
        b"b/ybb",
        b"b/yc",
    ]

    for path in file_paths:
        enc_store.encryption_bypass = False
        encrypted_path = encrypt_path_with_store_cipher(
            bucket_name, Unencrypted(path), enc_store
        )

        encoded_path = b""
        iterator = encrypted_path.iterator()
        while not iterator.done:
            next = iterator.next()
            encoded_path += urlsafe_b64encode(next) + b"/"

        encoded_path = encoded_path.removesuffix(b"/")

        enc_store.encryption_bypass = True
        actual_path = encrypt_path_with_store_cipher(
            bucket_name, Unencrypted(encoded_path), enc_store
        )

        assert encrypted_path == actual_path


def test_segment_encoding() -> None:
    assert encryption_path._encode_segment(b"") == b"\x01"

    segments = {
        b"": "01",
        b"a": "0261",
        b"\x00": "020101",
        b"/": "022e02",
        b"abcd12345": "02616263643132333435",
        b"/////": "022e022e022e022e022e02",
        b"\x00\x00\x00\x00\x00\x00\x00\x00\x00": "02010101010101010101010101010101010101",
        b"a/a2aa\x001b\xff": "02612e026132616101013162fe02",
        b"//a\x00aa\x001bgab/": "022e022e026101016161010131626761622e02",
        b"\x00/a0aa\x001bgab\x00": "0201012e0261306161010131626761620101",
    }

    for segment, want_encoded in segments.items():
        encoded = encryption_path._encode_segment(segment)
        assert encoded.find(0) == -1
        assert encoded.find(255) == -1
        assert encoded.find(ord("/")) == -1
        assert encoded == bytes.fromhex(want_encoded)
        decoded = encryption_path._decode_segment(encoded)
        assert decoded == segment
