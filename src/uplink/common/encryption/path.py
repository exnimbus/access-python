# Copyright (C) 2023 Storj Labs, Inc.
# See LICENSE for copying information.

from io import StringIO
from uplink.common.paths import Unencrypted, Encrypted, Iterator
from uplink.common.storj import CipherSuite, Key
from uplink.common import storj
from .encryption import derive_key, encrypt, decrypt
from .store import Store
from base64 import urlsafe_b64decode, urlsafe_b64encode
from typing import Optional
import hmac
import hashlib


AESGCM_NONCE_SIZE = 12
_EMPTY_COMPONENT_PREFIX = 1
_EMPTY_COMPONENT = _EMPTY_COMPONENT_PREFIX.to_bytes()
_NOT_EMPTY_COMPONENT_PREFIX = 2
_NOT_EMPTY_COMPONENT = _NOT_EMPTY_COMPONENT_PREFIX.to_bytes()

_ESCAPE_SLASH = int("2e", 16)
_ESCAPE_FF = int("fe", 16)
_ESCAPE_01 = int("01", 16)


def encrypt_path_with_store_cipher(
    bucket: bytes, path: Unencrypted, store: Store
) -> Encrypted:
    return encrypt_path(bucket, path, None, store)


def encrypt_path(
    bucket: bytes, path: Unencrypted, path_cipher: Optional[CipherSuite], store: Store
) -> Encrypted:
    if not path.valid:
        return Encrypted()

    _, remaining, base = store.lookup_unencrypted(bucket, path)
    if base is None:
        raise ValueError(f'"{bucket!r}/{path!r}": missing encryption base')
    if path_cipher is None:
        path_cipher = base.path_cipher

    # if we're using tbhe dbefault base (meaning the default key), we need
    # to include the bucket name in the path derivation.
    key = base.key
    if base.default:
        key = _derive_path_key_component(key, bucket)

    encrypted = _encrypt_iterator(remaining, path_cipher, key)

    pb = PathBuilder()
    if base.encrypted.valid:
        pb.append(base.encrypted.raw)
    if not remaining.done:
        pb.append(encrypted)
    return pb.encrypted


def _encrypt_iterator(iter: Iterator, cipher: CipherSuite, key: Key) -> bytes:
    iter = iter.copy()
    pb = PathBuilder()
    while not iter.done:
        component = iter.next()
        enc_component = _encrypt_path_component(component, cipher, key)
        key = _derive_path_key_component(key, component)
        pb.append(enc_component)
    return pb.value()


def _encrypt_path_component(comp: bytes, cipher: CipherSuite, key: Key) -> bytes:
    if cipher == CipherSuite.ENC_NULL:
        return comp

    if cipher == CipherSuite.ENC_NULL_BASE64URL:
        decoded = urlsafe_b64decode(comp)
        return decoded

    derived_key = _derive_path_key_component(key, comp)

    nonce = hmac.new(
        bytes(derived_key), msg=b"nonce", digestmod=hashlib.sha512
    ).digest()

    nonce_size = storj.NONCE_SIZE
    if cipher == CipherSuite.ENC_AESGCM:
        nonce_size = AESGCM_NONCE_SIZE
    nonce = nonce[:nonce_size]

    cipher_text = encrypt(comp, cipher, key, nonce)
    segment = bytearray(nonce)
    segment.extend(cipher_text)

    return _encode_segment(segment)


def _encode_segment(segment: bytes | bytearray) -> bytes:
    if len(segment) == 0:
        return _EMPTY_COMPONENT

    result = bytearray(_NOT_EMPTY_COMPONENT)
    for r in segment:
        if r == _ESCAPE_SLASH:
            result.extend([_ESCAPE_SLASH, 1])
        elif r == _ESCAPE_SLASH + 1:
            result.extend([_ESCAPE_SLASH, 2])
        elif r == _ESCAPE_FF:
            result.extend([_ESCAPE_FF, 1])
        elif r == _ESCAPE_FF + 1:
            result.extend([_ESCAPE_FF, 2])
        elif r == _ESCAPE_01 - 1:
            result.extend([_ESCAPE_01, 1])
        elif r == _ESCAPE_01:
            result.extend([_ESCAPE_01, 2])
        else:
            result.append(r)
    return bytes(result)


def _decode_segment(segment: bytes) -> bytes:
    _validate_encoded_segment(segment)

    if segment[0] == _EMPTY_COMPONENT[0]:
        return bytes()

    decoded = bytearray()
    i = 1
    while i < len(segment):
        if i == len(segment) - 1:
            decoded.append(segment[i])
        elif segment[i] == _ESCAPE_SLASH or segment[i] == _ESCAPE_FF:
            decoded.append(segment[i] + segment[i + 1] - 1)
            i = i + 1
        elif segment[i] == _ESCAPE_01:
            decoded.append(segment[i + 1] - 1)
            i = i + 1
        else:
            decoded.append(segment[i])
        i = i + 1

    return bytes(decoded)


def _validate_encoded_segment(segment: bytes) -> None:
    if len(segment) == 0:
        raise ValueError("encoded segment cannot be empty")
    elif (
        segment[0] != _EMPTY_COMPONENT_PREFIX
        and segment[0] != _NOT_EMPTY_COMPONENT_PREFIX
    ):
        raise ValueError("invalid segment prefix")
    elif segment[0] == _EMPTY_COMPONENT_PREFIX and len(segment) > 1:
        raise ValueError("segment encoded as empty but contains data")
    elif segment[0] == _NOT_EMPTY_COMPONENT_PREFIX and len(segment) == 1:
        raise ValueError("segment encoded as not empty but doesn't contain data")

    if len(segment) == 1:
        # empty, valid segment
        return

    index = 1
    while index < len(segment) - 1:
        if is_escape_byte(segment[index]):
            if not (segment[index + 1] == 1 or segment[index + 1] == 2):
                raise ValueError("invalid escape sequence")
            index += 1
        elif is_disallowed_byte(segment[index]):
            raise ValueError("invalid character in segment")
        index += 1
    if index == len(segment) - 1:
        if is_escape_byte(segment[index]):
            raise ValueError("invalid escape sequence")
        if is_disallowed_byte(segment[index]):
            raise ValueError("invalid character")


def is_escape_byte(b: int) -> bool:
    return b == _ESCAPE_SLASH or b == _ESCAPE_FF or b == _ESCAPE_01


def is_disallowed_byte(b: int) -> bool:
    return b == 0 or b == "\xff" or b == "/"


def decrypt_path_with_store_cipher(
    bucket: bytes, path: Encrypted, store: Store
) -> Unencrypted:
    return decrypt_path(bucket, path, None, store)


def decrypt_path(
    bucket: bytes, path: Encrypted, path_cipher: Optional[CipherSuite], store: Store
) -> Unencrypted:
    if not path.valid:
        return Unencrypted()

    _, remaining, base = store.lookup_encrypted(bucket, path)
    if base is None:
        raise ValueError(f'"{bucket!r}/{path!r}": missing decryption base')

    if path_cipher is None:
        path_cipher = base.path_cipher

    key = base.key
    if base.default:
        key = _derive_path_key_component(key, bucket)

    decrypted = _decrypt_iterator(remaining, path_cipher, key)

    pb = PathBuilder()
    if base.unencrypted.valid:
        pb.append(base.unencrypted.raw)
    if not remaining.done:
        pb.append(decrypted)
    return pb.unencrypted


def _decrypt_iterator(iter: Iterator, cipher: CipherSuite, key: Key) -> bytes:
    iter = iter.copy()
    pb = PathBuilder()
    while not iter.done:
        component = iter.next()
        unenc_component = _decrypt_path_component(component, cipher, key)
        key = _derive_path_key_component(key, unenc_component)
        pb.append(unenc_component)
    return pb.value()


def derive_path_key(bucket: bytes, path: Unencrypted, store: Store) -> Key:
    _, remaining, base = store.lookup_unencrypted(bucket, path)
    if base is None:
        raise ValueError(f'"{bucket!r}/{path!r}": missing encryption base')

    # If asking for the key at the bucket, do that and return.
    if not path.valid:
        # if we're using the default base (meaning the default key), we need
        # to include the bucket name in the path derivation.
        key = base.key
        if base.default:
            key = _derive_path_key_component(key, bucket)
        return key

    # if we're using the default base (meaning the default key), we need
    # to include the bucket name in the path derivation.
    key = base.key
    if base.default:
        key = _derive_path_key_component(key, bucket)

    while not remaining.done:
        key = _derive_path_key_component(key, remaining.next())

    return key


def _derive_path_key_component(key: Key, component: bytes) -> Key:
    path_component = bytearray(b"path:")
    path_component.extend(component)
    return derive_key(key, bytes(path_component))


def _decrypt_path_component(comp: bytes, cipher: CipherSuite, key: Key) -> bytes:
    if len(comp) == 0:
        return comp

    if cipher == CipherSuite.ENC_NULL:
        return comp

    if cipher == CipherSuite.ENC_NULL_BASE64URL:
        return urlsafe_b64encode(comp)

    data = _decode_segment(comp)

    nonce_size = storj.NONCE_SIZE
    if cipher == CipherSuite.ENC_AESGCM:
        nonce_size = AESGCM_NONCE_SIZE

    if len(data) < nonce_size or nonce_size < 0:
        raise ValueError("component did not contain enough nonce bytes")

    nonce = data[:nonce_size]
    cipher_data = data[nonce_size:]

    decrypted = decrypt(cipher_data, cipher, key, nonce)
    return decrypted


class PathBuilder:
    __slots__ = ["_i", "_buf"]

    def __init__(self) -> None:
        self._i = 0
        self._buf = bytearray()

    def value(self) -> bytes:
        return bytes(self._buf)

    def append(self, s: bytes) -> None:
        if self._i > 0:
            self._buf.extend(b"/")
        self._buf.extend(s)
        self._i += 1

    @property
    def encrypted(self) -> Encrypted:
        return Encrypted(self.value())

    @property
    def unencrypted(self) -> Unencrypted:
        return Unencrypted(self.value())
