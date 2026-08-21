# Copyright (C) 2023 Storj Labs, Inc.
# See LICENSE for copying information.


import hmac
import hashlib
from uplink.common.storj import CipherSuite, Key, KEY_SIZE
from .aesgcm import encrypt_aesgcm, decrypt_aesgcm
from .secretbox import encrypt_secretbox, decrypt_secretbox

AESGCM_NONCE_SIZE = 12


def to_aesgcm_nonce(nonce: bytes) -> bytes:
    return bytes(nonce[:AESGCM_NONCE_SIZE])


def encrypt(plain_data: bytes, cipher: CipherSuite, key: Key, nonce: bytes) -> bytes:
    if len(plain_data) == 0:
        return bytes()

    if cipher == CipherSuite.ENC_NULL:
        return plain_data
    elif cipher == CipherSuite.ENC_AESGCM:
        return encrypt_aesgcm(plain_data, bytes(key), to_aesgcm_nonce(nonce))
    elif cipher == CipherSuite.ENC_SECRETBOX:
        return encrypt_secretbox(plain_data, bytes(key), bytes(nonce))
    elif cipher == CipherSuite.ENC_NULL_BASE64URL:
        raise ValueError("base64 encoding not supported for this operation")
    else:
        raise ValueError(f"encryption type {cipher} not supported")


def decrypt(cipher_data: bytes, cipher: CipherSuite, key: Key, nonce: bytes) -> bytes:
    if len(cipher_data) == 0:
        return bytes()

    if cipher == CipherSuite.ENC_NULL:
        return cipher_data
    elif cipher == CipherSuite.ENC_AESGCM:
        return decrypt_aesgcm(cipher_data, bytes(key), to_aesgcm_nonce(nonce))
    elif cipher == CipherSuite.ENC_SECRETBOX:
        return decrypt_secretbox(cipher_data, bytes(key), bytes(nonce))
    elif cipher == CipherSuite.ENC_NULL_BASE64URL:
        raise ValueError("base64 encoding not supported for this operation")
    else:
        raise ValueError(f"encryption type {cipher} not supported")


def derive_key(key: Key, msg: bytes) -> Key:
    digest = hmac.new(bytes(key), msg=msg, digestmod=hashlib.sha512).digest()
    return Key(digest[:KEY_SIZE])
