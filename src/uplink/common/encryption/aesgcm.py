# Copyright (C) 2023 Storj Labs, Inc.
# See LICENSE for copying information.

from Crypto.Cipher import AES


def encrypt_aesgcm(plain_data: bytes, key: bytes, nonce: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(plain_data)
    return ciphertext + tag


def decrypt_aesgcm(cipher_data: bytes, key: bytes, nonce: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    return cipher.decrypt_and_verify(
        cipher_data[: -AES.block_size], cipher_data[-AES.block_size :]
    )
