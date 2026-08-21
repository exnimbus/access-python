# Copyright (C) 2023 Storj Labs, Inc.
# See LICENSE for copying information.

from base58 import b58decode_check, b58encode_check
from typing import Tuple


def check_decode(s: str) -> Tuple[bytes, int]:
    decoded = b58decode_check(s)
    if len(decoded) < 1:
        raise Exception("invalid format: version byte missing")
    version = decoded[0]
    return bytes(decoded[1:]), version


def check_encode(input: bytes, version: int) -> str:
    b = bytearray()
    b.append(version)
    b.extend(input)
    return b58encode_check(bytes(b)).decode()
