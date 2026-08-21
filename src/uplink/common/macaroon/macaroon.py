# Copyright (C) 2020 Storj Labs, Inc.
# See LICENSE for copying information.

from __future__ import annotations

import hmac
import hashlib
import os
from enum import IntEnum, unique
from collections.abc import Iterable
from typing import NamedTuple
from . import types_pb2 as types_pb2
import struct


@unique
class FieldType(IntEnum):
    EOS = 0
    LOCATION = 1
    IDENTIFIER = 2
    VERIFICATION_ID = 4
    SIGNATURE = 6


class Packet(NamedTuple):
    field_type: FieldType
    data: bytes | None


class Macaroon:
    VERSION = 2

    __slots__ = ["head", "tail", "caveats"]

    def __init__(
        self,
        head: bytes = bytes(),
        tail: bytes = bytes(),
        caveats: list[bytes] | None = None,
    ) -> None:
        self.head = head
        self.tail = tail
        self.caveats = caveats or []

    @staticmethod
    def parse(data: bytes) -> Macaroon:
        if len(data) < 2:
            raise Exception("empty macaroon")
        if data[0] != Macaroon.VERSION:
            raise Exception("invalid macaroon version")
        data = data[1:]
        data, section = parse_section(data)
        if len(section) > 0 and section[0].field_type == FieldType.LOCATION:
            section = section[1:]
        if len(section) != 1 or section[0].field_type != FieldType.IDENTIFIER:
            raise Exception("invalid macaroon header")

        mac = Macaroon()
        head = section[0].data
        if head is None:
            raise Exception("invalid macaroon header")
        mac.head = head
        while True:
            data, section = parse_section(data)
            if len(section) == 0:
                break
            if len(section) > 0 and section[0].field_type == FieldType.LOCATION:
                section = section[1:]
            if len(section) == 0 or section[0].field_type != FieldType.IDENTIFIER:
                raise Exception("no Identifier in caveat")
            cav = section[0].data
            if cav is None:
                raise Exception("no Identifier in caveat")
            section = section[1:]
            if len(section) == 0:
                # first party caveat
                mac.caveats.append(cav)
                continue
            if len(section) != 1:
                raise Exception("extra fields found in caveat")
            if section[0].field_type != FieldType.VERIFICATION_ID:
                raise Exception("invalid field found in caveat")
            mac.caveats.append(cav)
        _, sig = parse_packet(data)
        if sig.field_type != FieldType.SIGNATURE:
            raise Exception("unexpected field found instead of signature")
        if sig.data is None or len(sig.data) != 32:
            raise Exception("signature has unexpected length")
        mac.tail = sig.data
        return mac

    def serialize(self) -> bytes:
        # Start data from version int
        b = bytearray(b"\x02")

        # Serialize identity
        serialize_packet(b, FieldType.IDENTIFIER, self.head)
        b.append(0)

        # Serialize Caveats
        for cav in self.caveats:
            serialize_packet(b, FieldType.IDENTIFIER, cav)
            b.append(0)

        b.append(0)

        # Serialize Tail
        serialize_packet(b, FieldType.SIGNATURE, self.tail)

        return bytes(b)

    def copy(self) -> Macaroon:
        return Macaroon(
            head=self.head,
            tail=self.tail,
            caveats=self.caveats.copy(),
        )

    def add_first_party_caveat(self, caveat: bytes) -> Macaroon:
        macaroon = self.copy()
        macaroon.caveats.append(caveat)
        macaroon.tail = _sign(macaroon.tail, caveat)
        return macaroon

    def validate_and_tails(self, secret: bytes) -> tuple[bool, list[bytes]]:
        tails: list[bytes] = []
        tail = _sign(secret, self.head)
        tails.append(tail)
        for cav in self.caveats:
            tail = _sign(tail, cav)
            tails.append(tail)
        return hmac.compare_digest(tail, self.tail), tails


def parse_section(data: bytes) -> tuple[bytes, list[Packet]]:
    prev_field_type = -1
    packets: list[Packet] = []
    while True:
        if len(data) == 0:
            raise Exception("section extends past end of buffer")

        rest, p = parse_packet(data)

        if p.field_type == FieldType.EOS:
            return rest, packets

        if p.field_type <= prev_field_type:
            raise Exception("fields out of order")

        packets.append(p)
        prev_field_type = p.field_type
        data = rest


def parse_packet(data: bytes) -> tuple[bytes, Packet]:
    data, field_type_value = parse_varint(data)

    field_type = FieldType(field_type_value)
    if field_type == FieldType.EOS:
        return data, Packet(field_type=field_type, data=None)

    data, pack_len = parse_varint(data)

    if pack_len > len(data):
        raise Exception("out of bounds")

    if pack_len == 0:
        return data, Packet(field_type=field_type, data=None)

    p = Packet(field_type=field_type, data=data[0:pack_len])
    return data[pack_len:], p


def parse_varint(data: bytes) -> tuple[bytes, int]:
    value, n = uvarint(data)
    if n <= 0 or value > 0x7FFFFFFF:
        raise Exception("varint error")
    return data[n:], value


def uvarint(data: bytes) -> tuple[int, int]:
    MAXVARINTLEN64 = 10
    x = 0
    s = 0
    for i, b in enumerate(data):
        if i == MAXVARINTLEN64:
            return 0, -(i + 1)  # overflow
        if b < 0x80:
            if i == MAXVARINTLEN64 - 1 and b > 1:
                return 0, -(i + 1)  # overflow
            return x | b << s, i + 1
        x |= b & 0x7F << s
        s += 7
    return 0, 0


def serialize_packet(buf: bytearray, field_type: FieldType, data: bytes) -> None:
    append_varint(buf, field_type)
    append_varint(buf, len(data))
    buf.extend(data)


def append_varint(buf: bytearray, x: int) -> None:
    while x >= 0x80:
        buf.append(x | 0x80)
        x >>= 7
    buf.append(x)


def new_secret() -> bytes:
    return os.urandom(32)


def new_unrestricted(secret: bytes) -> Macaroon:
    head = new_secret()
    return new_unrestricted_from_parts(head, secret)


def new_unrestricted_from_parts(head: bytes, secret: bytes) -> Macaroon:
    return Macaroon(head=head, tail=_sign(secret, head))


def _sign(secret: bytes, data: bytes) -> bytes:
    return hmac.new(secret, msg=data, digestmod=hashlib.sha256).digest()
