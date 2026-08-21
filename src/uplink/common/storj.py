# Copyright (C) 2023 Storj Labs, Inc.
# See LICENSE for copying information.

from __future__ import annotations
import os
from enum import IntEnum
from urllib.parse import urlparse, parse_qs, ParseResult
from uplink.common import base58
from io import StringIO

KEY_SIZE = 32
NONCE_SIZE = 24

NODEID_SIZE = 32


class Key:
    __slots__ = "_data"

    SIZE = KEY_SIZE

    def __init__(self, data: bytes) -> None:
        if len(data) != KEY_SIZE:
            raise ValueError(f"key must be of length f{KEY_SIZE} but got f{len(data)}")
        self._data = data

    def __bytes__(self) -> bytes:
        return self._data

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Key):
            return NotImplemented
        return self._data == other._data

    @staticmethod
    def newzero() -> Key:
        return Key(b"\x00" * KEY_SIZE)

    @staticmethod
    def generate() -> Key:
        return Key(os.urandom(KEY_SIZE))


def new_key() -> Key:
    return Key.generate()


class CipherSuite(IntEnum):
    ENC_UNSPECIFIED = 0
    ENC_NULL = 1
    ENC_AESGCM = 2
    ENC_SECRETBOX = 3
    ENC_NULL_BASE64URL = 4


class NoiseInfo:
    __slots__ = ["_public_key", "_proto"]

    def __init__(self, public_key: str | None = None, proto: int = 0) -> None:
        self._public_key = public_key
        self._proto = proto

    @property
    def public_key(self) -> str | None:
        return self._public_key

    @property
    def proto(self) -> int:
        return self._proto

    @property
    def zero(self) -> bool:
        return self._proto == 0 and self._public_key is None


class NodeURL:
    __slots__ = ["_id", "_address", "_noise_info", "_debounce_limit", "_features"]

    def __init__(self) -> None:
        self._id: NodeID | None = None
        self._address = ""
        self._noise_info = NoiseInfo()
        self._debounce_limit = 0
        self._features = 0

    @staticmethod
    def parse(value: str) -> NodeURL:
        if value == "":
            return NodeURL()
        if not value.startswith("storj://"):
            if not "://" in value:
                value = "storj://" + value

        u = urlparse(value)
        if u.scheme != "" and u.scheme != "storj":
            raise ValueError(f'unknown scheme "{u.scheme}"')

        node = NodeURL()
        if u.username is not None:
            node._id = node_id_from_string(u.username)

        address = _hostport(u)
        if address is None:
            raise ValueError("host cannot be empty")

        node._address = address
        node._noise_info = NoiseInfo()

        query = parse_qs(u.query)
        if "noise_pub" in query:
            pubkey, _ = base58.check_decode(query["noise_pub"][0])
            node._noise_info._public_key = pubkey.decode()
        if "noise_proto" in query:
            node._noise_info._proto = int(query["noise_proto"][0], 10)
        if "debounce" in query:
            node._debounce_limit = int(query["debounce"][0], 10)
        if "f" in query:
            node._features = int(query["f"][0], 16)

        return node

    @property
    def id(self) -> NodeID | None:
        return self._id

    @id.setter
    def id(self, value: NodeID | None) -> None:
        self._id = value

    @property
    def address(self) -> str:
        return self._address

    @property
    def noise_info(self) -> NoiseInfo:
        return self._noise_info

    @property
    def debounce_limit(self) -> int:
        return self._debounce_limit

    @property
    def features(self) -> int:
        return self._features

    def __str__(self) -> str:
        out = StringIO()
        if self.id is not None:
            out.write(str(self.id))
            out.write("@")
        out.write(self._address)

        delim = "?"

        def write_key(key: str, value: str) -> None:
            nonlocal delim
            out.write(delim)
            delim = "&"
            out.write(key)
            out.write(value)

        if self.debounce_limit > 0:
            write_key("debounce=", f"{self.debounce_limit}")

        if self.features > 0:
            write_key("debounce=", f"{self.features:x}")

        if self.noise_info.proto > 0:
            write_key("noise_proto=", f"{self.noise_info.proto:d}")

        if self.noise_info.public_key is not None:
            write_key(
                "noise_pub=",
                base58.check_encode(self.noise_info.public_key.encode(), 0),
            )

        return out.getvalue()


class NodeID:
    __slots__ = ["_id"]

    def __init__(self, id_bytes: bytes | bytearray) -> None:
        if len(id_bytes) != NODEID_SIZE:
            raise ValueError(
                f"not enough bytes to make a node id; have {len(id_bytes)}, need {NODEID_SIZE}"
            )
        self._id = bytes(id_bytes)

    def __str__(self) -> str:
        unversioned = self.unversioned()
        # TODO: support versions
        return base58.check_encode(unversioned._id, 0)

    def unversioned(self: NodeID) -> NodeID:
        unversioned = bytearray(self._id)
        unversioned[-1] = 0
        return NodeID(unversioned)


def node_id_from_string(s: str) -> NodeID:
    id_bytes, version_number = base58.check_decode(s)
    unversioned_id = node_id_from_bytes(id_bytes)
    # TODO: support versions
    return unversioned_id


def node_id_from_bytes(v: bytes) -> NodeID:
    return NodeID(v)


def _hostport(u: ParseResult) -> str | None:
    if u.port is None:
        return u.hostname
    return f"{u.hostname}:{u.port}"
