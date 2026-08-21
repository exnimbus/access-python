# Copyright (C) 2023 Storj Labs, Inc.
# See LICENSE for copying information.

from __future__ import annotations
import copy


class Iterator:
    def __init__(self, raw: bytes = bytes()) -> None:
        self._raw = raw
        self._consumed = 0
        self._last_empty = bool(raw)

    @property
    def consumed(self) -> bytes:
        return self._raw[: self._consumed]

    @property
    def remaining(self) -> bytes:
        return self._raw[self._consumed :]

    @property
    def done(self) -> bool:
        return len(self._raw) == self._consumed and not self._last_empty

    def copy(self) -> Iterator:
        return copy.copy(self)

    def next(self) -> bytes:
        if self.done:
            return bytes()
        rem = self.remaining
        index = rem.find(ord("/"))
        if index == -1:
            self._consumed += len(rem)
            self._last_empty = False
            return rem
        self._consumed += index + 1
        self._last_empty = index == len(rem) - 1
        return rem[:index]


class Unencrypted:
    def __init__(self, raw: bytes = bytes()) -> None:
        self._raw = raw

    def __str__(self) -> str:
        return self.raw.decode()

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Unencrypted):
            return NotImplemented
        return self._raw == other._raw

    @property
    def valid(self) -> bool:
        return bool(self._raw)

    @property
    def raw(self) -> bytes:
        return self._raw

    def consume(self, prefix: Unencrypted) -> tuple[Unencrypted, bool]:
        if len(self._raw) >= len(prefix._raw) and self._raw.startswith(prefix._raw):
            return Unencrypted(self._raw[len(prefix._raw) :]), True
        return Unencrypted(), False

    def iterator(self) -> Iterator:
        return Iterator(self._raw)

    def less(self, other: Unencrypted) -> bool:
        return self._raw < other._raw


class Encrypted:
    def __init__(self, raw: bytes = bytes()) -> None:
        self._raw = raw

    def __str__(self) -> str:
        return self.raw.decode()

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Encrypted):
            return NotImplemented
        return self._raw == other._raw

    @property
    def valid(self) -> bool:
        return bool(self._raw)

    @property
    def raw(self) -> bytes:
        return self._raw

    def consume(self, prefix: Encrypted) -> tuple[Encrypted, bool]:
        if len(self._raw) >= len(prefix._raw) and self._raw.startswith(prefix._raw):
            return Encrypted(self._raw[len(prefix._raw) :]), True
        return Encrypted(), False

    def iterator(self) -> Iterator:
        return Iterator(self._raw)

    def less(self, other: Encrypted) -> bool:
        return self._raw < other._raw
