# Copyright (C) 2023 Storj Labs, Inc.
# See LICENSE for copying information.

from __future__ import annotations

import copy
from collections.abc import Callable
from contextlib import ExitStack
from uplink.common.storj import CipherSuite, Key
from uplink.common.paths import Unencrypted, Encrypted, Iterator


class Base:
    __slots__ = ["unencrypted", "encrypted", "key", "path_cipher", "default"]

    def __init__(
        self,
        key: Key,
        path_cipher: CipherSuite,
        unencrypted: Unencrypted = Unencrypted(),
        encrypted: Encrypted = Encrypted(),
        default: bool = False,
    ) -> None:
        self.unencrypted = unencrypted
        self.encrypted = encrypted
        self.key = key  # type: Key
        self.path_cipher = path_cipher
        self.default = default

    @staticmethod
    def clone(base: Base | None) -> Base | None:
        if base is None:
            return None
        return copy.deepcopy(base)


class _Node:
    __slots__ = ["_unenc", "_unenc_map", "_enc", "_enc_map", "_base"]

    def __init__(self) -> None:
        self._unenc: dict[bytes, _Node] = {}
        self._unenc_map: dict[bytes, bytes] = {}
        self._enc: dict[bytes, _Node] = {}
        self._enc_map: dict[bytes, bytes] = {}
        self._base: Base | None = None

    def add(self, unenc: Iterator, enc: Iterator, base: Base) -> None:
        """Places the path and base into the node tree structure."""
        if unenc.done != enc.done:
            raise ValueError(
                "encrypted and unencrypted paths had different number of components"
            )

        # If we're done walking the paths, this node must have the provided base.
        if unenc.done:
            self._base = base
            return

        # Walk to the next parts and ensure they're consistent with previous additions.
        unenc_part, enc_part = unenc.next(), enc.next()
        if key_exists_but_value_not_equal(self._enc_map, enc_part, unenc_part):
            raise ValueError("conflicting unencrypted parts for encrypted path")
        if key_exists_but_value_not_equal(self._unenc_map, unenc_part, enc_part):
            raise ValueError("conflicting encrypted parts for unencrypted path")

        # Look up the child node. Since we're sure the unenc and enc mappings are
        # consistent, we can look it up in one map and unconditionally insert it
        # into both maps if necessary.
        child = self._unenc.get(unenc_part)
        if child is None:
            child = _Node()

        # Recurse to the next node in the tree.
        child.add(unenc, enc, base)

        # Only add to the maps if the child add was successful.
        self._unenc_map[unenc_part] = enc_part
        self._enc_map[enc_part] = unenc_part
        self._unenc[unenc_part] = child
        self._enc[enc_part] = child

    def lookup(
        self,
        iter: Iterator,
        best_remaining: Iterator,
        best_base: Base | None,
        unenc: bool,
        depth: int = 0,
    ) -> tuple[dict[bytes, bytes], Iterator, Base | None]:
        if self._base is not None or best_base is None:
            best_remaining, best_base = iter.copy(), self._base
        revealed, children = self._unenc_map, self._enc
        if unenc:
            revealed, children = self._enc_map, self._unenc

        if iter.done:
            return revealed, best_remaining, best_base

        n = iter.next()
        child = children.get(n)
        if child is None:
            return {}, best_remaining, best_base

        return child.lookup(iter, best_remaining, best_base, unenc, depth + 1)

    def iterate_with_cipher(
        self,
        fn: Callable[[bytes, Unencrypted, Encrypted, Key, CipherSuite], None],
        bucket: bytes,
    ) -> None:
        if self._base is not None:
            fn(
                bucket,
                self._base.unencrypted,
                self._base.encrypted,
                self._base.key,
                self._base.path_cipher,
            )

        for child in self._unenc.values():
            child.iterate_with_cipher(fn, bucket)


class Store:
    __slots__ = ["_roots", "_default_key", "_default_path_cipher", "_encryption_bypass"]

    def __init__(
        self,
        default_key: Key | None = None,
        default_path_cipher: CipherSuite = CipherSuite.ENC_UNSPECIFIED,
        encryption_bypass: bool = False,
    ) -> None:
        self._roots: dict[bytes, _Node] = {}
        self._default_key = default_key
        self._default_path_cipher = default_path_cipher
        self._encryption_bypass = encryption_bypass

    @staticmethod
    def clone(store: Store) -> Store:
        return copy.deepcopy(store)

    @property
    def default_key(self) -> Key | None:
        """Returns the default key that is returned for any lookup that does not match a bucket."""
        return self._default_key

    @default_key.setter
    def default_key(self, default_key: Key | None) -> None:
        """Sets the default key to be returned for any lookup that does not match a bucket."""
        self._default_key = default_key

    @property
    def default_path_cipher(self) -> CipherSuite:
        """Returns the default path cipher or CipherSuite.ENC_UNSPECIFIED if unset"""
        return self._default_path_cipher

    @default_path_cipher.setter
    def default_path_cipher(self, default_path_cipher: CipherSuite) -> None:
        """Sets the default path cipher for any lookup that does not match a bucket"""
        self._default_path_cipher = default_path_cipher

    @property
    def encryption_bypass(self) -> bool:
        """Returns the default path cipher or CipherSuite.ENC_UNSPECIFIED if unset"""
        return self._encryption_bypass

    @encryption_bypass.setter
    def encryption_bypass(self, encryption_bypass: bool) -> None:
        """Sets the default path cipher for any lookup that does not match a bucket"""
        self._encryption_bypass = encryption_bypass

    def iterate_with_cipher(
        self, fn: Callable[[bytes, Unencrypted, Encrypted, Key, CipherSuite], None]
    ) -> None:
        """Executes the callback with every value that has been added to the Store"""
        for bucket, root in self._roots.items():
            root.iterate_with_cipher(fn, bucket)

    def add(self, bucket: bytes, unenc: Unencrypted, enc: Encrypted, key: Key) -> None:
        return self.add_with_cipher(bucket, unenc, enc, key, self.default_path_cipher)

    def add_with_cipher(
        self,
        bucket: bytes,
        unenc: Unencrypted,
        enc: Encrypted,
        key: Key,
        path_cipher: CipherSuite,
    ) -> None:
        """Creates a mapping from the unencrypted path to the encrypted path and key with the given cipher."""
        root = self._roots.get(bucket)
        if root is None:
            root = _Node()

        root.add(
            unenc.iterator(),
            enc.iterator(),
            Base(key=key, path_cipher=path_cipher, unencrypted=unenc, encrypted=enc),
        )
        self._roots[bucket] = root

    def default_base(self, default_key: Key) -> Base:
        return Base(key=default_key, path_cipher=self.default_path_cipher, default=True)

    def lookup_unencrypted(
        self, bucket: bytes, path: Unencrypted
    ) -> tuple[dict[bytes, bytes], Iterator, Base | None]:
        revealed: dict[bytes, bytes] = {}
        remaining = Iterator()
        base = None

        root = self._roots.get(bucket)
        if root is not None:
            revealed, remaining, base = root.lookup(
                path.iterator(), Iterator(), None, True
            )

        if base is None and self.default_key is not None:
            return (
                {},
                path.iterator(),
                self._bypass_encryption(self.default_base(self.default_key)),
            )

        return revealed, remaining, self._bypass_encryption(Base.clone(base))

    def lookup_encrypted(
        self, bucket: bytes, path: Encrypted
    ) -> tuple[dict[bytes, bytes], Iterator, Base | None]:
        revealed: dict[bytes, bytes] = {}
        remaining = Iterator()
        base = None

        root = self._roots.get(bucket)
        if root is not None:
            revealed, remaining, base = root.lookup(
                path.iterator(), Iterator(), None, False
            )

        if base is None and self.default_key is not None:
            return (
                {},
                path.iterator(),
                self._bypass_encryption(self.default_base(self.default_key)),
            )

        return revealed, remaining, self._bypass_encryption(Base.clone(base))

    def _bypass_encryption(self, base: Base | None) -> Base | None:
        if base is not None and self.encryption_bypass:
            base.path_cipher = CipherSuite.ENC_NULL_BASE64URL
        return base


def key_exists_but_value_not_equal(
    m: dict[bytes, bytes], key: bytes, expect_value: bytes
) -> bool:
    value = m.get(key)
    return value is not None and value != expect_value
