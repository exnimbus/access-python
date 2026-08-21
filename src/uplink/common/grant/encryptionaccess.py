# Copyright (C) 2023 Storj Labs, Inc.
# See LICENSE for copying information.

from __future__ import annotations

from collections.abc import Sequence
from uplink.common.macaroon import Macaroon, APIKey, Caveat, CaveatPath
from uplink.common.pb import encryption_pb2, encryption_access_pb2
from uplink.common import encryption
from uplink.common.encryption import Store
from uplink.common.paths import Encrypted, Unencrypted
from uplink.common import storj
from uplink.common.storj import Key


class EncryptionAccess:
    __slots__ = ["_store"]

    def __init__(self, default_key: Key | None = None) -> None:
        store = Store()
        store.default_key = default_key

        self._store = store

    def clone(self) -> EncryptionAccess:
        clone = EncryptionAccess()
        clone._store = Store.clone(self._store)
        return clone

    @property
    def store(self) -> Store:
        return self._store

    @property
    def default_key(self) -> Key | None:
        return self._store.default_key

    @default_key.setter
    def default_key(self, default_key: Key | None) -> None:
        self._store.default_key = default_key

    @property
    def default_path_cipher(self) -> storj.CipherSuite:
        return self._store.default_path_cipher

    @default_path_cipher.setter
    def default_path_cipher(self, default_path_cipher: storj.CipherSuite) -> None:
        self._store.default_path_cipher = default_path_cipher

    def limit_to(self, api_key: APIKey) -> None:
        try:
            self._store = self.__maybe_limit_to(api_key)
        except Exception:
            self._store = Store()

    def __maybe_limit_to(self, api_key: APIKey) -> Store:
        # TODO: storj/common does a clone of the macaroon here but "bytes" are
        # immutable in python so it's probably ok to just return parts of the
        # api key macaroon without duplicating...

        prefixes, restricted = collapse_prefixes(api_key.mac)

        if not restricted:
            return self._store

        store = Store()
        store.default_path_cipher = self._store.default_path_cipher

        for prefix in prefixes:
            bucket = prefix.bucket
            enc_path = Encrypted(prefix.encrypted_path_prefix)
            try:
                unenc_path = encryption.decrypt_path_with_store_cipher(
                    bucket, enc_path, self._store
                )
                key = encryption.derive_path_key(bucket, unenc_path, self._store)
                _, _, base = self._store.lookup_encrypted(bucket, enc_path)
                if base is None:
                    continue  # this should not happen given Decrypt succeeded, but whatever
                store.add_with_cipher(
                    bucket, unenc_path, enc_path, key, base.path_cipher
                )
            except Exception as wtf:
                # storj/common ignores prefixes that fail to be added
                pass

        return store

    def to_proto(self) -> encryption_access_pb2.EncryptionAccess:
        enc_access = encryption_access_pb2.EncryptionAccess()

        def append(
            bucket: bytes,
            unenc: Unencrypted,
            enc: Encrypted,
            key: Key,
            path_cipher: storj.CipherSuite,
        ) -> None:
            store_entry = encryption_access_pb2.EncryptionAccess.StoreEntry()
            store_entry.bucket = bucket
            store_entry.unencrypted_path = unenc.raw
            store_entry.encrypted_path = enc.raw
            store_entry.key = bytes(key)
            store_entry.path_cipher = encryption_pb2.CipherSuite.ValueType(path_cipher)
            enc_access.store_entries.append(store_entry)

        self._store.iterate_with_cipher(append)

        if self.default_key is not None:
            enc_access.default_key = bytes(self.default_key)
        enc_access.default_path_cipher = encryption_pb2.CipherSuite.ValueType(
            self._store.default_path_cipher
        )
        return enc_access


def collapse_prefixes(mac: Macaroon) -> tuple[list[CaveatPath], bool]:
    def is_allowed_by_group(cav: CaveatPath, group: Sequence[CaveatPath]) -> bool:
        for other in group:
            if cav.bucket == other.bucket and cav.encrypted_path_prefix.startswith(
                other.encrypted_path_prefix
            ):
                return True
        return False

    def is_allowed_by_groups(
        cav: CaveatPath, groups: list[Sequence[CaveatPath]]
    ) -> bool:
        for group in groups:
            if not is_allowed_by_group(cav, group):
                return False
        return True

    groups: list[Sequence[CaveatPath]] = []
    prefixes: list[CaveatPath] = []
    for cav_data in mac.caveats:
        cav = Caveat()
        cav.ParseFromString(cav_data)
        if len(cav.allowed_paths) > 0:
            groups.append(cav.allowed_paths)
            prefixes.extend(cav.allowed_paths)

    if len(groups) == 0 or len(prefixes) == 0:
        return [], False

    j = 0
    for prefix in prefixes:
        if not is_allowed_by_groups(prefix, groups):
            continue
        prefixes[j] = prefix
        j += 1
    return prefixes[:j], True
