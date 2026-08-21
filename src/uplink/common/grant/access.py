# Copyright (C) 2023 Storj Labs, Inc.
# See LICENSE for copying information.

from __future__ import annotations

from collections.abc import Sequence
from .encryptionaccess import EncryptionAccess
from .permission import Permission
from .shareprefix import SharePrefix
from uplink.common import base58, storj, paths, macaroon, encryption
from uplink.common.macaroon import APIKey
from uplink.common.pb import scope_pb2, encryption_pb2, encryption_access_pb2
from uplink.common.storj import Key
from google.protobuf.duration_pb2 import Duration
from google.protobuf.timestamp_pb2 import Timestamp
from datetime import datetime, timedelta


class Access:
    __slots__ = ["_satellite_address", "_api_key", "_enc_access"]

    def __init__(
        self, satellite_address: str, api_key: APIKey, enc_access: EncryptionAccess
    ) -> None:
        self._satellite_address = satellite_address
        self._api_key = api_key
        self._enc_access = enc_access

    @property
    def satellite_address(self) -> str:
        return self._satellite_address

    @property
    def api_key(self) -> APIKey:
        return self._api_key

    @property
    def enc_access(self) -> EncryptionAccess:
        return self._enc_access

    @staticmethod
    def parse(access: str) -> Access:
        data, version = base58.check_decode(access)
        if version != 0:
            raise ValueError("invalid access grant format")

        scope = scope_pb2.Scope()
        scope.ParseFromString(data)
        if len(scope.satellite_addr) == 0:
            raise ValueError("access grant is missing satellite address")

        api_key = APIKey.parse_raw(scope.api_key)

        enc_access = _parse_encryption_access_from_proto(scope.encryption_access)
        enc_access.limit_to(api_key)

        return Access(
            satellite_address=scope.satellite_addr,
            api_key=api_key,
            enc_access=enc_access,
        )

    def restrict(
        self, permission: Permission, prefixes: Sequence[SharePrefix] = []
    ) -> Access:
        not_before = permission.not_before
        not_after = permission.not_after

        if not_before is not None and not_after is not None and not_after < not_before:
            raise ValueError("invalid time range")

        if (
            permission.max_object_ttl is not None
            and permission.max_object_ttl <= timedelta()
        ):
            raise ValueError("non-positive ttl period")

        caveat = macaroon.caveat_with_nonce(
            macaroon.Caveat(
                disallow_reads=not permission.allow_download,
                disallow_writes=not permission.allow_upload,
                disallow_lists=not permission.allow_list,
                disallow_deletes=not permission.allow_delete,
                not_before=_opt_timestamp(not_before),
                not_after=_opt_timestamp(not_after),
                max_object_ttl=_opt_duration(permission.max_object_ttl),
            )
        )

        for prefix in prefixes:
            # If the share prefix ends in a `/` we need to remove this final slash.
            # Otherwise, if we the shared prefix is `/bob/`, the encrypted shared
            # prefix results in `enc("")/enc("bob")/enc("")`. This is an incorrect
            # encrypted prefix, what we really want is `enc("")/enc("bob")`.
            unenc_path = paths.Unencrypted(prefix.prefix.removesuffix(b"/"))

            enc_path = encryption.encrypt_path_with_store_cipher(
                prefix.bucket, unenc_path, self.enc_access.store
            )

            caveat_path = macaroon.CaveatPath()
            caveat_path.bucket = prefix.bucket
            caveat_path.encrypted_path_prefix = enc_path.raw
            caveat.allowed_paths.append(caveat_path)

        restricted_api_key = self.api_key.restrict(caveat)

        enc_access = self._enc_access.clone()
        enc_access.limit_to(restricted_api_key)

        return Access(
            satellite_address=self.satellite_address,
            api_key=restricted_api_key,
            enc_access=enc_access,
        )

    def serialize(self) -> str:
        if len(self.satellite_address) == 0:
            raise Exception("access grant is missing satellite address")
        if self.api_key is None:
            raise Exception("access grant is missing api key")
        if self.enc_access is None:
            raise Exception("access grant is missing encryption access")

        enc = self.enc_access.to_proto()

        scope = scope_pb2.Scope()
        scope.satellite_addr = self.satellite_address
        scope.api_key = self._api_key.serialize_raw()
        scope.encryption_access.CopyFrom(enc)

        data = scope.SerializeToString()
        return base58.check_encode(data, 0)


def _parse_encryption_access_from_proto(
    p: encryption_access_pb2.EncryptionAccess,
) -> EncryptionAccess:
    access = EncryptionAccess()
    if len(p.default_key) > 0:
        if len(p.default_key) != storj.KEY_SIZE:
            raise ValueError("invalid default key in encryption access")
        access.default_key = Key(p.default_key)

    # Unspecified cipher suite means that most probably access was serialized
    # before path cipher was moved to encryption access
    if p.default_path_cipher == encryption_pb2.CipherSuite.ENC_UNSPECIFIED:
        access.default_path_cipher = storj.CipherSuite.ENC_AESGCM
    else:
        access.default_path_cipher = storj.CipherSuite(p.default_path_cipher)

    for entry in p.store_entries:
        if len(entry.key) != storj.KEY_SIZE:
            raise ValueError("invalid default key in encryption access entry")
        access.store.add_with_cipher(
            entry.bucket,
            paths.Unencrypted(entry.unencrypted_path),
            paths.Encrypted(entry.encrypted_path),
            Key(entry.key),
            storj.CipherSuite(entry.path_cipher),
        )

    return access


def _opt_timestamp(dt: datetime | None) -> Timestamp | None:
    if dt is None:
        return None
    ts = Timestamp()
    ts.FromDatetime(dt)
    return ts


def _opt_duration(td: timedelta | None) -> Duration | None:
    if td is None:
        return None
    d = Duration()
    d.FromTimedelta(td)
    return d
