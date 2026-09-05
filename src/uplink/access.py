# Copyright (C) 2023 Storj Labs, Inc.
# See LICENSE for copying information.

from collections.abc import Sequence
import hashlib
import hmac
from uplink.common import grant
from uplink.common import encryption
from uplink.common import macaroon
from uplink.common import metainfo
from uplink.common import paths
from uplink.common.storj import NodeURL
from uplink.common.storj import CipherSuite, Key
from uplink.common import rpc


def parse_access(access_value: str) -> "Access":
    if not access_value:
        raise ValueError("access is empty or None")
    try:
        inner = grant.Access.parse(access_value)
        return Access._from_internal(inner)
    except ValueError as e:
        raise ValueError(f"access is malformed: {e}")


def parse_node_url(address: str) -> NodeURL:
    if not address:
        raise ValueError("node URL is empty or None")

    node_url = NodeURL.parse(address)
    if node_url.id is None:
        node_id = rpc.known_node_id(node_url.address)
        if node_id is None:
            raise ValueError("node id is required in node URL")
        node_url.id = node_id

    return node_url


def request_access_with_passphrase(
    satellite_address: str, api_key: str, passphrase: str
) -> "Access":
    return Config().request_access_with_passphrase(
        satellite_address, api_key, passphrase
    )


class Config:
    def __init__(
        self,
        user_agent: str = "",
        dial_timeout: float = 20.0,
        disable_object_key_encryption: bool = False,
    ) -> None:
        if dial_timeout <= 0:
            raise ValueError("dial timeout must be positive")
        self.user_agent = user_agent
        self.dial_timeout = dial_timeout
        self.disable_object_key_encryption = disable_object_key_encryption

    def request_access_with_passphrase(
        self, satellite_address: str, api_key: str, passphrase: str
    ) -> "Access":
        try:
            parsed_api_key = macaroon.APIKey.parse(api_key)
            satellite_url = parse_node_url(satellite_address)
        except ValueError as exc:
            raise ValueError(f"access request is malformed: {exc}") from exc

        salt = metainfo.project_salt(
            satellite_url,
            parsed_api_key.serialize_raw(),
            self.user_agent,
            self.dial_timeout,
        )
        try:
            key = _derive_root_key(passphrase, salt)
        except Exception as exc:
            raise ValueError("could not derive access root key") from exc
        enc_access = grant.EncryptionAccess(key)
        enc_access.default_path_cipher = (
            CipherSuite.ENC_NULL
            if self.disable_object_key_encryption
            else CipherSuite.ENC_AESGCM
        )
        enc_access.limit_to(parsed_api_key)
        return Access(satellite_url, parsed_api_key, enc_access)


def _derive_root_key(passphrase: str, project_salt: bytes) -> Key:
    from argon2.low_level import Type, hash_secret_raw

    password = passphrase.encode()
    mixed_salt = hmac.new(password, project_salt, hashlib.sha256).digest()
    path_salt = hmac.new(mixed_salt, b"", hashlib.sha256).digest()
    return Key(
        hash_secret_raw(
            password,
            path_salt,
            time_cost=1,
            memory_cost=65536,
            parallelism=8,
            hash_len=32,
            type=Type.ID,
            version=19,
        )
    )


class Access:
    __slots__ = ["_satellite_url", "_api_key", "_enc_access"]

    def __init__(
        self,
        satellite_url: NodeURL,
        api_key: macaroon.APIKey,
        enc_access: grant.EncryptionAccess,
    ) -> None:
        self._satellite_url = satellite_url
        self._api_key = api_key
        self._enc_access = enc_access

    @property
    def satellite_url(self) -> NodeURL:
        return self._satellite_url

    @property
    def api_key(self) -> macaroon.APIKey:
        return self._api_key

    @property
    def enc_access(self) -> grant.EncryptionAccess:
        return self._enc_access

    def share(
        self,
        permission: grant.Permission,
        prefixes: Sequence[grant.SharePrefix] = [],
    ) -> "Access":
        return Access._from_internal(self._to_internal().restrict(permission, prefixes))

    def serialize(self) -> str:
        return self._to_internal().serialize()

    def override_encryption_key(
        self, bucket: bytes, prefix: bytes, encryption_key: Key
    ) -> None:
        if not prefix.endswith(b"/"):
            raise ValueError("prefix must end with slash")

        unencrypted = paths.Unencrypted(prefix.removesuffix(b"/"))
        store = self.enc_access.store
        encrypted = encryption.encrypt_path_with_store_cipher(
            bucket, unencrypted, store
        )
        store.add(bucket, unencrypted, encrypted, encryption_key)

    def _to_internal(self) -> grant.Access:
        return grant.Access(
            satellite_address=str(self._satellite_url),
            api_key=self._api_key,
            enc_access=self._enc_access,
        )

    @staticmethod
    def _from_internal(inner: grant.Access) -> "Access":
        satellite_url = parse_node_url(inner.satellite_address)
        return Access(
            satellite_url=satellite_url,
            api_key=inner.api_key,
            enc_access=inner.enc_access,
        )
