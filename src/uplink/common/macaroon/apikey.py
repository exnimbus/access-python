# Copyright (C) 2023 Storj Labs, Inc.
# See LICENSE for copying information.

from __future__ import annotations

from collections.abc import Sequence
from datetime import datetime, timedelta
from enum import Enum, IntFlag
from typing import NamedTuple, Protocol

from uplink.common import base58
from google.protobuf.timestamp_pb2 import Timestamp
from .macaroon import Macaroon, new_unrestricted, new_unrestricted_from_parts
from .caveat import Caveat


class APIKeyError(ValueError):
    pass


class FormatError(APIKeyError):
    pass


class InvalidError(APIKeyError):
    pass


class UnauthorizedError(APIKeyError):
    pass


class RevokedError(APIKeyError):
    pass


class APIKeyVersion(IntFlag):
    MIN = 0
    OBJECT_LOCK = 1
    AUDITABLE = 2
    EVENTING = 4

    def supports_object_lock(self) -> bool:
        return bool(self & APIKeyVersion.OBJECT_LOCK)

    def supports_auditability(self) -> bool:
        return bool(self & APIKeyVersion.AUDITABLE)

    def supports_eventing(self) -> bool:
        return bool(self & APIKeyVersion.EVENTING)


class Revoker(Protocol):
    def check(self, tails: Sequence[bytes]) -> bool:
        ...


class AllowedBuckets(NamedTuple):
    all: bool
    buckets: frozenset[bytes]


class ActionType(Enum):
    # These values are persisted in macaroons, so they must never be renumbered.
    ACTION_UNSPECIFIED = 0
    ACTION_READ = 1
    ACTION_WRITE = 2
    ACTION_LIST = 3
    ACTION_DELETE = 4
    ACTION_PROJECT_INFO = 5
    ACTION_LOCK = 6
    ACTION_PUT_OBJECT_RETENTION = 7
    ACTION_GET_OBJECT_RETENTION = 8
    ACTION_PUT_OBJECT_LEGAL_HOLD = 9
    ACTION_GET_OBJECT_LEGAL_HOLD = 10
    ACTION_BYPASS_GOVERNANCE_RETENTION = 11
    ACTION_PUT_BUCKET_OBJECT_LOCK_CONFIGURATION = 12
    ACTION_GET_BUCKET_OBJECT_LOCK_CONFIGURATION = 13
    ACTION_PUT_BUCKET_NOTIFICATION_CONFIGURATION = 14
    ACTION_GET_BUCKET_NOTIFICATION_CONFIGURATION = 15


class Action:
    __slots__ = ["op", "bucket", "encrypted_path", "time"]

    def __init__(
        self, op: ActionType, bucket: bytes, encrypted_path: bytes, time: datetime
    ) -> None:
        self.op = op
        self.bucket = bucket
        self.encrypted_path = encrypted_path
        self.time = time


class APIKey:
    __slots__ = ["mac"]

    def __init__(self, mac: Macaroon) -> None:
        self.mac = mac

    @staticmethod
    def parse(key: str) -> APIKey:
        try:
            data, version = base58.check_decode(key)
        except Exception as exc:
            raise FormatError("invalid api key format") from exc
        if version != 0:
            raise FormatError("invalid api key format")
        return APIKey.parse_raw(data)

    @staticmethod
    def parse_raw(data: bytes) -> APIKey:
        try:
            mac = Macaroon.parse(data)
        except Exception as exc:
            raise FormatError("invalid api key format") from exc
        return APIKey(mac=mac)

    @staticmethod
    def from_parts(head: bytes, secret: bytes, *caveats: Caveat) -> APIKey:
        api_key = APIKey(new_unrestricted_from_parts(head, secret))
        for caveat in caveats:
            api_key = api_key.restrict(caveat)
        return api_key

    @property
    def head(self) -> bytes:
        return self.mac.head

    @property
    def tail(self) -> bytes:
        return self.mac.tail

    def serialize(self) -> str:
        return base58.check_encode(self.serialize_raw(), 0)

    def serialize_raw(self) -> bytes:
        return self.mac.serialize()

    def restrict(self, caveat: Caveat) -> APIKey:
        caveat_bytes = caveat.SerializeToString()
        mac = self.mac.add_first_party_caveat(caveat_bytes)
        return APIKey(mac)

    def check(
        self,
        secret: bytes,
        action: Action,
        *,
        version: APIKeyVersion = APIKeyVersion.MIN,
        revoker: Revoker | None = None,
    ) -> None:
        """Authorize ``action`` using ``secret``; version and revoker are keyword-only."""
        ok, tails = self.mac.validate_and_tails(secret)
        if not ok:
            raise InvalidError("macaroon unauthorized")

        if action.time is None:
            raise APIKeyError("no timestamp provided")

        if (
            action.op
            in {
                ActionType.ACTION_LOCK,
                ActionType.ACTION_PUT_OBJECT_RETENTION,
                ActionType.ACTION_GET_OBJECT_RETENTION,
                ActionType.ACTION_PUT_OBJECT_LEGAL_HOLD,
                ActionType.ACTION_GET_OBJECT_LEGAL_HOLD,
                ActionType.ACTION_BYPASS_GOVERNANCE_RETENTION,
                ActionType.ACTION_PUT_BUCKET_OBJECT_LOCK_CONFIGURATION,
                ActionType.ACTION_GET_BUCKET_OBJECT_LOCK_CONFIGURATION,
            }
            and not version.supports_object_lock()
        ) or (
            action.op
            in {
                ActionType.ACTION_PUT_BUCKET_NOTIFICATION_CONFIGURATION,
                ActionType.ACTION_GET_BUCKET_NOTIFICATION_CONFIGURATION,
            }
            and not version.supports_eventing()
        ):
            raise UnauthorizedError("action disallowed")

        for cav in self._caveats():
            if not caveat_allows(cav, action):
                raise UnauthorizedError("action disallowed")

        if revoker is not None:
            try:
                revoked = revoker.check(tails)
            except Exception as exc:
                raise RevokedError("revocation check failed") from exc
            if revoked:
                raise RevokedError("contains revoked tail")

    def get_allowed_buckets(self, action: Action) -> AllowedBuckets:
        buckets: frozenset[bytes] | None = None
        for cav in self._caveats():
            if not caveat_allows(cav, action):
                raise UnauthorizedError("action disallowed")
            if cav.allowed_paths:
                caveat_buckets = frozenset(path.bucket for path in cav.allowed_paths)
                buckets = (
                    caveat_buckets if buckets is None else buckets & caveat_buckets
                )
        return AllowedBuckets(buckets is None, buckets or frozenset())

    def get_max_object_ttl(self) -> timedelta | None:
        ttl: timedelta | None = None
        for cav in self._caveats():
            if cav.HasField("max_object_ttl"):
                candidate = cav.max_object_ttl.ToTimedelta()
                if ttl is None or candidate < ttl:
                    ttl = candidate
        return ttl

    def _caveats(self) -> list[Caveat]:
        caveats: list[Caveat] = []
        for data in self.mac.caveats:
            caveat = Caveat()
            try:
                caveat.ParseFromString(data)
            except Exception as exc:
                raise FormatError("invalid caveat format") from exc
            caveats.append(caveat)
        return caveats


def new_api_key(secret: bytes) -> APIKey:
    mac = new_unrestricted(secret)
    return APIKey(mac)


def caveat_allows(c: Caveat, action: Action) -> bool:
    # if the action is after the caveat's "not after" field, then it is invalid
    if is_valid_timestamp(c.not_after) and action.time > c.not_after.ToDatetime():
        return False

    # if the caveat's "not before" field is *after* the action, then the action
    # is before the "not before" field and it is invalid
    if is_valid_timestamp(c.not_before) and c.not_before.ToDatetime() > action.time:
        return False

    # we want to always allow reads for bucket metadata, perhaps filtered by the
    # buckets in the allowed paths.
    if action.op == ActionType.ACTION_READ and len(action.encrypted_path) == 0:
        if len(c.allowed_paths) == 0:
            return True
        if len(action.bucket) == 0:
            # if no action.bucket name is provided, then this call is checking that
            # we can list all buckets. In that case, return true here and we will
            # filter out buckets that aren't allowed later with `GetAllowedBuckets()`
            return True
        for path in c.allowed_paths:
            if path.bucket == action.bucket:
                return True
        return False

    if action.op == ActionType.ACTION_READ:
        if c.disallow_reads:
            return False
    elif action.op == ActionType.ACTION_WRITE:
        if c.disallow_writes:
            return False
    elif action.op == ActionType.ACTION_LIST:
        if c.disallow_lists:
            return False
    elif action.op == ActionType.ACTION_DELETE:
        if c.disallow_deletes:
            return False
    elif action.op == ActionType.ACTION_PROJECT_INFO:
        # allow
        pass
    elif action.op == ActionType.ACTION_LOCK:
        if c.disallow_locks:
            return False
    elif action.op == ActionType.ACTION_PUT_OBJECT_RETENTION:
        if c.disallow_put_retention:
            return False
    elif action.op == ActionType.ACTION_GET_OBJECT_RETENTION:
        # Mirrors storj.io/common/macaroon: reading a retention period is only
        # denied when *both* retention bits are set, so that grants which were
        # allowed to set retention can still read it back.
        if c.disallow_put_retention:
            if c.disallow_get_retention:
                return False
    elif action.op == ActionType.ACTION_PUT_OBJECT_LEGAL_HOLD:
        if c.disallow_put_legal_hold:
            return False
    elif action.op == ActionType.ACTION_GET_OBJECT_LEGAL_HOLD:
        if c.disallow_get_legal_hold:
            return False
    elif action.op == ActionType.ACTION_BYPASS_GOVERNANCE_RETENTION:
        if c.disallow_bypass_governance_retention:
            return False
    elif action.op == ActionType.ACTION_PUT_BUCKET_OBJECT_LOCK_CONFIGURATION:
        if c.disallow_put_bucket_object_lock_configuration:
            return False
    elif action.op == ActionType.ACTION_GET_BUCKET_OBJECT_LOCK_CONFIGURATION:
        if c.disallow_get_bucket_object_lock_configuration:
            return False
    elif action.op == ActionType.ACTION_PUT_BUCKET_NOTIFICATION_CONFIGURATION:
        if c.disallow_put_bucket_notification_configuration:
            return False
    elif action.op == ActionType.ACTION_GET_BUCKET_NOTIFICATION_CONFIGURATION:
        if c.disallow_get_bucket_notification_configuration:
            return False
    else:
        return False

    if len(c.allowed_paths) > 0 and action.op != ActionType.ACTION_PROJECT_INFO:
        found = False
        for path in c.allowed_paths:
            if action.bucket == path.bucket and action.encrypted_path.startswith(
                path.encrypted_path_prefix
            ):
                found = True
                break
        if not found:
            return False

    return True


def is_valid_timestamp(ts: Timestamp | None) -> bool:
    if ts is None:
        return False
    if ts == Timestamp():
        return False
    return True
