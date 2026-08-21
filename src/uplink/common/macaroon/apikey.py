# Copyright (C) 2023 Storj Labs, Inc.
# See LICENSE for copying information.

from __future__ import annotations

import os
from enum import Enum
from uplink.common import base58
from datetime import datetime
from google.protobuf.timestamp_pb2 import Timestamp
from .macaroon import Macaroon, new_unrestricted
from .caveat import Caveat


class UnauthorizedError(Exception):
    pass


class ActionType(Enum):
    ACTION_UNSPECIFIED = 0
    ACTION_READ = 1
    ACTION_WRITE = 2
    ACTION_LIST = 3
    ACTION_DELETE = 4
    ACTION_PROJECT_INFO = 5


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
        data, version = base58.check_decode(key)
        if version != 0:
            raise ValueError("invalid api key format")
        return APIKey.parse_raw(data)

    @staticmethod
    def parse_raw(data: bytes) -> APIKey:
        mac = Macaroon.parse(data)
        return APIKey(mac=mac)

    def serialize_raw(self) -> bytes:
        return self.mac.serialize()

    def restrict(self, caveat: Caveat) -> APIKey:
        caveat_bytes = caveat.SerializeToString()
        mac = self.mac.add_first_party_caveat(caveat_bytes)
        return APIKey(mac)

    # TODO: implement revoker
    def check(self, secret: bytes, action: Action) -> None:
        ok, tails = self.mac.validate_and_tails(secret)
        if not ok:
            raise ValueError("macaroon unauthorized")

        if action.time is None:
            raise ValueError("no timestamp provided")

        for caveat in self.mac.caveats:
            cav = Caveat()
            cav.ParseFromString(caveat)
            if not caveat_allows(cav, action):
                raise UnauthorizedError("action disallowed")

        # TODO: implement revoker?


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
