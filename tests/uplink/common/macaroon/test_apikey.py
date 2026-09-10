# Copyright (C) 2026 Storj Labs, Inc.
# See LICENSE for copying information.

from datetime import UTC, datetime, timedelta
from collections.abc import Sequence

import pytest
from google.protobuf.duration_pb2 import Duration

from uplink.common.macaroon import (
    APIKey,
    APIKeyError,
    APIKeyVersion,
    Action,
    ActionType,
    Caveat,
    CaveatPath,
    FormatError,
    InvalidError,
    RevokedError,
    UnauthorizedError,
    new_api_key,
)


SECRET = b"s" * 32
ACTION_TIME = datetime.now()


def action(
    op: ActionType = ActionType.ACTION_READ, time: datetime | None = ACTION_TIME
) -> Action:
    return Action(op, b"bucket", b"path", time)  # type: ignore[arg-type]


def test_versions_and_gates() -> None:
    assert APIKeyVersion.MIN == 0
    assert APIKeyVersion.OBJECT_LOCK == 1
    assert APIKeyVersion.AUDITABLE == 2
    assert APIKeyVersion.EVENTING == 4
    assert APIKeyVersion.OBJECT_LOCK.supports_object_lock()
    assert not APIKeyVersion.AUDITABLE.supports_object_lock()
    assert APIKeyVersion.AUDITABLE.supports_auditability()
    assert APIKeyVersion.EVENTING.supports_eventing()
    assert (APIKeyVersion.OBJECT_LOCK | APIKeyVersion.EVENTING).supports_eventing()

    key = new_api_key(SECRET)
    for op in list(ActionType)[6:14]:
        with pytest.raises(UnauthorizedError):
            key.check(SECRET, action(op))
        key.check(SECRET, action(op), version=APIKeyVersion.OBJECT_LOCK)
    for op in list(ActionType)[14:16]:
        with pytest.raises(UnauthorizedError):
            key.check(SECRET, action(op))
        key.check(SECRET, action(op), version=APIKeyVersion.EVENTING)
    key.check(SECRET, action())
    with pytest.raises(TypeError):
        key.check(SECRET, action(), APIKeyVersion.MIN)  # type: ignore[call-arg]


def test_errors_and_revoker_tails() -> None:
    key = new_api_key(SECRET)
    with pytest.raises(FormatError):
        APIKey.parse("not an api key")
    with pytest.raises(FormatError):
        APIKey.parse_raw(b"bad")
    with pytest.raises(InvalidError):
        key.check(b"x" * 32, action())
    with pytest.raises(APIKeyError):
        key.check(SECRET, action(time=None))
    with pytest.raises(UnauthorizedError):
        key.check(SECRET, action(ActionType.ACTION_LOCK))

    restricted = key.restrict(Caveat(disallow_reads=True))
    seen: list[bytes] = []

    class Recorder:
        def check(self, tails: Sequence[bytes]) -> bool:
            seen.extend(tails)
            return False

    restricted.check(SECRET, action(ActionType.ACTION_WRITE), revoker=Recorder())
    assert seen == [key.tail, restricted.tail]

    class Broken:
        def check(self, tails: Sequence[bytes]) -> bool:
            raise RuntimeError("unavailable")

    with pytest.raises(RevokedError) as exc_info:
        key.check(SECRET, action(), revoker=Broken())
    assert isinstance(exc_info.value.__cause__, RuntimeError)

    class Revoked:
        def check(self, tails: Sequence[bytes]) -> bool:
            return True

    with pytest.raises(RevokedError):
        key.check(SECRET, action(), revoker=Revoked())


def test_inspection_and_serialization() -> None:
    key = APIKey.from_parts(b"head", SECRET)
    assert key.head == b"head"
    assert APIKey.parse(key.serialize()).serialize_raw() == key.serialize_raw()
    assert APIKey.parse_raw(key.serialize_raw()).tail == key.tail

    first = Caveat()
    first.allowed_paths.extend(
        [
            CaveatPath(bucket=b"a"),
            CaveatPath(bucket=b"a"),
            CaveatPath(bucket=b"b"),
        ]
    )
    second = Caveat()
    second.allowed_paths.extend([CaveatPath(bucket=b"b"), CaveatPath(bucket=b"c")])
    restricted = key.restrict(first).restrict(second)
    bucket_listing = Action(ActionType.ACTION_READ, b"", b"", ACTION_TIME)
    assert key.get_allowed_buckets(bucket_listing) == (True, frozenset())
    assert restricted.get_allowed_buckets(bucket_listing) == (False, frozenset({b"b"}))
    with pytest.raises(UnauthorizedError):
        key.restrict(Caveat(disallow_reads=True)).get_allowed_buckets(action())

    empty = key.restrict(Caveat(allowed_paths=[CaveatPath(bucket=b"a")])).restrict(
        Caveat(allowed_paths=[CaveatPath(bucket=b"b")])
    )
    assert empty.get_allowed_buckets(action(ActionType.ACTION_PROJECT_INFO)) == (
        False,
        frozenset(),
    )

    short = Caveat(max_object_ttl=Duration(seconds=1))
    long = Caveat(max_object_ttl=Duration(seconds=2))
    assert key.get_max_object_ttl() is None
    assert key.restrict(long).restrict(short).get_max_object_ttl() == timedelta(
        seconds=1
    )


def test_large_caveat_round_trip() -> None:
    key = new_api_key(SECRET).restrict(Caveat(nonce=b"x" * 300))
    assert APIKey.parse_raw(key.serialize_raw()).tail == key.tail


def test_timezone_aware_action() -> None:
    expires = datetime.now(UTC) + timedelta(minutes=1)
    caveat = Caveat()
    caveat.not_after.FromDatetime(expires)
    new_api_key(SECRET).restrict(caveat).check(SECRET, action(time=datetime.now(UTC)))
