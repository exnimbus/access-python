# Copyright (C) 2023 Storj Labs, Inc.
# See LICENSE for copying information.

"""Tests covering the caveat permissions shared with the Storj Go implementation.

The Go reference lives in storj.io/common/macaroon (caveat schema and
Caveat.Allows) and storj.io/common/grant (Permission and Access.Restrict).
"""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime

from google.protobuf.descriptor import FieldDescriptor
import pytest

from uplink.common import macaroon, storj
from uplink.common.grant import Access, EncryptionAccess, Permission
from uplink.common.macaroon import Action, ActionType, UnauthorizedError
from uplink.common.storj import CipherSuite


# Field numbers are part of the wire format and are shared with Go. Field 10 is
# allowed_paths, which is why the disallow bits jump from 9 to 11.
EXPECTED_FIELD_NUMBERS: dict[str, int] = {
    "disallow_reads": 1,
    "disallow_writes": 2,
    "disallow_lists": 3,
    "disallow_deletes": 4,
    "disallow_locks": 5,
    "disallow_put_retention": 6,
    "disallow_get_retention": 7,
    "disallow_put_legal_hold": 8,
    "disallow_get_legal_hold": 9,
    "allowed_paths": 10,
    "disallow_bypass_governance_retention": 11,
    "disallow_put_bucket_object_lock_configuration": 12,
    "disallow_get_bucket_object_lock_configuration": 13,
    "disallow_put_bucket_notification_configuration": 14,
    "disallow_get_bucket_notification_configuration": 15,
    "not_after": 20,
    "not_before": 21,
    "max_object_ttl": 22,
    "nonce": 30,
}

# The permission that grants each newly added action, excluding
# ACTION_GET_OBJECT_RETENTION which has bespoke two-bit handling in Go.
NEW_ACTION_PERMISSIONS: list[tuple[ActionType, Permission]] = [
    (ActionType.ACTION_LOCK, Permission(allow_lock=True)),
    (
        ActionType.ACTION_PUT_OBJECT_RETENTION,
        Permission(allow_put_object_retention=True),
    ),
    (
        ActionType.ACTION_PUT_OBJECT_LEGAL_HOLD,
        Permission(allow_put_object_legal_hold=True),
    ),
    (
        ActionType.ACTION_GET_OBJECT_LEGAL_HOLD,
        Permission(allow_get_object_legal_hold=True),
    ),
    (
        ActionType.ACTION_BYPASS_GOVERNANCE_RETENTION,
        Permission(allow_bypass_governance_retention=True),
    ),
    (
        ActionType.ACTION_PUT_BUCKET_OBJECT_LOCK_CONFIGURATION,
        Permission(allow_put_bucket_object_lock_configuration=True),
    ),
    (
        ActionType.ACTION_GET_BUCKET_OBJECT_LOCK_CONFIGURATION,
        Permission(allow_get_bucket_object_lock_configuration=True),
    ),
    (
        ActionType.ACTION_PUT_BUCKET_NOTIFICATION_CONFIGURATION,
        Permission(allow_put_bucket_notification_configuration=True),
    ),
    (
        ActionType.ACTION_GET_BUCKET_NOTIFICATION_CONFIGURATION,
        Permission(allow_get_bucket_notification_configuration=True),
    ),
]


def new_access() -> tuple[bytes, Access]:
    """Build an unrestricted access grant and return it with its secret."""
    secret = macaroon.new_secret()
    api_key = macaroon.new_api_key(secret)

    enc_access = EncryptionAccess(default_key=storj.new_key())
    enc_access.default_path_cipher = CipherSuite.ENC_NULL

    access = Access(satellite_address="", api_key=api_key, enc_access=enc_access)
    return secret, access


def full_legacy_permission() -> Permission:
    return Permission(
        allow_download=True,
        allow_upload=True,
        allow_list=True,
        allow_delete=True,
    )


def action(op: ActionType) -> Action:
    return Action(
        op,
        bucket=b"bucket",
        encrypted_path=b"prefix/path",
        time=datetime.now(),
    )


def last_caveat(access: Access) -> macaroon.Caveat:
    caveat = macaroon.Caveat()
    caveat.ParseFromString(access.api_key.mac.caveats[-1])
    return caveat


def allows(secret: bytes, access: Access, op: ActionType) -> bool:
    try:
        access.api_key.check(secret, action(op))
    except UnauthorizedError:
        return False
    return True


def test_caveat_field_numbers_match_go() -> None:
    """Field numbers are wire format and must not drift from the Go schema."""
    fields: Mapping[str, FieldDescriptor] = macaroon.Caveat.DESCRIPTOR.fields_by_name

    actual = {name: field.number for name, field in fields.items()}
    assert actual == EXPECTED_FIELD_NUMBERS


def test_restrict_rejects_empty_permission() -> None:
    """Go returns "permission is empty" rather than minting a useless grant."""
    _, access = new_access()

    with pytest.raises(ValueError, match="permission is empty"):
        access.restrict(Permission())


def test_restrict_accepts_permission_with_only_a_time_bound() -> None:
    """Go compares against Permission{}, so a lone time bound is not empty."""
    _, access = new_access()

    # Denies every operation, but it is a legitimate permission rather than an
    # empty one, so it must not trip the empty-permission guard.
    restricted = access.restrict(Permission(not_after=datetime.now()))

    assert last_caveat(restricted).disallow_reads is True


def test_restrict_emits_every_denial_bit() -> None:
    """A legacy-only permission must deny each newer capability explicitly.

    Caveat booleans are proto3 scalars, so an unset field is indistinguishable
    from an explicit allow. Every disallow bit therefore has to be present.
    """
    _, access = new_access()

    restricted = access.restrict(full_legacy_permission())
    caveat = last_caveat(restricted)

    # The four legacy operations were granted.
    assert caveat.disallow_reads is False
    assert caveat.disallow_writes is False
    assert caveat.disallow_lists is False
    assert caveat.disallow_deletes is False

    # Everything added since must be denied, and denied on the wire rather than
    # by protobuf default.
    serialized = caveat.SerializeToString()
    for name in (
        "disallow_locks",
        "disallow_put_retention",
        "disallow_get_retention",
        "disallow_put_legal_hold",
        "disallow_get_legal_hold",
        "disallow_bypass_governance_retention",
        "disallow_put_bucket_object_lock_configuration",
        "disallow_get_bucket_object_lock_configuration",
        "disallow_put_bucket_notification_configuration",
        "disallow_get_bucket_notification_configuration",
    ):
        assert getattr(caveat, name) is True, name

        number = EXPECTED_FIELD_NUMBERS[name]
        # proto3 varint bool: (field_number << 3) | wire type 0, then value 1.
        assert bytes([number << 3, 1]) in serialized, name


@pytest.mark.parametrize("op,permission", NEW_ACTION_PERMISSIONS)
def test_api_key_evaluates_new_action_permissions(
    op: ActionType, permission: Permission
) -> None:
    secret, access = new_access()

    denied = access.restrict(full_legacy_permission())
    assert allows(secret, denied, op) is False

    granted = access.restrict(permission)
    assert allows(secret, granted, op) is True


def test_get_object_retention_follows_go_two_bit_rule() -> None:
    """Go denies reading retention only when both retention bits are set."""
    secret, access = new_access()

    denied = access.restrict(full_legacy_permission())
    assert allows(secret, denied, ActionType.ACTION_GET_OBJECT_RETENTION) is False

    # Either retention grant is enough to read retention back.
    for permission in (
        Permission(allow_put_object_retention=True),
        Permission(allow_get_object_retention=True),
    ):
        granted = access.restrict(permission)
        assert allows(secret, granted, ActionType.ACTION_GET_OBJECT_RETENTION) is True


def test_restricted_child_does_not_inherit_newer_parent_capabilities() -> None:
    """Regression: a child restricted to legacy operations loses Object Lock.

    A parent minted before these capabilities existed carries no opinion about
    them, which historically meant a child silently kept them.
    """
    secret, access = new_access()

    parent = access.restrict(
        Permission(
            allow_download=True,
            allow_upload=True,
            allow_list=True,
            allow_delete=True,
            allow_lock=True,
            allow_put_object_retention=True,
            allow_put_object_legal_hold=True,
            allow_put_bucket_notification_configuration=True,
        )
    )
    assert allows(secret, parent, ActionType.ACTION_LOCK) is True
    assert allows(secret, parent, ActionType.ACTION_PUT_OBJECT_RETENTION) is True

    # The child asks for the legacy operations only.
    child = parent.restrict(full_legacy_permission())

    assert allows(secret, child, ActionType.ACTION_READ) is True
    assert allows(secret, child, ActionType.ACTION_LOCK) is False
    assert allows(secret, child, ActionType.ACTION_PUT_OBJECT_RETENTION) is False
    assert allows(secret, child, ActionType.ACTION_PUT_OBJECT_LEGAL_HOLD) is False
    assert (
        allows(secret, child, ActionType.ACTION_PUT_BUCKET_NOTIFICATION_CONFIGURATION)
        is False
    )


def test_child_cannot_regain_capability_the_parent_denied() -> None:
    """Restriction intersects: asking for more than the parent has is refused."""
    secret, access = new_access()

    parent = access.restrict(full_legacy_permission())
    child = parent.restrict(
        Permission(
            allow_download=True,
            allow_upload=True,
            allow_list=True,
            allow_delete=True,
            allow_lock=True,
        )
    )

    assert allows(secret, child, ActionType.ACTION_LOCK) is False


def test_grants_without_the_new_fields_keep_working() -> None:
    """Caveats serialized before these fields existed must still validate.

    Such a caveat omits the new bits entirely, which decodes as "allowed" and
    preserves the behaviour those older grants were issued with.
    """
    secret, access = new_access()

    legacy_caveat = macaroon.Caveat(
        disallow_reads=False,
        disallow_writes=True,
        disallow_lists=False,
        disallow_deletes=True,
    )
    # Nothing beyond the legacy bits is on the wire.
    serialized = legacy_caveat.SerializeToString()
    for number in list(range(5, 10)) + list(range(11, 16)):
        assert bytes([number << 3, 1]) not in serialized

    restricted_key = access.api_key.restrict(legacy_caveat)

    restricted_key.check(secret, action(ActionType.ACTION_READ))
    with pytest.raises(UnauthorizedError):
        restricted_key.check(secret, action(ActionType.ACTION_WRITE))

    # Absent bits keep their historical meaning rather than failing closed.
    restricted_key.check(secret, action(ActionType.ACTION_LOCK))
