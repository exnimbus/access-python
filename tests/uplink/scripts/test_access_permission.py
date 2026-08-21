# Copyright (C) 2023 Storj Labs, Inc.
# See LICENSE for copying information.

from datetime import datetime, timedelta
from typing import Any
from unittest.mock import Mock

import pytest

from uplink.common import grant
from uplink.scripts.access_permission import AccessPermission


@pytest.mark.parametrize(
    "options, expected",
    [
        ({"disallow_writes": True}, (True, True, True, False)),
        ({"disallow_deletes": True}, (False, True, True, True)),
        ({"readonly": True}, (False, True, True, False)),
        ({"writeonly": True}, (True, False, False, True)),
        ({"readonly": True, "writeonly": True}, (False, False, False, False)),
    ],
)
def test_permission_mappings(
    options: Any, expected: tuple[bool, bool, bool, bool]
) -> None:
    # Pytest supplies dynamically shaped keyword dictionaries at this boundary.
    permission = AccessPermission(**options)

    assert (
        permission.allow_delete,
        permission.allow_list,
        permission.allow_download,
        permission.allow_upload,
    ) == expected


@pytest.mark.parametrize(
    "name, value",
    [
        ("not_before", datetime(2023, 1, 1)),
        ("not_after", datetime(2023, 1, 2)),
        ("max_object_ttl", timedelta(hours=1)),
    ],
)
def test_apply_time_or_ttl_only_restriction(
    name: str, value: datetime | timedelta
) -> None:
    # Mock call results are intentionally dynamic at this test boundary.
    access: Any = Mock()

    options: dict[str, Any] = {name: value}
    result: Any = AccessPermission(**options).apply(access)

    permission: grant.Permission
    prefixes: list[grant.SharePrefix]
    permission, prefixes = access.share.call_args.args
    assert result is access.share.return_value
    assert (
        permission.allow_delete,
        permission.allow_list,
        permission.allow_download,
        permission.allow_upload,
    ) == (True, True, True, True)
    actual: datetime | timedelta | None = {
        "not_before": permission.not_before,
        "not_after": permission.not_after,
        "max_object_ttl": permission.max_object_ttl,
    }[name]
    assert actual == value
    assert prefixes == []


def test_apply_genuinely_unrestricted_request_is_noop() -> None:
    # Mock methods are intentionally dynamic at this test boundary.
    access: Any = Mock()

    assert AccessPermission().apply(access) is access
    access.share.assert_not_called()
