# Copyright (C) 2023 Storj Labs, Inc.
# See LICENSE for copying information.

# The following excerpts are testable examples showing basic library usage.

import pytest
import uplink
from datetime import datetime, timedelta
from uplink.common.grant import Permission
from uplink import edge

EXAMPLE_ACCESS = "15M6fjomdWMwh4cdbZx5YmDQpQsc8EN73sYKcfLodh6yz6PXEbNJe1WKFvKrwMotebVhRWPiihQoPEuKkaEt1reW5WhPwipmRZnqcfnA483LwehmgUdV1wzftUQ7rArkEJNkVCYJXiaUeWMUNmC2qc6y2nv92LCLQTj2ypoLR7A6ua8yzjEcvfdop5yr12yPMesWvwkqMFwc7gi2GJTnaBrhic55aHfk4K7c1dJuhw33VYHZvsiDU1J2RePppMaxbhTen54cGcNB5Dzz76FjJWSesB4JnHPh7"


def test_restrict_readonly_example() -> None:
    """example that restricts an access grant to read-only operations for the next week"""
    now = datetime.now()
    later = now + timedelta(weeks=1)

    permission = Permission(
        allow_delete=False,
        allow_list=True,
        allow_download=True,
        allow_upload=False,
        not_before=now,
        not_after=later,
    )

    access = uplink.parse_access(EXAMPLE_ACCESS)
    restricted = access.share(permission)
    print(restricted.serialize())


def test_restrict_uploadonly_example() -> None:
    """example that restricts an access grant to uploading short-lived operations for the next week"""

    now = datetime.now()
    later = now + timedelta(weeks=1)

    permission = Permission(
        allow_delete=False,
        allow_list=False,
        allow_download=False,
        allow_upload=True,
        not_before=now,
        not_after=later,
        max_object_ttl=timedelta(hours=1),
    )

    access = uplink.parse_access(EXAMPLE_ACCESS)
    restricted = access.share(permission)
    print(restricted.serialize())


@pytest.mark.skip("Skipped because this example registers with an external service")
def test_register_example() -> None:
    # The edge service to register with
    auth_service_url = "https://auth.storjshare.io"

    # Whether or not the share should be public
    public = False

    access = uplink.parse_access(EXAMPLE_ACCESS)
    config = edge.Config(auth_service_url)
    credentials = config.register_access(
        access, edge.RegisterAccessOptions(public=public)
    )

    print(f"Access Key ID    : {credentials.access_key_id}")
    print(f"Secret Access Key: {credentials.secret_key}")
    print(f"Endpoint          : {credentials.endpoint}")
