# Copyright (C) 2023 Storj Labs, Inc.
# See LICENSE for copying information.

import pytest

from uplink.edge import ShareURLOptions, join_share_url

ACCESS_KEY_ID = "aaaaaaaaaaaaaaaaaaaaaaaaaaaa"


@pytest.mark.parametrize(
    "base_url,bucket,key,options,expected",
    [
        (
            "https://linksharing.test",
            "",
            "",
            None,
            f"https://linksharing.test/s/{ACCESS_KEY_ID}",
        ),
        (
            "https://linksharing.test/",
            "mybucket",
            "",
            None,
            f"https://linksharing.test/s/{ACCESS_KEY_ID}/mybucket",
        ),
        (
            "https://linksharing.test/base/path/",
            "mybucket",
            "my/prefix/",
            None,
            f"https://linksharing.test/base/path/s/{ACCESS_KEY_ID}/mybucket/my/prefix/",
        ),
        (
            "https://linksharing.test",
            "my bucket",
            "a\x00/final?#",
            None,
            f"https://linksharing.test/s/{ACCESS_KEY_ID}/my%20bucket/a%00/final%3F%23",
        ),
        (
            "https://linksharing.test",
            "mybucket",
            "myobject",
            ShareURLOptions(raw=True),
            f"https://linksharing.test/raw/{ACCESS_KEY_ID}/mybucket/myobject",
        ),
    ],
)
def test_join_share_url(
    base_url: str,
    bucket: str,
    key: str,
    options: ShareURLOptions | None,
    expected: str,
) -> None:
    assert join_share_url(base_url, ACCESS_KEY_ID, bucket, key, options) == expected


@pytest.mark.parametrize(
    "base_url,access_key_id,bucket,key,options,error",
    [
        ("", ACCESS_KEY_ID, "", "", None, "invalid base URL"),
        (
            "linksharing.test",
            ACCESS_KEY_ID,
            "",
            "",
            None,
            "invalid base URL",
        ),
        (
            "https://linksharing.test",
            "",
            "",
            "",
            None,
            "access_key_id is required",
        ),
        (
            "https://linksharing.test",
            ACCESS_KEY_ID,
            "",
            "myobject",
            None,
            "bucket is required if key is specified",
        ),
        (
            "https://linksharing.test",
            ACCESS_KEY_ID,
            "mybucket",
            "",
            ShareURLOptions(raw=True),
            "key is required for a raw download link",
        ),
        (
            "https://linksharing.test",
            ACCESS_KEY_ID,
            "mybucket",
            "myprefix/",
            ShareURLOptions(raw=True),
            "a raw download link can not be a prefix",
        ),
    ],
)
def test_join_share_url_rejects_invalid_input(
    base_url: str,
    access_key_id: str,
    bucket: str,
    key: str,
    options: ShareURLOptions | None,
    error: str,
) -> None:
    with pytest.raises(ValueError, match=error):
        join_share_url(base_url, access_key_id, bucket, key, options)
