# Copyright (C) 2023 Storj Labs, Inc.
# See LICENSE for copying information.

from re import search
from typing import Optional
from urllib.parse import quote, urlsplit, urlunsplit


class ShareURLOptions:
    __slots__ = ["raw"]

    def __init__(self, raw: bool = False) -> None:
        self.raw = raw


def join_share_url(
    base_url: str,
    access_key_id: str,
    bucket: str = "",
    key: str = "",
    options: Optional[ShareURLOptions] = None,
) -> str:
    if access_key_id == "":
        raise ValueError("access_key_id is required")
    if bucket == "" and key != "":
        raise ValueError("bucket is required if key is specified")

    options = options or ShareURLOptions()
    if options.raw:
        if key == "":
            raise ValueError("key is required for a raw download link")
        if key.endswith("/"):
            raise ValueError("a raw download link can not be a prefix")

    try:
        parsed = urlsplit(base_url)
    except ValueError:
        raise ValueError(f"invalid base URL: {base_url!r}") from None
    if (
        not parsed.scheme
        or not parsed.netloc
        or search(r"%(?![0-9A-Fa-f]{2})", base_url)
    ):
        raise ValueError(f"invalid base URL: {base_url!r}")

    parts = ["raw" if options.raw else "s", quote(access_key_id, safe="")]
    if bucket:
        parts.append(quote(bucket, safe=""))
    if key:
        parts.append(quote(key, safe="/"))

    base_path = quote(parsed.path.rstrip("/"), safe="/%:@&=+$,;")
    path = f"{base_path}/{'/'.join(parts)}"
    return urlunsplit(
        (parsed.scheme, parsed.netloc, path, parsed.query, parsed.fragment)
    )
