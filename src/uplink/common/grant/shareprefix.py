# Copyright (C) 2023 Storj Labs, Inc.
# See LICENSE for copying information.


class SharePrefix:
    __slots__ = ["bucket", "prefix"]

    def __init__(self, bucket: bytes, prefix: bytes) -> None:
        self.bucket = bucket
        self.prefix = prefix
