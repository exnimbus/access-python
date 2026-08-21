# Copyright (C) 2023 Storj Labs, Inc.
# See LICENSE for copying information.


from datetime import datetime, timedelta
from typing import Optional


class Permission:
    __slots__ = [
        "allow_delete",
        "allow_list",
        "allow_download",
        "allow_upload",
        "not_before",
        "not_after",
        "max_object_ttl",
    ]

    def __init__(
        self,
        allow_delete: bool = False,
        allow_list: bool = False,
        allow_download: bool = False,
        allow_upload: bool = False,
        not_before: Optional[datetime] = None,
        not_after: Optional[datetime] = None,
        max_object_ttl: Optional[timedelta] = None,
    ) -> None:
        self.allow_delete = allow_delete
        self.allow_list = allow_list
        self.allow_download = allow_download
        self.allow_upload = allow_upload
        self.not_before = not_before
        self.not_after = not_after
        self.max_object_ttl = max_object_ttl

    @property
    def restricted(self) -> bool:
        return not (
            self.allow_delete
            and self.allow_list
            and self.allow_download
            and self.allow_upload
        )
