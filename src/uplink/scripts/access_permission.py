# Copyright (C) 2023 Storj Labs, Inc.
# See LICENSE for copying information.

from collections.abc import Callable
import click
from uplink import Access
from uplink.common import grant
from datetime import datetime, timedelta
from .paramtypes import SharePrefix, HumanDateNotBefore, HumanDateNotAfter, Duration


def access_permission_options(
    function: Callable[..., None],
) -> Callable[..., None]:
    function = click.option(
        "--max-object-ttl",
        type=Duration(),
        help="The object is automatically deleted after this period",
    )(function)
    function = click.option(
        "--not-after", type=HumanDateNotAfter(), help="Disallow access after this time"
    )(function)
    function = click.option(
        "--not-before",
        type=HumanDateNotBefore(),
        help="Disallow access before this time",
    )(function)
    function = click.option(
        "--disallow-writes", type=click.BOOL, help="Disallow writes with the access"
    )(function)
    function = click.option(
        "--disallow-reads", type=click.BOOL, help="Disallow reads with the access"
    )(function)
    function = click.option(
        "--disallow-lists", type=click.BOOL, help="Disallow lists with the access"
    )(function)
    function = click.option(
        "--disallow-deletes", type=click.BOOL, help="Disallow deletes with the access"
    )(function)
    function = click.option(
        "--writeonly",
        type=click.BOOL,
        help="Implies --disallow-reads and --disallow-lists",
    )(function)
    function = click.option(
        "--readonly",
        type=click.BOOL,
        default=True,
        help="Implies --disallow-writes and --disallow-deletes",
    )(function)
    function = click.option(
        "--prefix",
        "prefixes",
        type=SharePrefix(),
        multiple=True,
        help="Key prefix access will be restricted to",
    )(function)
    return function


class AccessPermission:
    __slots__ = [
        "_prefixes",
        "_readonly",
        "_writeonly",
        "_disallow_deletes",
        "_disallow_lists",
        "_disallow_reads",
        "_disallow_writes",
        "_not_before",
        "_not_after",
        "_max_object_ttl",
    ]

    def __init__(
        self,
        prefixes: list[grant.SharePrefix] | tuple[grant.SharePrefix, ...] | None = None,
        readonly: bool = False,
        writeonly: bool = False,
        disallow_deletes: bool = False,
        disallow_lists: bool = False,
        disallow_reads: bool = False,
        disallow_writes: bool = False,
        not_before: datetime | None = None,
        not_after: datetime | None = None,
        max_object_ttl: timedelta | None = None,
    ) -> None:
        self._prefixes = prefixes or []
        self._readonly = readonly
        self._writeonly = writeonly
        self._disallow_deletes = disallow_deletes
        self._disallow_lists = disallow_lists
        self._disallow_reads = disallow_reads
        self._disallow_writes = disallow_writes
        self._not_before = not_before
        self._not_after = not_after
        self._max_object_ttl = max_object_ttl

    @property
    def prefixes(self) -> list[grant.SharePrefix] | tuple[grant.SharePrefix, ...]:
        return self._prefixes

    @property
    def not_before(self) -> datetime | None:
        return self._not_before

    @property
    def not_after(self) -> datetime | None:
        return self._not_after

    @property
    def allow_delete(self) -> bool:
        return not (self._disallow_deletes or self._readonly)

    @property
    def allow_list(self) -> bool:
        return not (self._disallow_lists or self._writeonly)

    @property
    def allow_download(self) -> bool:
        return not (self._disallow_reads or self._writeonly)

    @property
    def allow_upload(self) -> bool:
        return not (self._disallow_writes or self._readonly)

    @property
    def max_object_ttl(self) -> timedelta | None:
        return self._max_object_ttl

    def apply(self, access: Access) -> Access:
        permission = grant.Permission(
            allow_delete=self.allow_delete,
            allow_list=self.allow_list,
            allow_download=self.allow_download,
            allow_upload=self.allow_upload,
            not_before=self.not_before,
            not_after=self.not_after,
            max_object_ttl=self.max_object_ttl,
        )

        if (
            not permission.restricted
            and len(self.prefixes) == 0
            and self.not_before is None
            and self.not_after is None
            and self.max_object_ttl is None
        ):
            return access

        return access.share(permission, self.prefixes)
