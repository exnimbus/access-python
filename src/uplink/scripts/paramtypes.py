# Copyright (C) 2023 Storj Labs, Inc.
# See LICENSE for copying information.

import datetime

import click

from uplink.common import grant
from .location import Location


class SharePrefix(click.ParamType[grant.SharePrefix]):
    name = "prefix"

    def convert(
        self,
        value: object,
        param: click.Parameter | None,
        ctx: click.Context | None,
    ) -> grant.SharePrefix:
        if isinstance(value, grant.SharePrefix):
            return value
        if not isinstance(value, str):
            raise ValueError("invalid prefix: expected text")
        loc = Location.parse(value)
        bucket, key, ok = loc.remote_parts()
        if not ok:
            raise ValueError(f"invalid prefix: must be remote: {loc}")
        return grant.SharePrefix(bucket.encode(), key.encode())


class HumanDateNotBefore(click.ParamType[datetime.datetime]):
    name = "not_before"

    def convert(
        self,
        value: object,
        param: click.Parameter | None,
        ctx: click.Context | None,
    ) -> datetime.datetime:
        return _convert_human_date(value, False)


class HumanDateNotAfter(click.ParamType[datetime.datetime]):
    name = "not_after"

    def convert(
        self,
        value: object,
        param: click.Parameter | None,
        ctx: click.Context | None,
    ) -> datetime.datetime:
        return _convert_human_date(value, True)


class Duration(click.ParamType[datetime.timedelta]):
    name = "duration"

    def convert(
        self,
        value: object,
        param: click.Parameter | None,
        ctx: click.Context | None,
    ) -> datetime.timedelta:
        if isinstance(value, datetime.timedelta):
            return value
        raise Exception("not implemented yet")


def _convert_human_date(value: object, ceil: bool) -> datetime.datetime:
    if isinstance(value, datetime.datetime):
        return value
    raise Exception("not implemented yet")
