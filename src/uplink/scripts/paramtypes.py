# Copyright (C) 2023 Storj Labs, Inc.
# See LICENSE for copying information.

import datetime
import re

import click

from uplink.common import grant
from .location import Location


class SharePrefix(click.ParamType[grant.SharePrefix]):  # type: ignore[type-arg]
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
            self.fail("expected text", param, ctx)
        try:
            loc = Location.parse(value)
        except ValueError as error:
            self.fail(str(error), param, ctx)
        bucket, key, ok = loc.remote_parts()
        if not ok:
            self.fail(f"must be remote: {loc}", param, ctx)
        return grant.SharePrefix(bucket.encode(), key.encode())


class HumanDateNotBefore(
    click.ParamType[datetime.datetime | None]  # type: ignore[type-arg]
):
    name = "not_before"

    def convert(
        self,
        value: object,
        param: click.Parameter | None,
        ctx: click.Context | None,
    ) -> datetime.datetime | None:
        try:
            return _convert_human_date(value, False)
        except (OverflowError, TypeError, ValueError) as error:
            self.fail(str(error), param, ctx)


class HumanDateNotAfter(
    click.ParamType[datetime.datetime | None]  # type: ignore[type-arg]
):
    name = "not_after"

    def convert(
        self,
        value: object,
        param: click.Parameter | None,
        ctx: click.Context | None,
    ) -> datetime.datetime | None:
        try:
            return _convert_human_date(value, True)
        except (OverflowError, TypeError, ValueError) as error:
            self.fail(str(error), param, ctx)


class Duration(click.ParamType[datetime.timedelta]):  # type: ignore[type-arg]
    name = "duration"

    def convert(
        self,
        value: object,
        param: click.Parameter | None,
        ctx: click.Context | None,
    ) -> datetime.timedelta:
        if isinstance(value, datetime.timedelta):
            return value
        try:
            return _parse_duration(value)
        except (OverflowError, TypeError, ValueError) as error:
            self.fail(str(error), param, ctx)


_DURATION_PART = re.compile(r"(\d+(?:\.\d*)?|\.\d+)(ns|us|µs|μs|ms|s|m|h)")
_DURATION_UNITS = {
    "ns": 1e-9,
    "us": 1e-6,
    "µs": 1e-6,
    "μs": 1e-6,
    "ms": 1e-3,
    "s": 1,
    "m": 60,
    "h": 3600,
}
_RFC3339 = re.compile(
    r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})"
)


def _parse_duration(value: object) -> datetime.timedelta:
    if not isinstance(value, str):
        raise TypeError("expected text")
    if value == "0":
        return datetime.timedelta()

    sign = -1 if value.startswith("-") else 1
    unsigned = value[1:] if value.startswith(("+", "-")) else value
    parts = list(_DURATION_PART.finditer(unsigned))
    if not parts or "".join(match.group(0) for match in parts) != unsigned:
        raise ValueError(f"invalid duration: {value!r}")
    seconds = sum(
        float(match.group(1)) * _DURATION_UNITS[match.group(2)] for match in parts
    )
    return datetime.timedelta(seconds=sign * seconds)


def _convert_human_date(value: object, ceil: bool) -> datetime.datetime | None:
    if isinstance(value, datetime.datetime):
        return value
    if not isinstance(value, str):
        raise TypeError("expected text")
    if value in ("", "none"):
        return None

    now = datetime.datetime.now().astimezone()
    if value == "now":
        return now
    if re.fullmatch(r"[+-]\d+d", value):
        return now + datetime.timedelta(days=int(value[:-1]))
    if value.startswith(("+", "-")):
        return now + _parse_duration(value)

    if _RFC3339.fullmatch(value):
        return datetime.datetime.fromisoformat(value)

    for format, resolution in (
        ("%Y-%m-%dT%H:%M:%S", datetime.timedelta(seconds=1)),
        ("%Y-%m-%dT%H:%M", datetime.timedelta(minutes=1)),
        ("%Y-%m-%d", datetime.timedelta(days=1)),
    ):
        try:
            parsed = datetime.datetime.strptime(value, format).astimezone()
        except ValueError:
            continue
        return parsed + resolution - datetime.timedelta.resolution if ceil else parsed

    try:
        return now + _parse_duration(value)
    except ValueError:
        raise ValueError(f"invalid date: {value!r}") from None
