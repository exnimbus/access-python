# Copyright (C) 2023 Storj Labs, Inc.
# See LICENSE for copying information.

from datetime import datetime, timedelta
from typing import Any
from unittest.mock import Mock

from click.testing import CliRunner
import pytest

from uplink import edge
from uplink.common import grant
from uplink.scripts import main as main_module


def _restricted_access(monkeypatch: pytest.MonkeyPatch) -> Any:
    access: Any = Mock()
    access.share.return_value.serialize.return_value = "restricted"

    def parse_access(value: str) -> Any:
        return access

    monkeypatch.setattr(main_module.uplink, "parse_access", parse_access)
    return access


def test_restrict_parses_dates_duration_and_prefix(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    access = _restricted_access(monkeypatch)

    result = CliRunner().invoke(
        main_module.main,
        [
            "restrict",
            "--access",
            "access",
            "--not-before",
            "2030-02-03T12:13:14+01:00",
            "--not-after",
            "2030-03-31",
            "--max-object-ttl",
            "1h30m",
            "--prefix",
            "sj://widgets/springs",
        ],
    )

    assert result.exit_code == 0
    assert result.output == "restricted\n"
    permission, prefixes = access.share.call_args.args
    assert permission.not_before == datetime.fromisoformat("2030-02-03T12:13:14+01:00")
    assert permission.not_after.strftime("%Y-%m-%dT%H:%M:%S.%f") == (
        "2030-03-31T23:59:59.999999"
    )
    assert permission.max_object_ttl == timedelta(hours=1, minutes=30)
    assert [(prefix.bucket, prefix.prefix) for prefix in prefixes] == [
        (b"widgets", b"springs")
    ]


@pytest.mark.parametrize(
    "value, offset",
    [
        ("now", timedelta()),
        ("+2h", timedelta(hours=2)),
        ("+2d", timedelta(days=2)),
    ],
)
def test_restrict_parses_relative_dates(
    monkeypatch: pytest.MonkeyPatch, value: str, offset: timedelta
) -> None:
    access = _restricted_access(monkeypatch)
    before = datetime.now().astimezone() + offset

    result = CliRunner().invoke(
        main_module.main,
        ["restrict", "--access", "access", "--not-before", value],
    )

    after = datetime.now().astimezone() + offset
    assert result.exit_code == 0
    permission: grant.Permission = access.share.call_args.args[0]
    assert permission.not_before is not None
    assert before <= permission.not_before <= after


def test_restrict_date_only_not_before_starts_at_midnight(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    access = _restricted_access(monkeypatch)

    result = CliRunner().invoke(
        main_module.main,
        ["restrict", "--access", "access", "--not-before", "2030-02-03"],
    )

    assert result.exit_code == 0
    permission: grant.Permission = access.share.call_args.args[0]
    assert permission.not_before is not None
    assert permission.not_before.strftime("%Y-%m-%dT%H:%M:%S.%f") == (
        "2030-02-03T00:00:00.000000"
    )


@pytest.mark.parametrize("value", ["none", ""])
def test_restrict_accepts_explicit_no_limit(
    monkeypatch: pytest.MonkeyPatch, value: str
) -> None:
    access = _restricted_access(monkeypatch)

    result = CliRunner().invoke(
        main_module.main,
        [
            "restrict",
            "--access",
            "access",
            "--not-before",
            value,
            "--not-after",
            value,
        ],
    )

    assert result.exit_code == 0
    permission: grant.Permission = access.share.call_args.args[0]
    assert permission.not_before is None
    assert permission.not_after is None


@pytest.mark.parametrize(
    "option, value",
    [
        ("--not-before", "later"),
        ("--not-after", "2030-99-99"),
        ("--max-object-ttl", "1 hour"),
        ("--max-object-ttl", "+-5s"),
        ("--max-object-ttl", "9" * 400 + "h"),
        ("--prefix", "widgets"),
        ("--prefix", "sj://"),
    ],
)
def test_restrict_reports_invalid_parameters(option: str, value: str) -> None:
    result = CliRunner().invoke(
        main_module.main, ["restrict", "--access", "access", option, value]
    )

    assert result.exit_code == 2
    assert f"Invalid value for '{option}'" in result.output
    assert "Traceback" not in result.output
    assert isinstance(result.exception, SystemExit)


def test_restrict_help_uses_remote_prefixes() -> None:
    result = CliRunner().invoke(main_module.main, ["restrict", "--help"])

    assert result.exit_code == 0
    assert "--prefix=sj://widgets\n" in result.output
    assert "--prefix=sj://widgets/springs\n" in result.output


@pytest.mark.parametrize("profile", [None, "work"])
def test_register_displays_aws_credentials(
    monkeypatch: pytest.MonkeyPatch, profile: str | None
) -> None:
    credentials = edge.Credentials("key", "secret", "https://gateway.example")

    def parse_access(value: str) -> Any:
        return Mock()

    def register_access(*args: Any) -> edge.Credentials:
        return credentials

    monkeypatch.setattr(main_module.uplink, "parse_access", parse_access)
    monkeypatch.setattr(main_module, "_register_access", register_access)
    args = ["register", "--access", "access", "--format", "aws"]
    if profile:
        args.extend(["--aws-profile", profile])

    result = CliRunner().invoke(main_module.main, args)

    assert result.exit_code == 0
    profile_arg = f" --profile {profile}" if profile else ""
    assert (
        f"aws configure{profile_arg} aws_access_key_id key\n"
        f"aws configure{profile_arg} aws_secret_access_key secret\n"
        f"aws configure{profile_arg} s3.endpoint_url https://gateway.example\n"
    ) in result.output
