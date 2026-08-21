# Copyright (C) 2023 Storj Labs, Inc.
# See LICENSE for copying information.

import pytest
import uplink
from uplink.common import base58, grant, macaroon, rpc
from uplink.common.grant import EncryptionAccess
from uplink.common.storj import Key, NodeURL, node_id_from_string


KNOWN_NODES = [
    (
        "12EayRS2V1kEsWESU9QMRseFhdxYxKicsiFmxrsLZHeLUtdps3S",
        "us-central-1.tardigrade.io",
    ),
    (
        "12EayRS2V1kEsWESU9QMRseFhdxYxKicsiFmxrsLZHeLUtdps3S",
        "mars.tardigrade.io",
    ),
    (
        "121RTSDpyNZVcEU84Ticf2L1ntiuUimbWgfATz21tuvgk3vzoA6",
        "asia-east-1.tardigrade.io",
    ),
    (
        "121RTSDpyNZVcEU84Ticf2L1ntiuUimbWgfATz21tuvgk3vzoA6",
        "saturn.tardigrade.io",
    ),
    (
        "12L9ZFwhzVpuEKMUNUqkaTLGzwY9G24tbiigLiXpmZWKwmcNDDs",
        "europe-west-1.tardigrade.io",
    ),
    (
        "12L9ZFwhzVpuEKMUNUqkaTLGzwY9G24tbiigLiXpmZWKwmcNDDs",
        "jupiter.tardigrade.io",
    ),
    (
        "118UWpMCHzs6CvSgWd9BfFVjw5K9pZbJjkfZJexMtSkmKxvvAW",
        "satellite.stefan-benten.de",
    ),
    (
        "1wFTAgs9DP5RSnCqKV1eLf6N9wtk4EAtmN5DpSxcs8EjT69tGE",
        "saltlake.tardigrade.io",
    ),
]


@pytest.mark.parametrize("node_id,host", KNOWN_NODES)
def test_known_node_aliases(node_id: str, host: str) -> None:
    for address in (host, f"{host}:7777", f"{host}:1234"):
        assert str(rpc.known_node_id(address)) == node_id
    assert rpc.known_node_id(f"unknown.{host}") is None


def test_legacy_hostname_only_access() -> None:
    node_id, host = KNOWN_NODES[0]
    inner = grant.Access(
        satellite_address=host,
        api_key=macaroon.new_api_key(b"secret"),
        enc_access=EncryptionAccess(Key.newzero()),
    )

    access = uplink.parse_access(inner.serialize())

    assert access.satellite_url.address == host
    assert str(access.satellite_url.id) == node_id


def test_node_id_preserves_registered_base58_version() -> None:
    encoded = base58.check_encode(bytes(range(31)) + b"\0", 0)
    assert str(node_id_from_string(encoded)) == encoded


@pytest.mark.parametrize("version", [1, 255])
def test_node_id_canonicalizes_unregistered_base58_version(version: int) -> None:
    node_id = bytes(range(31)) + b"\0"
    encoded = base58.check_encode(node_id, version)
    assert str(node_id_from_string(encoded)) == base58.check_encode(node_id, 0)


@pytest.mark.parametrize(
    "value,address",
    [
        ("33.20.0.1:7777", "33.20.0.1:7777"),
        (
            "[2001:db8:1f70::999:de8:7648:6e8]:7777",
            "[2001:db8:1f70::999:de8:7648:6e8]:7777",
        ),
        ("example.com:7777", "example.com:7777"),
        (f"{KNOWN_NODES[0][0]}@", ""),
    ],
)
def test_node_url_matches_go_address_cases(value: str, address: str) -> None:
    node_url = NodeURL.parse(value)

    assert node_url.address == address
    assert str(node_url) == value


def test_node_url_feature_flags() -> None:
    node_url = NodeURL.parse("example.test:7777?f=ff")

    assert node_url.features == 255
    assert str(node_url) == "example.test:7777?f=ff"


def test_node_url_round_trip_preserves_queries() -> None:
    node_id = KNOWN_NODES[0][0]
    noise_pub = base58.check_encode(b"\xff\0noise", 0)
    value = (
        f"{node_id}@example.test:7777?"
        f"debounce=3&f=ff&noise_proto=1&noise_pub={noise_pub}"
    )

    node_url = NodeURL.parse(value)

    assert node_url.features == 255
    assert node_url.noise_info.public_key == b"\xff\0noise"
    assert str(node_url) == value


@pytest.mark.parametrize(
    "value",
    [
        KNOWN_NODES[0][0][:-1] + "1",
        base58.check_encode(b"\0" * 31, 0),
    ],
)
def test_node_url_rejects_malformed_node_id(value: str) -> None:
    with pytest.raises(ValueError, match="invalid node ID"):
        NodeURL.parse(f"{value}@example.test:7777")


@pytest.mark.parametrize(
    "key,value",
    [
        ("noise_pub", base58.check_encode(b"noise", 0)[:-1] + "1"),
        ("noise_proto", "bad"),
        ("debounce", "bad"),
        ("f", "xyz"),
        ("f", "-1"),
        ("f", "10000000000000000"),
    ],
)
def test_node_url_rejects_malformed_query_values(key: str, value: str) -> None:
    with pytest.raises(ValueError, match=f"invalid {key}"):
        NodeURL.parse(f"example.test:7777?{key}={value}")
