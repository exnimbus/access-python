# Copyright (C) 2023 Storj Labs, Inc.
# See LICENSE for copying information.

from uplink.common.storj import NodeID, node_id_from_string


_KNOWN_NODE_IDS = {
    "us-central-1.tardigrade.io": "12EayRS2V1kEsWESU9QMRseFhdxYxKicsiFmxrsLZHeLUtdps3S",
    "mars.tardigrade.io": "12EayRS2V1kEsWESU9QMRseFhdxYxKicsiFmxrsLZHeLUtdps3S",
    "asia-east-1.tardigrade.io": "121RTSDpyNZVcEU84Ticf2L1ntiuUimbWgfATz21tuvgk3vzoA6",
    "saturn.tardigrade.io": "121RTSDpyNZVcEU84Ticf2L1ntiuUimbWgfATz21tuvgk3vzoA6",
    "europe-west-1.tardigrade.io": "12L9ZFwhzVpuEKMUNUqkaTLGzwY9G24tbiigLiXpmZWKwmcNDDs",
    "jupiter.tardigrade.io": "12L9ZFwhzVpuEKMUNUqkaTLGzwY9G24tbiigLiXpmZWKwmcNDDs",
    "satellite.stefan-benten.de": "118UWpMCHzs6CvSgWd9BfFVjw5K9pZbJjkfZJexMtSkmKxvvAW",
    "saltlake.tardigrade.io": "1wFTAgs9DP5RSnCqKV1eLf6N9wtk4EAtmN5DpSxcs8EjT69tGE",
}


def known_node_id(address: str) -> NodeID | None:
    node_id = _KNOWN_NODE_IDS.get(address)
    if node_id is None and ":" in address:
        node_id = _KNOWN_NODE_IDS.get(address.rsplit(":", 1)[0])
    return node_id_from_string(node_id) if node_id is not None else None
