# Copyright (C) 2023 Storj Labs, Inc.
# See LICENSE for copying information.

import os

from . import types_pb2 as types_pb2

Caveat = types_pb2.Caveat
CaveatPath = Caveat.Path


def caveat_with_nonce(caveat: Caveat) -> Caveat:
    out = Caveat()
    out.CopyFrom(caveat)
    out.nonce = os.urandom(4)
    return out
