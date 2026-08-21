# Copyright (C) 2023 Storj Labs, Inc.
# See LICENSE for copying information.

import pytest
from copy import copy
from datetime import datetime, timedelta
from uplink.common import macaroon, storj
from uplink.common.grant import (
    Access,
    EncryptionAccess,
    Permission,
    SharePrefix,
)
from uplink.common.macaroon import Action, ActionType, UnauthorizedError
from uplink.common.storj import CipherSuite
from uplink.common import paths


def test_restrict() -> None:
    secret = macaroon.new_secret()

    api_key = macaroon.new_api_key(secret)

    default_key = storj.new_key()

    enc_access = EncryptionAccess(default_key=default_key)
    enc_access.default_path_cipher = CipherSuite.ENC_NULL

    access = Access(satellite_address="", api_key=api_key, enc_access=enc_access)

    full_permission = Permission(
        allow_download=True, allow_upload=True, allow_list=True, allow_delete=True
    )

    now = datetime.now()

    action1 = Action(
        ActionType.ACTION_READ,
        bucket=b"bucket",
        encrypted_path=b"prefix1/path1",
        time=now,
    )

    action2 = Action(
        ActionType.ACTION_READ,
        bucket=b"bucket",
        encrypted_path=b"prefix2/path2",
        time=now,
    )

    permission = copy(full_permission)
    permission.not_after = now + timedelta(hours=2)

    restricted = access.restrict(permission)

    # Check that all actions are allowed and the encAccess has only the default key
    restricted.api_key.check(secret, action1)
    restricted.api_key.check(secret, action2)

    assert default_key == restricted.enc_access.store.default_key

    _, _, base = restricted.enc_access.store.lookup_encrypted(
        b"bucket", paths.Encrypted(b"prefix1/path1")
    )
    assert base is not None
    assert base.default is True
    assert base.key == default_key

    _, _, base = restricted.enc_access.store.lookup_encrypted(
        b"bucket", paths.Encrypted(b"prefix2/path2")
    )
    assert base is not None
    assert base.default is True
    assert base.key == default_key

    # Restrict further the access to a specific prefix
    restricted = restricted.restrict(
        full_permission,
        [
            SharePrefix(
                bucket=b"bucket",
                prefix=b"prefix1",
            )
        ],
    )

    # Check that only the actions under this prefix are allowed
    restricted.api_key.check(secret, action1)
    with pytest.raises(UnauthorizedError):
        restricted.api_key.check(secret, action2)

    # Check that enc_access has a derived key for the allowed prefix instead of the default key
    _, _, base = restricted.enc_access.store.lookup_encrypted(
        b"bucket", paths.Encrypted(b"prefix1/path1")
    )
    assert base is not None
    assert base.default is False
    assert base.key != default_key
    assert base.encrypted.raw == b"prefix1"
    assert base.unencrypted.raw == b"prefix1"

    _, _, base = restricted.enc_access.store.lookup_encrypted(
        b"bucket", paths.Encrypted(b"prefix2/path2")
    )
    assert base is None

    # Further restrict the access with a not_after time.
    permission.not_after = now + timedelta(hours=1)

    # Check that the access still allows only actions under the allowed prefix
    restricted = restricted.restrict(permission)
    restricted.api_key.check(secret, action1)
    with pytest.raises(UnauthorizedError):
        restricted.api_key.check(secret, action2)

    # Check that enc_access has not changed too
    _, _, base = restricted.enc_access.store.lookup_encrypted(
        b"bucket", paths.Encrypted(b"prefix1/path1")
    )
    assert base is not None
    assert base.default is False
    assert base.key != default_key
    assert base.encrypted.raw == b"prefix1"
    assert base.unencrypted.raw == b"prefix1"

    _, _, base = restricted.enc_access.store.lookup_encrypted(
        b"bucket", paths.Encrypted(b"prefix2/path2")
    )
    assert base is None
