# Copyright (C) 2023 Storj Labs, Inc.
# See LICENSE for copying information.

import ssl
import json
from typing import Optional
from uplink import Access
import urllib.request


class Credentials:
    __slots__ = ["access_key_id", "secret_key", "endpoint"]

    def __init__(
        self, access_key_id: str = "", secret_key: str = "", endpoint: str = ""
    ) -> None:
        self.access_key_id = access_key_id
        self.secret_key = secret_key
        self.endpoint = endpoint


class RegisterAccessOptions:
    __slots__ = ["public"]

    def __init__(self, public: bool = False) -> None:
        self.public = public


class Config:
    __slots__ = [
        "auth_service_url",
        "certificate_pem",
    ]

    def __init__(
        self,
        auth_service_url: str,
        certificate_pem: Optional[bytes] = None,
    ) -> None:
        self.auth_service_url = auth_service_url
        self.certificate_pem = certificate_pem

    def register_access(
        self, access: Access, options: Optional[RegisterAccessOptions]
    ) -> Credentials:
        if self.auth_service_url == "":
            raise ValueError("auth_service_url is missing")

        if options is None:
            options = RegisterAccessOptions()

        serialized_access = access.serialize()

        context = None
        if self.certificate_pem is not None:
            context = ssl.create_default_context(cadata=self.certificate_pem)

        req = urllib.request.Request(
            f"{self.auth_service_url}/v1/access",
            method="POST",
            data=json.dumps(
                {
                    "access_grant": serialized_access,
                    "public": options.public,
                }
            ).encode(),
        )

        resp = urllib.request.urlopen(req, context=context)
        # urllib's response body is untyped at this dependency boundary.
        raw: bytes = resp.read()
        # The service's JSON response is an untyped dependency boundary.
        body: dict[str, str] = json.loads(raw)
        return Credentials(
            access_key_id=body["access_key_id"],
            secret_key=body["secret_key"],
            endpoint=body["endpoint"],
        )
