# Copyright (C) 2023 Storj Labs, Inc.
# See LICENSE for copying information.

from __future__ import annotations

import json
import socket
import ssl
import urllib.error
import urllib.request
from datetime import UTC, datetime
from typing import Optional, cast
from urllib.parse import urlsplit

from uplink import Access
from uplink.common import drpc
from uplink.common.pb import edgeauth_pb2


class AuthServiceError(RuntimeError):
    """The auth service rejected a registration request."""


class Credentials:
    __slots__ = [
        "access_key_id",
        "secret_key",
        "endpoint",
        "free_tier_restricted_expiration",
    ]

    def __init__(
        self,
        access_key_id: str = "",
        secret_key: str = "",
        endpoint: str = "",
        free_tier_restricted_expiration: datetime | None = None,
    ) -> None:
        self.access_key_id = access_key_id
        self.secret_key = secret_key
        self.endpoint = endpoint
        self.free_tier_restricted_expiration = free_tier_restricted_expiration


class RegisterAccessOptions:
    __slots__ = ["public"]

    def __init__(self, public: bool = False) -> None:
        self.public = public


class Config:
    __slots__ = ["auth_service_url", "certificate_pem", "timeout"]

    def __init__(
        self,
        auth_service_url: str,
        certificate_pem: Optional[bytes] = None,
        timeout: float = 20.0,
    ) -> None:
        if timeout <= 0:
            raise ValueError("timeout must be positive")
        self.auth_service_url = auth_service_url
        self.certificate_pem = certificate_pem
        self.timeout = timeout

    def register_access(
        self, access: Access, options: Optional[RegisterAccessOptions] = None
    ) -> Credentials:
        if self.auth_service_url == "":
            raise ValueError("auth_service_url is missing")
        if options is None:
            options = RegisterAccessOptions()

        serialized_access = access.serialize()
        if self.auth_service_url.lower().startswith(("http://", "https://")):
            return self._register_http(serialized_access, options.public)
        return self._register_drpc(serialized_access, options.public)

    def _register_drpc(self, access: str, public: bool) -> Credentials:
        host, port, insecure = _drpc_target(self.auth_service_url)
        request = edgeauth_pb2.EdgeRegisterAccessRequest(
            access_grant=access, public=public
        )
        conn: socket.socket | ssl.SSLSocket
        try:
            conn = socket.create_connection((host, port), timeout=self.timeout)
            try:
                if not insecure:
                    conn = self._ssl_context().wrap_socket(conn, server_hostname=host)
                response = drpc.invoke(
                    conn,
                    "/EdgeAuth/RegisterAccess",
                    cast(bytes, request.SerializeToString()),
                )
            finally:
                conn.close()
        except drpc.RemoteError as exc:
            raise AuthServiceError(
                f"auth service rejected registration: {exc}"
            ) from exc
        except TimeoutError as exc:
            raise TimeoutError("auth service timed out") from exc
        except ssl.SSLError:
            raise
        except (ConnectionError, OSError) as exc:
            raise ConnectionError("could not communicate with auth service") from exc

        result = edgeauth_pb2.EdgeRegisterAccessResponse()
        try:
            result.ParseFromString(response)
            expiration = (
                result.free_tier_restricted_expiration.ToDatetime(tzinfo=UTC)
                if result.HasField("free_tier_restricted_expiration")
                else None
            )
            return _credentials(
                result.access_key_id,
                result.secret_key,
                result.endpoint,
                expiration,
            )
        except Exception as exc:
            raise ValueError("malformed auth service response") from exc

    def _register_http(self, access: str, public: bool) -> Credentials:
        request = urllib.request.Request(
            f"{self.auth_service_url.rstrip('/')}/v1/access",
            method="POST",
            data=json.dumps({"access_grant": access, "public": public}).encode(),
            headers={"Content-Type": "application/json"},
        )
        context = (
            self._ssl_context()
            if self.auth_service_url.lower().startswith("https://")
            else None
        )
        try:
            with urllib.request.urlopen(
                request, context=context, timeout=self.timeout
            ) as response:
                raw: bytes = response.read()
        except urllib.error.HTTPError as exc:
            raise AuthServiceError(f"auth service returned HTTP {exc.code}") from exc
        except urllib.error.URLError as exc:
            if isinstance(exc.reason, ssl.SSLError):
                raise exc.reason
            if isinstance(exc.reason, TimeoutError):
                raise TimeoutError("auth service timed out") from exc
            raise ConnectionError("could not connect to auth service") from exc
        except TimeoutError as exc:
            raise TimeoutError("auth service timed out") from exc

        try:
            body = cast(dict[str, object], json.loads(raw))
            expiration = _parse_expiration(
                body.get(
                    "free_tier_restricted_expiration",
                    body.get("freeTierRestrictedExpiration"),
                )
            )
            return _credentials(
                body.get("access_key_id"),
                body.get("secret_key"),
                body.get("endpoint"),
                expiration,
            )
        except Exception as exc:
            raise ValueError("malformed auth service response") from exc

    def _ssl_context(self) -> ssl.SSLContext:
        if self.certificate_pem is None:
            return ssl.create_default_context()
        try:
            return ssl.create_default_context(
                cadata=self.certificate_pem.decode("ascii")
            )
        except (UnicodeDecodeError, ssl.SSLError) as exc:
            raise ssl.SSLError("invalid certificate PEM") from exc


def _drpc_target(address: str) -> tuple[str, int, bool]:
    insecure = address.lower().startswith("insecure://")
    if "://" in address and not insecure:
        raise ValueError(
            "auth service address must be HTTP(S), host:port, or insecure://host:port"
        )
    target = address[len("insecure://") :] if insecure else address
    parsed = urlsplit(f"//{target}")
    try:
        port = parsed.port
    except ValueError as exc:
        raise ValueError("invalid auth service address") from exc
    if (
        parsed.hostname is None
        or port is None
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError("auth service dRPC address must be host:port")
    return parsed.hostname, port, insecure


def _credentials(
    access_key_id: object,
    secret_key: object,
    endpoint: object,
    expiration: datetime | None,
) -> Credentials:
    if not all(
        isinstance(value, str) and value
        for value in (access_key_id, secret_key, endpoint)
    ):
        raise ValueError("credential fields are missing")
    return Credentials(
        cast(str, access_key_id),
        cast(str, secret_key),
        cast(str, endpoint),
        expiration,
    )


def _parse_expiration(value: object) -> datetime | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise ValueError("expiration is not a string")
    expiration = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if expiration.tzinfo is None:
        raise ValueError("expiration has no timezone")
    return expiration.astimezone(UTC)
