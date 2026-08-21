# Copyright (C) 2023 Storj Labs, Inc.
# See LICENSE for copying information.

import click
import uplink
from typing import Any
from uplink import edge
from .access_permission import AccessPermission, access_permission_options

_DEFAULT_AUTH_SERVICE = "https://auth.storjshare.io"

_RESTRICT_EXAMPLE = """
\b
Example: restrict access to read-only on the "widgets" bucket
\b
    $ uplink restrict \\
        --access $(cat access-key.txt) \\
        --readonly=true \\
        --prefix=widgets

\b
Example: restrict access to the "springs" prefix in the "widgets" bucket
\b
    $ uplink restrict \\
        --access $(cat access-key.txt) \\
        --prefix=widgets/springs

"""

_REGISTER_EXAMPLE = """
\b
Example: register access with default auth service
\b
    $ uplink register --access $(cat access-key.txt)

"""


@click.group()
@click.version_option()
def main() -> None:
    pass


@main.command(
    help="Restricts the provided access", no_args_is_help=True, epilog=_RESTRICT_EXAMPLE
)
@click.option("--access", required=True, help="Access value to restrict")
@access_permission_options
def restrict(access: str, **kwargs: Any) -> None:
    # Click supplies dynamically typed option values at this callback boundary.
    # TODO: load from file? e.g. go uplink takes a name or value and looks it up in access.json
    access_in = uplink.parse_access(access)

    permissions = AccessPermission(**kwargs)

    access_out = permissions.apply(access_in)

    serialized = access_out.serialize()
    click.echo(f"{serialized}")


@main.command(
    help="Registers the provided access", no_args_is_help=True, epilog=_REGISTER_EXAMPLE
)
@click.option(
    "--auth-service",
    default=_DEFAULT_AUTH_SERVICE,
    help=f"The address to the service you wish to register your access with (defaults to {_DEFAULT_AUTH_SERVICE})",
)
@click.option(
    "--ca-cert",
    help="path to a file in PEM format with certificate(s) or certificate chain(s) to validate the auth service against",
)
@click.option("--public", type=click.BOOL, help="If true, the access will be public")
@click.option(
    "--format",
    help="Format of the output credentials, use 'env' or 'aws' when using in scripts",
)
@click.option(
    "--aws-profile",
    help="If using -format=aws, output the --profile tag using this profile",
)
@click.option(
    "--access", required=True, help="Access value to register with the auth service"
)
def register(
    auth_service: str,
    ca_cert: str | None,
    public: bool,
    format: str,
    aws_profile: str,
    access: str,
) -> None:
    access_in = uplink.parse_access(access)
    credentials = _register_access(access_in, auth_service, public, ca_cert)
    _display_gateway_credentials(credentials, format, aws_profile)


def _register_access(
    access: uplink.Access, auth_service: str, public: bool, ca_cert: str | None
) -> edge.Credentials:
    if auth_service == "":
        raise ValueError("no auth service address provided")

    certificate_pem = None
    if ca_cert is not None:
        certificate_pem = open(ca_cert, mode="rb").read()

    # We don't implement dRPC yet, so use the legacy http service only.

    config = edge.Config(
        auth_service_url=auth_service,
        certificate_pem=certificate_pem,
    )

    return config.register_access(access, edge.RegisterAccessOptions(public=public))


def _display_gateway_credentials(
    credentials: edge.Credentials, format: str, aws_profile: str
) -> None:
    if format == "env":
        print(f"AWS_ACCESS_KEY_ID={credentials.access_key_id}")
        print(f"AWS_SECRET_ACCESS_KEY={credentials.secret_key}")
        print(f"AWS_ENDPOINT={credentials.endpoint}")
    elif format == "aws":
        profile = ""
        if aws_profile != "":
            profile = " --profile " + aws_profile
            print(f"aws configure{profile}")
        print(f"aws configure{profile} aws_access_key_id {credentials.access_key_id}")
        print(f"aws configure{profile} aws_secret_access_key {credentials.secret_key}")
        print(f"aws configure{profile} s3.endpoint_url {credentials.endpoint}")
    else:
        print(
            "========== GATEWAY CREDENTIALS ==========================================================="
        )
        print(f"Access Key ID: {credentials.access_key_id}")
        print(f"Secret Key   : {credentials.secret_key}")
        print(f"Endpoint     : {credentials.endpoint}")
