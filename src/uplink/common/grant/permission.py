# Copyright (C) 2023 Storj Labs, Inc.
# See LICENSE for copying information.


from datetime import datetime, timedelta
from typing import Optional

# The names of every "allow" flag, in caveat field order. Kept as a module level
# tuple so that emptiness checks stay in sync with the fields automatically.
ALLOW_FIELDS = (
    "allow_download",
    "allow_upload",
    "allow_list",
    "allow_delete",
    "allow_lock",
    "allow_put_object_retention",
    "allow_get_object_retention",
    "allow_put_object_legal_hold",
    "allow_get_object_legal_hold",
    "allow_bypass_governance_retention",
    "allow_put_bucket_object_lock_configuration",
    "allow_get_bucket_object_lock_configuration",
    "allow_put_bucket_notification_configuration",
    "allow_get_bucket_notification_configuration",
)


class Permission:
    """Permission defines what actions can be used to share.

    The set of flags mirrors storj.io/common/grant.Permission so that access
    grants restricted by this library are equivalent to ones restricted by the
    Go implementation.
    """

    __slots__ = [
        "allow_delete",
        "allow_list",
        "allow_download",
        "allow_upload",
        "allow_lock",
        "allow_put_object_retention",
        "allow_get_object_retention",
        "allow_put_object_legal_hold",
        "allow_get_object_legal_hold",
        "allow_bypass_governance_retention",
        "allow_put_bucket_object_lock_configuration",
        "allow_get_bucket_object_lock_configuration",
        "allow_put_bucket_notification_configuration",
        "allow_get_bucket_notification_configuration",
        "not_before",
        "not_after",
        "max_object_ttl",
    ]

    def __init__(
        self,
        allow_delete: bool = False,
        allow_list: bool = False,
        allow_download: bool = False,
        allow_upload: bool = False,
        not_before: Optional[datetime] = None,
        not_after: Optional[datetime] = None,
        max_object_ttl: Optional[timedelta] = None,
        # The Object Lock and bucket notification flags are keyword friendly
        # additions. They are declared after the pre-existing parameters so that
        # positional callers written against the older signature keep working.
        allow_lock: bool = False,
        allow_put_object_retention: bool = False,
        allow_get_object_retention: bool = False,
        allow_put_object_legal_hold: bool = False,
        allow_get_object_legal_hold: bool = False,
        allow_bypass_governance_retention: bool = False,
        allow_put_bucket_object_lock_configuration: bool = False,
        allow_get_bucket_object_lock_configuration: bool = False,
        allow_put_bucket_notification_configuration: bool = False,
        allow_get_bucket_notification_configuration: bool = False,
    ) -> None:
        self.allow_delete = allow_delete
        self.allow_list = allow_list
        self.allow_download = allow_download
        self.allow_upload = allow_upload
        # allow_lock is retained for historical compatibility. Prefer the
        # granular allow_put_object_retention / allow_get_object_retention
        # flags, matching the deprecation in the Go implementation.
        self.allow_lock = allow_lock
        self.allow_put_object_retention = allow_put_object_retention
        self.allow_get_object_retention = allow_get_object_retention
        self.allow_put_object_legal_hold = allow_put_object_legal_hold
        self.allow_get_object_legal_hold = allow_get_object_legal_hold
        self.allow_bypass_governance_retention = allow_bypass_governance_retention
        self.allow_put_bucket_object_lock_configuration = (
            allow_put_bucket_object_lock_configuration
        )
        self.allow_get_bucket_object_lock_configuration = (
            allow_get_bucket_object_lock_configuration
        )
        self.allow_put_bucket_notification_configuration = (
            allow_put_bucket_notification_configuration
        )
        self.allow_get_bucket_notification_configuration = (
            allow_get_bucket_notification_configuration
        )
        self.not_before = not_before
        self.not_after = not_after
        self.max_object_ttl = max_object_ttl

    @property
    def empty(self) -> bool:
        """True when no field is set at all.

        This mirrors the ``permission == (Permission{})`` comparison that the Go
        implementation uses to reject empty permissions, so the time bounds and
        the object TTL participate in the check alongside the allow flags.
        """
        if any(getattr(self, name) for name in ALLOW_FIELDS):
            return False
        return (
            self.not_before is None
            and self.not_after is None
            and self.max_object_ttl is None
        )

    @property
    def restricted(self) -> bool:
        """True when any of the four legacy operations is withheld.

        Deliberately scoped to the legacy read/write/list/delete flags: it feeds
        the CLI's "should we bother re-sharing?" shortcut, and widening it to the
        newer Object Lock flags would silently change that behaviour.
        """
        return not (
            self.allow_delete
            and self.allow_list
            and self.allow_download
            and self.allow_upload
        )
