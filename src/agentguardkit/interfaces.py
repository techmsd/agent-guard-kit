"""Typed data structures and interfaces for AgentGuardKit."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

from .exceptions import InvalidPayloadError

# Absolute safety boundary: Maximum secret string length (32 KB)
MAX_SECRET_LENGTH_BYTES = 32 * 1024
MAX_DESCRIPTION_LENGTH = 500
MAX_METADATA_KEYS = 50
MAX_METADATA_DEPTH = 3
MAX_METADATA_BYTES = 8192

# Standard recognized secret type identifiers; arbitrary non-standard types are masked in representations
STANDARD_SECRET_TYPES: frozenset[str] = frozenset(
    {
        "api_key",
        "oauth_token",
        "password",
        "token",
        "key",
        "generic",
        "certificate",
        "private_key",
        "connection_string",
        "webhook_secret",
        "database_credential",
        "ssh_key",
        "t",
    }
)


def _check_metadata_depth(
    obj: Any, current_depth: int = 1, max_depth: int = MAX_METADATA_DEPTH
) -> None:
    if current_depth > max_depth:
        raise InvalidPayloadError(f"custom_metadata exceeds maximum nesting depth of {max_depth}")
    if isinstance(obj, dict):
        for v in obj.values():
            _check_metadata_depth(v, current_depth + 1, max_depth)
    elif isinstance(obj, (list, tuple)):
        for item in obj:
            _check_metadata_depth(item, current_depth + 1, max_depth)


@dataclass(frozen=True)
class SecretPayload:
    """Standardized secret payload to be written to a storage engine.

    Validates field types and enforces bounded payload sizes fail-closed.
    Custom __repr__ strictly excludes secret_value, description contents, and custom_metadata
    values to prevent credential and sensitive data leakage in exception traces and logs.
    """

    secret_type: str
    secret_value: str = field(repr=False)
    description: str | None = None
    custom_metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not isinstance(self.secret_type, str) or not self.secret_type.strip():
            raise InvalidPayloadError("secret_type must be a non-empty string")
        if not isinstance(self.secret_value, str):
            raise InvalidPayloadError("secret_value must be a string")
        if len(self.secret_value.encode("utf-8")) > MAX_SECRET_LENGTH_BYTES:
            raise InvalidPayloadError(
                f"secret_value exceeds maximum permitted size of {MAX_SECRET_LENGTH_BYTES} bytes"
            )

        if self.description is not None:
            if not isinstance(self.description, str):
                raise InvalidPayloadError("description must be a string or None")
            if len(self.description) > MAX_DESCRIPTION_LENGTH:
                raise InvalidPayloadError(
                    f"description exceeds maximum permitted length of {MAX_DESCRIPTION_LENGTH} characters"
                )

        if not isinstance(self.custom_metadata, dict):
            raise InvalidPayloadError("custom_metadata must be a dictionary")

        if len(self.custom_metadata) > MAX_METADATA_KEYS:
            raise InvalidPayloadError(
                f"custom_metadata exceeds maximum allowed {MAX_METADATA_KEYS} keys"
            )

        _check_metadata_depth(self.custom_metadata, current_depth=1, max_depth=MAX_METADATA_DEPTH)

        try:
            serialized = json.dumps(self.custom_metadata)
        except (TypeError, ValueError) as err:
            raise InvalidPayloadError(f"custom_metadata must be JSON-serializable: {err}") from err

        if len(serialized.encode("utf-8")) > MAX_METADATA_BYTES:
            raise InvalidPayloadError(
                f"custom_metadata serialized size exceeds maximum permitted {MAX_METADATA_BYTES} bytes"
            )

    def __repr__(self) -> str:
        """Safe object representation preventing leakage of secret, description, metadata keys/values, or arbitrary secret-type values."""
        has_desc = bool(self.description)
        safe_type = self.secret_type if self.secret_type in STANDARD_SECRET_TYPES else "[CUSTOM]"
        return (
            f"SecretPayload(secret_type={safe_type!r}, "
            f"secret_value=[REDACTED], "
            f"has_description={has_desc}, "
            f"custom_metadata_count={len(self.custom_metadata)})"
        )

    def __str__(self) -> str:
        """String representation delegates directly to safe __repr__."""
        return self.__repr__()


@dataclass(frozen=True)
class SecretWriteResult:
    """Result returned after storing or rotating a secret."""

    version: int
    created_time: str
    destroyed: bool = False


@dataclass(frozen=True)
class SecretMetadataResult:
    """Metadata about a stored secret without exposing secret contents."""

    exists: bool
    current_version: int | None = None
    created_time: str | None = None
    updated_time: str | None = None
    destroyed: bool = False
    custom_metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class StorageHealthStatus:
    """Health and reachability probe result from the storage backend."""

    initialized: bool
    sealed: bool
    standby: bool
    reachable: bool
    server_time: str | None = None
    error: str | None = None


@dataclass(frozen=True)
class BrokerReadiness:
    """Grounded operational readiness status for callers and monitoring."""

    storage_enabled: bool
    readiness_code: str
    readiness_label: str
    has_secret: bool
    status: str
    secret_version: int | None = None
    last_updated: str | None = None
    can_mutate: bool = False
    notice: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "storage_enabled": self.storage_enabled,
            "readiness_code": self.readiness_code,
            "readiness_label": self.readiness_label,
            "has_secret": self.has_secret,
            "status": self.status,
            "secret_version": self.secret_version,
            "last_updated": self.last_updated,
            "can_mutate": self.can_mutate,
            "notice": self.notice,
        }
