"""Tenant-scoped path derivation and identifier validation."""

from __future__ import annotations

import re
import uuid

from .exceptions import InvalidPathError

# Strictly allow UUIDs or alphanumeric identifiers with hyphens and underscores (1 to 64 chars)
_IDENTIFIER_PATTERN = re.compile(r"^[a-zA-Z0-9_\-]{1,64}$")


def validate_identifier(val: str | uuid.UUID, field_name: str = "identifier") -> str:
    """Validate that an identifier strictly matches safe alphanumeric constraints.

    Rejects path traversal, null bytes, slashes, wildcards, and special characters.
    """
    if isinstance(val, uuid.UUID):
        return str(val).lower()

    if not isinstance(val, str) or isinstance(val, bool):
        raise InvalidPathError(
            f"{field_name} must be a valid string or UUID, got {type(val).__name__}"
        )

    clean = val.strip().lower()
    if not clean:
        raise InvalidPathError(f"{field_name} cannot be empty")

    if not _IDENTIFIER_PATTERN.match(clean):
        raise InvalidPathError(
            f"{field_name} contains invalid characters or length. Must match ^[a-zA-Z0-9_-]{{1,64}}$"
        )

    # Explicit defense against traversal patterns even if regex changes
    if ".." in clean or "/" in clean or "\\" in clean or "\0" in clean:
        raise InvalidPathError(f"{field_name} contains prohibited traversal characters")

    return clean


def derive_tenant_secret_path(
    tenant_id: str | uuid.UUID,
    connector_id: str | uuid.UUID,
    prefix: str = "tenants",
) -> str:
    """Derive a canonical, isolated tenant secret path.

    Guarantees strict tenant isolation:
    Format: {prefix}/{clean_tenant_id}/connectors/{clean_connector_id}
    """
    clean_tenant = validate_identifier(tenant_id, field_name="tenant_id")
    clean_connector = validate_identifier(connector_id, field_name="connector_id")

    clean_prefix = prefix.strip("/").lower()
    if clean_prefix and not _IDENTIFIER_PATTERN.match(clean_prefix):
        raise InvalidPathError(f"prefix contains invalid characters: {clean_prefix}")

    if clean_prefix:
        return f"{clean_prefix}/{clean_tenant}/connectors/{clean_connector}"
    return f"{clean_tenant}/connectors/{clean_connector}"
