"""Abstract protocol defining the metadata and audit storage interface."""

from __future__ import annotations

import abc
from dataclasses import dataclass, field
from typing import Any


@dataclass
class ConnectionMetadata:
    """Opaque metadata record for a tenant connector (stores ZERO plaintext secrets)."""

    tenant_id: str
    connector_id: str
    vault_secret_ref: str | None = None
    status: str = "not_configured"
    secret_version: int | None = None
    created_at: str | None = None
    updated_at: str | None = None
    custom_attributes: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class AuditEventRecord:
    """Sanitized, metadata-only audit record."""

    event_id: str
    tenant_id: str
    connector_id: str | None
    actor: str
    action: str
    outcome: str
    metadata: dict[str, Any]
    timestamp: str


@dataclass(frozen=True)
class RollbackRecoveryRecord:
    """Opaque record created when a compensating rollback could not be completed cleanly.

    Contains zero plaintext secrets; provides structured trace data for operators.
    """

    recovery_id: str
    tenant_id: str
    connector_id: str
    secret_path: str
    version: int
    action: str
    error: str
    timestamp: str


class CredentialMetadataStore(abc.ABC):
    """Abstract interface for storing opaque connection metadata and audit trails."""

    @abc.abstractmethod
    def get_connection(self, tenant_id: str, connector_id: str) -> ConnectionMetadata | None:
        """Retrieve connection metadata for tenant and connector."""
        ...

    @abc.abstractmethod
    def save_connection(self, conn: ConnectionMetadata) -> None:
        """Persist updated connection metadata."""
        ...

    @abc.abstractmethod
    def record_audit_event(self, event: AuditEventRecord) -> None:
        """Persist a sanitized audit event."""
        ...

    @abc.abstractmethod
    def get_audit_events(
        self,
        tenant_id: str | None = None,
        limit: int = 50,
    ) -> list[AuditEventRecord]:
        """Retrieve recent audit events."""
        ...

    @abc.abstractmethod
    def save_recovery_record(self, record: RollbackRecoveryRecord) -> None:
        """Persist an uncompleted rollback recovery record."""
        ...

    @abc.abstractmethod
    def get_recovery_records(
        self,
        tenant_id: str | None = None,
    ) -> list[RollbackRecoveryRecord]:
        """Retrieve uncompleted rollback recovery records."""
        ...
