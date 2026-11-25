"""Thread-safe in-memory metadata store implementation with fault injection."""

from __future__ import annotations

import copy
import threading

from ..exceptions import StorageError
from .base import (
    AuditEventRecord,
    ConnectionMetadata,
    CredentialMetadataStore,
    RollbackRecoveryRecord,
)


class InMemoryMetadataStore(CredentialMetadataStore):
    """In-memory metadata and audit store for testing, CLIs, and standalone agents."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        # Key: (tenant_id, connector_id) -> ConnectionMetadata
        self._connections: dict[tuple[str, str], ConnectionMetadata] = {}
        self._events: list[AuditEventRecord] = []
        self._recovery_records: list[RollbackRecoveryRecord] = []

        # Fault injection toggles for two-phase rollback testing
        self.simulated_save_failure: bool = False
        self.simulated_audit_failure: bool = False

    def reset(self) -> None:
        with self._lock:
            self._connections.clear()
            self._events.clear()
            self._recovery_records.clear()
            self.simulated_save_failure = False
            self.simulated_audit_failure = False

    def get_connection(self, tenant_id: str, connector_id: str) -> ConnectionMetadata | None:
        with self._lock:
            key = (tenant_id.lower(), connector_id.lower())
            conn = self._connections.get(key)
            if conn is None:
                return None
            return copy.deepcopy(conn)

    def save_connection(self, conn: ConnectionMetadata) -> None:
        if self.simulated_save_failure:
            raise StorageError(
                "Simulated metadata persistence failure (triggering compensating rollback)",
                code="metadata_save_failed",
            )
        with self._lock:
            key = (conn.tenant_id.lower(), conn.connector_id.lower())
            self._connections[key] = copy.deepcopy(conn)

    def record_audit_event(self, event: AuditEventRecord) -> None:
        if self.simulated_audit_failure:
            raise StorageError("Simulated audit write failure", code="audit_save_failed")
        with self._lock:
            self._events.append(copy.deepcopy(event))

    def get_audit_events(
        self,
        tenant_id: str | None = None,
        limit: int = 50,
    ) -> list[AuditEventRecord]:
        with self._lock:
            if tenant_id:
                clean_tid = tenant_id.lower()
                filtered = [e for e in self._events if e.tenant_id.lower() == clean_tid]
            else:
                filtered = list(self._events)
            # Return newest first up to limit
            return list(reversed(filtered[-limit:]))

    def save_recovery_record(self, record: RollbackRecoveryRecord) -> None:
        with self._lock:
            self._recovery_records.append(copy.deepcopy(record))

    def get_recovery_records(
        self,
        tenant_id: str | None = None,
    ) -> list[RollbackRecoveryRecord]:
        with self._lock:
            if tenant_id:
                clean_tid = tenant_id.lower()
                filtered = [r for r in self._recovery_records if r.tenant_id.lower() == clean_tid]
            else:
                filtered = list(self._recovery_records)
            return list(reversed(filtered))
