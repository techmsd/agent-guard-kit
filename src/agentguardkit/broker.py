"""Tenant-isolated Credential Broker orchestrating storage, metadata, and capability policies."""

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone
from typing import Any

from .audit.sanitizer import AuditSanitizer
from .exceptions import (
    AgentGuardError,
    CasMismatchError,
    RevocationError,
    RollbackError,
    StorageError,
    StorageNotFoundError,
    UnauthorizedActionError,
)
from .interfaces import (
    BrokerReadiness,
    SecretPayload,
)
from .metadata.base import (
    AuditEventRecord,
    ConnectionMetadata,
    CredentialMetadataStore,
    RollbackRecoveryRecord,
)
from .metadata.memory import InMemoryMetadataStore
from .path import derive_tenant_secret_path, validate_identifier
from .policy import AgentRole, AuthorizationContext, CredentialAction, PolicyEngine
from .storage.base import SecretStorageBackend
from .storage.memory import MockVaultStorage

logger = logging.getLogger(__name__)


class CredentialBroker:
    """Orchestrates tenant credential lifecycles across storage and metadata stores.

    Architectural Pattern:
    ----------------------
    Uses a coordinated two-phase write pattern with version-scoped compensating rollback.
    NOTE ON CONSISTENCY: This is an eventual-consistency compensating rollback pattern,
    NOT an ACID distributed transaction. If a failure occurs between the storage write
    and the metadata save, the broker executes a compensating deletion of the newly
    written secret version in the storage engine to prevent orphaned secrets.

    Security Boundary:
    ------------------
    Requires an explicit, authenticated AuthorizationContext for all tenant operations.
    Untrusted raw strings or missing contexts fail closed immediately.
    """

    def __init__(
        self,
        storage: SecretStorageBackend | None = None,
        metadata_store: CredentialMetadataStore | None = None,
        policy_engine: PolicyEngine | None = None,
        sanitizer: AuditSanitizer | None = None,
        enabled: bool = True,
        path_prefix: str = "tenants",
    ):
        self.storage = storage or MockVaultStorage()
        self.metadata_store = metadata_store or InMemoryMetadataStore()
        self.policy_engine = policy_engine or PolicyEngine()
        self.sanitizer = sanitizer or AuditSanitizer()
        self.enabled = enabled
        self.path_prefix = path_prefix

    def _ensure_enabled(self) -> None:
        if not self.enabled:
            raise AgentGuardError(
                "CredentialBroker is currently disabled by configuration",
                code="broker_disabled",
            )

    def _validate_actor(self, auth_context: AuthorizationContext) -> str:
        """Validate and return sanitized actor identifier."""
        if not isinstance(auth_context, AuthorizationContext) or not auth_context.actor_id:
            raise UnauthorizedActionError("Missing or invalid AuthorizationContext actor")
        return auth_context.actor_id

    def get_readiness_status(
        self,
        tenant_id: str | uuid.UUID | None = None,
        connector_id: str | uuid.UUID | None = None,
        auth_context: AuthorizationContext | None = None,
    ) -> BrokerReadiness:
        """Evaluate grounded readiness for the broker and an optional connection.

        If tenant_id or connector_id is provided, callers MUST supply an authenticated
        AuthorizationContext authorized for READ_METADATA on that scope.
        """
        if not self.enabled:
            return BrokerReadiness(
                storage_enabled=False,
                readiness_code="disabled",
                readiness_label="Broker Engine Disabled",
                has_secret=False,
                status="disabled",
                secret_version=None,
                last_updated=None,
                can_mutate=False,
                notice="The credential broker is disabled. Secret lifecycle operations are locked.",
            )

        # Health probe on backend storage
        try:
            health = self.storage.health_check()
            if not health.reachable or not health.initialized or health.sealed or health.standby:
                if not health.reachable:
                    readiness_code = "storage_unreachable"
                    readiness_label = "Storage Backend Unreachable"
                    notice = "Storage backend is unreachable or timed out."
                elif not health.initialized:
                    readiness_code = "storage_uninitialized"
                    readiness_label = "Storage Backend Uninitialized"
                    notice = "Storage backend cluster has not been initialized."
                elif health.sealed:
                    readiness_code = "storage_sealed"
                    readiness_label = "Storage Backend Sealed"
                    notice = "Storage backend cluster is currently sealed."
                else:
                    readiness_code = "storage_standby"
                    readiness_label = "Storage Backend Standby"
                    notice = "Storage backend cluster is currently in standby mode."

                return BrokerReadiness(
                    storage_enabled=True,
                    readiness_code=readiness_code,
                    readiness_label=readiness_label,
                    has_secret=False,
                    status="unavailable",
                    secret_version=None,
                    last_updated=None,
                    can_mutate=False,
                    notice=notice,
                )
        except Exception as e:
            return BrokerReadiness(
                storage_enabled=True,
                readiness_code="health_check_failed",
                readiness_label="Storage Health Probe Failed",
                has_secret=False,
                status="error",
                secret_version=None,
                last_updated=None,
                can_mutate=False,
                notice=f"Storage health probe failed: {e.__class__.__name__}",
            )

        # Global broker readiness (no tenant/connector specified)
        if not tenant_id or not connector_id:
            can_mutate = False
            if auth_context and auth_context.is_authenticated:
                role_val = (
                    auth_context.role.value
                    if isinstance(auth_context.role, AgentRole)
                    else str(auth_context.role)
                )
                can_mutate = role_val in (AgentRole.HUMAN_OWNER.value, AgentRole.HUMAN_ADMIN.value)

            return BrokerReadiness(
                storage_enabled=True,
                readiness_code="ready",
                readiness_label="Broker Engine Ready",
                has_secret=False,
                status="idle",
                secret_version=None,
                last_updated=None,
                can_mutate=can_mutate,
                notice="Broker engine is operational and ready to process requests.",
            )

        clean_t = validate_identifier(tenant_id, "tenant_id")
        clean_c = validate_identifier(connector_id, "connector_id")

        if not isinstance(auth_context, AuthorizationContext) or not auth_context.is_authenticated:
            raise UnauthorizedActionError(
                "Missing or unauthenticated AuthorizationContext required to inspect tenant readiness."
            )

        # ENFORCE READ_METADATA POLICY: Verifies actor role and tenant/connector scopes fail-closed
        self.policy_engine.enforce(
            auth_context=auth_context,
            action=CredentialAction.READ_METADATA,
            tenant_id=clean_t,
            connector_id=clean_c,
        )

        # Evaluate caller's actual mutation authority to prevent misleading can_mutate=True for read-only actors
        mutate_decision = self.policy_engine.evaluate(
            auth_context=auth_context,
            action=CredentialAction.REGISTER,
            tenant_id=clean_t,
            connector_id=clean_c,
        )
        actor_can_mutate = mutate_decision.allowed

        conn = self.metadata_store.get_connection(clean_t, clean_c)

        if conn is None:
            return BrokerReadiness(
                storage_enabled=True,
                readiness_code="awaiting_setup",
                readiness_label="Awaiting Credential Setup",
                has_secret=False,
                status="not_configured",
                secret_version=None,
                last_updated=None,
                can_mutate=actor_can_mutate,
                notice="No active secret reference linked to this connector.",
            )

        if not conn.vault_secret_ref:
            if conn.status == "revoked":
                return BrokerReadiness(
                    storage_enabled=True,
                    readiness_code="revoked",
                    readiness_label="Secret Revoked / Deleted",
                    has_secret=False,
                    status="revoked",
                    secret_version=None,
                    last_updated=conn.updated_at,
                    can_mutate=actor_can_mutate,
                    notice="Secret was revoked from storage backend.",
                )
            return BrokerReadiness(
                storage_enabled=True,
                readiness_code="awaiting_setup",
                readiness_label="Awaiting Credential Setup",
                has_secret=False,
                status=conn.status,
                secret_version=None,
                last_updated=conn.updated_at,
                can_mutate=actor_can_mutate,
                notice="No active secret reference linked to this connector.",
            )

        # Query live metadata from storage
        path = derive_tenant_secret_path(clean_t, clean_c, prefix=self.path_prefix)
        try:
            meta = self.storage.read_secret_metadata(path)
            if not meta.exists or meta.destroyed:
                readiness_code = "revoked"
                readiness_label = "Secret Revoked / Deleted"
                can_mutate = actor_can_mutate
                has_secret = False
                status = "revoked"
            elif conn.status == "verified":
                readiness_code = "verified"
                readiness_label = "Verified"
                can_mutate = actor_can_mutate
                has_secret = True
                status = "verified"
            elif conn.status == "revocation_failed":
                readiness_code = "revocation_failed"
                readiness_label = "Revocation Failed"
                can_mutate = False
                has_secret = True
                status = "revocation_failed"
            else:
                readiness_code = "stored"
                readiness_label = "Stored (Unverified)"
                can_mutate = actor_can_mutate
                has_secret = True
                status = conn.status

            return BrokerReadiness(
                storage_enabled=True,
                readiness_code=readiness_code,
                readiness_label=readiness_label,
                has_secret=has_secret,
                status=status,
                secret_version=meta.current_version if has_secret else None,
                last_updated=meta.updated_time or meta.created_time or conn.updated_at,
                can_mutate=can_mutate,
                notice=(
                    "Secret is stored in backend storage."
                    if has_secret
                    else "Secret revoked or absent in storage backend."
                ),
            )
        except Exception as e:
            logger.warning("Metadata query failed for %s: %s", path, e.__class__.__name__)
            return BrokerReadiness(
                storage_enabled=True,
                readiness_code="metadata_unavailable",
                readiness_label="Metadata Unavailable",
                has_secret=False,
                status="error",
                secret_version=None,
                last_updated=None,
                can_mutate=False,
                notice="Failed to verify secret metadata in storage backend.",
            )

    def register_secret(
        self,
        tenant_id: str | uuid.UUID,
        connector_id: str | uuid.UUID,
        payload: SecretPayload,
        auth_context: AuthorizationContext,
    ) -> dict[str, Any]:
        """Register a new credential in storage for a tenant connector.

        Enforces:
        - Strict AuthorizationContext requirement (rejects unauthenticated or untrusted callers fail-closed).
        - CAS=0 (create-if-absent) to prevent silent overwrite of pre-existing keys.
        - Eventual-consistency compensating rollback protecting EVERY post-write metadata operation.
        """
        self._ensure_enabled()
        clean_t = validate_identifier(tenant_id, "tenant_id")
        clean_c = validate_identifier(connector_id, "connector_id")

        if not isinstance(auth_context, AuthorizationContext):
            raise UnauthorizedActionError(
                "Missing or invalid AuthorizationContext. Explicit authorization context is required fail-closed."
            )

        actor_id = self._validate_actor(auth_context)

        # 1. Enforce actor policy
        self.policy_engine.enforce(
            auth_context=auth_context,
            action=CredentialAction.REGISTER,
            tenant_id=clean_t,
            connector_id=clean_c,
        )

        tenant_path = derive_tenant_secret_path(clean_t, clean_c, prefix=self.path_prefix)
        now_iso = datetime.now(timezone.utc).isoformat()

        storage_data = {
            "secret_type": payload.secret_type,
            "secret_value": payload.secret_value,
            "description": payload.description or "",
            "custom_metadata": payload.custom_metadata,
            "registered_at": now_iso,
        }

        # 2. Write to storage with cas=0 (create-if-absent)
        try:
            write_res = self.storage.write_secret(tenant_path, storage_data, cas=0)
        except CasMismatchError as cas_err:
            raise AgentGuardError(
                "A secret already exists at this path; registration aborted to prevent overwrite",
                code="secret_already_exists",
            ) from cas_err

        # 3. Post-write operations: COMPLETELY PROTECTED by compensating rollback try block
        try:
            opaque_ref = f"vault://{tenant_path}"
            conn = self.metadata_store.get_connection(clean_t, clean_c) or ConnectionMetadata(
                tenant_id=clean_t,
                connector_id=clean_c,
                created_at=now_iso,
            )
            conn.vault_secret_ref = opaque_ref
            conn.status = "stored"
            conn.secret_version = write_res.version
            conn.updated_at = now_iso

            self.metadata_store.save_connection(conn)
        except Exception as post_write_err:
            # Compensating rollback: delete ONLY the newly created version
            logger.error(
                "Post-write metadata operation failed for %s. Executing compensating rollback: %s",
                tenant_path,
                post_write_err.__class__.__name__,
            )
            recovery_id = str(uuid.uuid4())
            try:
                rollback_success = self.storage.delete_secret(
                    tenant_path, versions=[write_res.version]
                )
                if not rollback_success:
                    raise StorageError(
                        "Storage backend delete returned False during compensating rollback",
                        code="rollback_returned_false",
                    )
            except Exception as rollback_err:
                diag_code = rollback_err.__class__.__name__
                logger.critical(
                    "CRITICAL: Compensating version rollback failed for %s: %s",
                    tenant_path,
                    diag_code,
                )
                recovery_record = RollbackRecoveryRecord(
                    recovery_id=recovery_id,
                    tenant_id=clean_t,
                    connector_id=clean_c,
                    secret_path=tenant_path,
                    version=write_res.version,
                    action=CredentialAction.REGISTER.value,
                    error=diag_code,
                    timestamp=now_iso,
                )
                try:
                    self.metadata_store.save_recovery_record(recovery_record)
                except Exception as meta_save_err:
                    logger.critical(
                        "CRITICAL: Could not persist RollbackRecoveryRecord in metadata store: %s",
                        meta_save_err.__class__.__name__,
                    )

                # Safe structured error without raw backend error strings
                raise RollbackError(
                    "Compensating rollback failed following metadata persistence error.",
                    code="rollback_failed",
                    recovery_id=recovery_id,
                    tenant_id=clean_t,
                    connector_id=clean_c,
                    secret_path=tenant_path,
                    version=write_res.version,
                    action=CredentialAction.REGISTER.value,
                    diagnostic_code=diag_code,
                ) from rollback_err

            raise StorageError(
                "Failed to record credential metadata; secret version was rolled back.",
                code="metadata_persistence_failed",
            ) from post_write_err

        # 4. Record sanitized audit event
        raw_audit_meta = {
            "resource_type": payload.secret_type,
            "target_resource": clean_c,
            "version": write_res.version,
            "created_time": write_res.created_time,
        }
        sanitized_audit_meta = self.sanitizer.sanitize(raw_audit_meta)

        try:
            self.metadata_store.record_audit_event(
                AuditEventRecord(
                    event_id=str(uuid.uuid4()),
                    tenant_id=clean_t,
                    connector_id=clean_c,
                    actor=actor_id,
                    action=CredentialAction.REGISTER.value,
                    outcome="success",
                    metadata=sanitized_audit_meta,
                    timestamp=now_iso,
                )
            )
        except Exception as audit_err:
            logger.warning("Failed to record audit event: %s", audit_err.__class__.__name__)

        return {
            "success": True,
            "status": "stored",
            "version": write_res.version,
            "created_at": write_res.created_time,
            "readiness_code": "stored",
        }

    def rotate_secret(
        self,
        tenant_id: str | uuid.UUID,
        connector_id: str | uuid.UUID,
        payload: SecretPayload,
        auth_context: AuthorizationContext,
    ) -> dict[str, Any]:
        """Rotate an existing credential in storage, creating a new version.

        Enforces CAS against current active version to prevent lost concurrent updates,
        with complete post-write compensating rollback protection.
        """
        self._ensure_enabled()
        clean_t = validate_identifier(tenant_id, "tenant_id")
        clean_c = validate_identifier(connector_id, "connector_id")

        if not isinstance(auth_context, AuthorizationContext):
            raise UnauthorizedActionError(
                "Missing or invalid AuthorizationContext. Explicit authorization context is required fail-closed."
            )

        actor_id = self._validate_actor(auth_context)

        self.policy_engine.enforce(
            auth_context=auth_context,
            action=CredentialAction.ROTATE,
            tenant_id=clean_t,
            connector_id=clean_c,
        )

        conn = self.metadata_store.get_connection(clean_t, clean_c)
        if conn is None or not conn.vault_secret_ref:
            raise AgentGuardError(
                "Cannot rotate: connector has no existing secret reference. Use register instead.",
                code="no_existing_secret",
            )

        tenant_path = derive_tenant_secret_path(clean_t, clean_c, prefix=self.path_prefix)
        meta = self.storage.read_secret_metadata(tenant_path)
        if not meta.exists or meta.current_version is None:
            raise AgentGuardError(
                "Cannot rotate: secret does not exist in storage backend",
                code="no_secret_to_rotate",
            )

        now_iso = datetime.now(timezone.utc).isoformat()
        storage_data = {
            "secret_type": payload.secret_type,
            "secret_value": payload.secret_value,
            "description": payload.description or "",
            "custom_metadata": payload.custom_metadata,
            "rotated_at": now_iso,
        }

        # Write new version with CAS against current version
        try:
            write_res = self.storage.write_secret(
                tenant_path, storage_data, cas=meta.current_version
            )
        except CasMismatchError as cas_err:
            raise AgentGuardError(
                "Secret was modified concurrently; retry rotation with latest version",
                code="cas_mismatch",
            ) from cas_err

        # Post-write operations: COMPLETELY PROTECTED by compensating rollback try block
        try:
            conn.status = "stored"
            conn.secret_version = write_res.version
            conn.updated_at = now_iso

            self.metadata_store.save_connection(conn)
        except Exception as post_write_err:
            # Compensating rollback: delete ONLY newly rotated version
            logger.error(
                "Post-write metadata operation failed after rotation for %s. Executing version rollback: %s",
                tenant_path,
                post_write_err.__class__.__name__,
            )
            recovery_id = str(uuid.uuid4())
            try:
                rollback_success = self.storage.delete_secret(
                    tenant_path, versions=[write_res.version]
                )
                if not rollback_success:
                    raise StorageError(
                        "Storage backend delete returned False during compensating rollback",
                        code="rollback_returned_false",
                    )
            except Exception as rollback_err:
                diag_code = rollback_err.__class__.__name__
                logger.critical(
                    "CRITICAL: Compensating rotation rollback failed for %s: %s",
                    tenant_path,
                    diag_code,
                )
                recovery_record = RollbackRecoveryRecord(
                    recovery_id=recovery_id,
                    tenant_id=clean_t,
                    connector_id=clean_c,
                    secret_path=tenant_path,
                    version=write_res.version,
                    action=CredentialAction.ROTATE.value,
                    error=diag_code,
                    timestamp=now_iso,
                )
                try:
                    self.metadata_store.save_recovery_record(recovery_record)
                except Exception as meta_save_err:
                    logger.critical(
                        "CRITICAL: Could not persist RollbackRecoveryRecord in metadata store: %s",
                        meta_save_err.__class__.__name__,
                    )

                raise RollbackError(
                    "Compensating rotation rollback failed following metadata persistence error.",
                    code="rollback_failed",
                    recovery_id=recovery_id,
                    tenant_id=clean_t,
                    connector_id=clean_c,
                    secret_path=tenant_path,
                    version=write_res.version,
                    action=CredentialAction.ROTATE.value,
                    diagnostic_code=diag_code,
                ) from rollback_err

            raise StorageError(
                "Failed to record rotated credential metadata; rotated version was rolled back.",
                code="metadata_persistence_failed",
            ) from post_write_err

        raw_audit_meta = {
            "resource_type": payload.secret_type,
            "target_resource": clean_c,
            "version": write_res.version,
            "rotated_time": write_res.created_time,
        }
        sanitized_audit_meta = self.sanitizer.sanitize(raw_audit_meta)

        try:
            self.metadata_store.record_audit_event(
                AuditEventRecord(
                    event_id=str(uuid.uuid4()),
                    tenant_id=clean_t,
                    connector_id=clean_c,
                    actor=actor_id,
                    action=CredentialAction.ROTATE.value,
                    outcome="success",
                    metadata=sanitized_audit_meta,
                    timestamp=now_iso,
                )
            )
        except Exception as audit_err:
            logger.warning("Failed to record audit event: %s", audit_err.__class__.__name__)

        return {
            "success": True,
            "status": "stored",
            "version": write_res.version,
            "rotated_at": write_res.created_time,
            "readiness_code": "stored",
        }

    def revoke_secret(
        self,
        tenant_id: str | uuid.UUID,
        connector_id: str | uuid.UUID,
        auth_context: AuthorizationContext,
    ) -> dict[str, Any]:
        """Revoke a credential from storage.

        FAIL-CLOSED INVARIANT:
        If deletion fails or returns False, the metadata reference pointer is PRESERVED,
        status is set to revocation_failed, and RevocationError is raised without leaking
        raw backend exception details.
        """
        self._ensure_enabled()
        clean_t = validate_identifier(tenant_id, "tenant_id")
        clean_c = validate_identifier(connector_id, "connector_id")

        if not isinstance(auth_context, AuthorizationContext):
            raise UnauthorizedActionError(
                "Missing or invalid AuthorizationContext. Explicit authorization context is required fail-closed."
            )

        actor_id = self._validate_actor(auth_context)

        self.policy_engine.enforce(
            auth_context=auth_context,
            action=CredentialAction.REVOKE,
            tenant_id=clean_t,
            connector_id=clean_c,
        )

        conn = self.metadata_store.get_connection(clean_t, clean_c)
        if conn is None or not conn.vault_secret_ref:
            if conn:
                conn.status = "revoked"
                self.metadata_store.save_connection(conn)
            return {
                "success": True,
                "status": "revoked",
                "notice": "No active secret reference linked to connector.",
            }

        tenant_path = derive_tenant_secret_path(clean_t, clean_c, prefix=self.path_prefix)
        now_iso = datetime.now(timezone.utc).isoformat()

        # Delete from backend storage
        try:
            deleted = self.storage.delete_secret(tenant_path)
        except StorageNotFoundError:
            deleted = True
        except Exception as e:
            # FAIL-CLOSED: Preserve vault_secret_ref, update status to revocation_failed
            diag_code = e.__class__.__name__
            logger.error(
                "Storage secret deletion failed for %s: %s",
                tenant_path,
                diag_code,
            )
            conn.status = "revocation_failed"
            conn.updated_at = now_iso
            try:
                self.metadata_store.save_connection(conn)
            except Exception as save_err:
                logger.error(
                    "Failed to update status to revocation_failed: %s", save_err.__class__.__name__
                )

            try:
                sanitized_err_meta = self.sanitizer.sanitize({"error": diag_code})
                self.metadata_store.record_audit_event(
                    AuditEventRecord(
                        event_id=str(uuid.uuid4()),
                        tenant_id=clean_t,
                        connector_id=clean_c,
                        actor=actor_id,
                        action=CredentialAction.REVOKE.value,
                        outcome="failure",
                        metadata=sanitized_err_meta,
                        timestamp=now_iso,
                    )
                )
            except Exception:
                pass

            # Safe structured error without raw backend exception text
            raise RevocationError(
                "Failed to revoke secret in storage backend; metadata reference preserved.",
                code="revocation_failed",
            ) from e

        if not deleted:
            # Storage delete returned False: must fail-closed
            conn.status = "revocation_failed"
            conn.updated_at = now_iso
            self.metadata_store.save_connection(conn)
            raise RevocationError(
                "Storage backend returned False during deletion; metadata reference preserved.",
                code="revocation_failed",
            )

        # Deletion succeeded: Update metadata
        conn.vault_secret_ref = None
        conn.status = "revoked"
        conn.updated_at = now_iso
        self.metadata_store.save_connection(conn)

        try:
            sanitized_rev_meta = self.sanitizer.sanitize({"revoked_at": now_iso})
            self.metadata_store.record_audit_event(
                AuditEventRecord(
                    event_id=str(uuid.uuid4()),
                    tenant_id=clean_t,
                    connector_id=clean_c,
                    actor=actor_id,
                    action=CredentialAction.REVOKE.value,
                    outcome="success",
                    metadata=sanitized_rev_meta,
                    timestamp=now_iso,
                )
            )
        except Exception:
            pass

        return {
            "success": True,
            "status": "revoked",
            "readiness_code": "revoked",
            "notice": (
                "Secret soft-deleted from backend storage. External third-party credentials "
                "remain active externally until independently revoked at the third-party provider."
            ),
        }

    def get_connection_metadata(
        self,
        tenant_id: str | uuid.UUID,
        connector_id: str | uuid.UUID,
        auth_context: AuthorizationContext,
    ) -> ConnectionMetadata | None:
        """Retrieve sanitized connection metadata ensuring tenant boundary authorization."""
        clean_t = validate_identifier(tenant_id, "tenant_id")
        clean_c = validate_identifier(connector_id, "connector_id")

        if not isinstance(auth_context, AuthorizationContext) or not auth_context.is_authenticated:
            raise UnauthorizedActionError("Missing or unauthenticated AuthorizationContext.")

        self.policy_engine.enforce(
            auth_context=auth_context,
            action=CredentialAction.READ_METADATA,
            tenant_id=clean_t,
            connector_id=clean_c,
        )

        return self.metadata_store.get_connection(clean_t, clean_c)
