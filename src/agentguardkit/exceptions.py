"""Unified exception hierarchy for AgentGuardKit.

All exceptions inherit from AgentGuardError and provide machine-readable error codes.
"""

from __future__ import annotations


class AgentGuardError(Exception):
    """Base exception for all AgentGuardKit errors."""

    def __init__(self, message: str, code: str = "agent_guard_error"):
        super().__init__(message)
        self.message = message
        self.code = code


# -----------------------------------------------------------------------------
# Validation & Input Errors
# -----------------------------------------------------------------------------


class ValidationError(AgentGuardError):
    """Base error for parameter and format validation failures."""

    def __init__(self, message: str, code: str = "validation_error"):
        super().__init__(message, code=code)


class InvalidPathError(ValidationError):
    """Raised when tenant ID, connector ID, or generated path violates security constraints."""

    def __init__(
        self, message: str = "Invalid path or identifier format", code: str = "invalid_path"
    ):
        super().__init__(message, code=code)


class InvalidPayloadError(ValidationError):
    """Raised when secret or metadata payload violates schema or size constraints."""

    def __init__(self, message: str = "Payload validation failed", code: str = "invalid_payload"):
        super().__init__(message, code=code)


# -----------------------------------------------------------------------------
# Security & Policy Errors
# -----------------------------------------------------------------------------


class SecurityError(AgentGuardError):
    """Base error for security policy and access boundary violations."""

    def __init__(self, message: str, code: str = "security_error"):
        super().__init__(message, code=code)


class InsecureTransportError(SecurityError):
    """Raised when an unencrypted HTTP connection is attempted for non-loopback endpoints."""

    def __init__(
        self,
        message: str = "Insecure transport: remote endpoints must use HTTPS",
        code: str = "insecure_transport",
    ):
        super().__init__(message, code=code)


class UnsafeRedirectError(SecurityError):
    """Raised when an HTTP redirect attempts cross-domain or credential-leaking navigation."""

    def __init__(
        self,
        message: str = "Unsafe redirect rejected to prevent credential forwarding",
        code: str = "unsafe_redirect",
    ):
        super().__init__(message, code=code)


class UnauthorizedActionError(SecurityError):
    """Raised when an agent role attempts an action denied by capability policy."""

    def __init__(
        self,
        message: str = "Action denied by agent capability policy",
        code: str = "unauthorized_action",
    ):
        super().__init__(message, code=code)


class TenantMismatchError(SecurityError):
    """Raised when attempting an operation across conflicting or mismatched tenant scopes."""

    def __init__(
        self,
        message: str = "Tenant boundary violation: cross-tenant access prohibited",
        code: str = "tenant_mismatch",
    ):
        super().__init__(message, code=code)


# -----------------------------------------------------------------------------
# Storage & Backend Errors
# -----------------------------------------------------------------------------


class StorageError(AgentGuardError):
    """Base error for storage engine and adapter failures."""

    def __init__(self, message: str, code: str = "storage_error"):
        super().__init__(message, code=code)


class StorageConnectionError(StorageError):
    """Raised when the backend storage engine cannot be reached or times out."""

    def __init__(
        self,
        message: str = "Storage backend unreachable or timed out",
        code: str = "storage_unreachable",
    ):
        super().__init__(message, code=code)


class StorageAuthenticationError(StorageError):
    """Raised when storage backend authentication (e.g. Vault token) fails or is invalid."""

    def __init__(
        self,
        message: str = "Storage backend authentication failed",
        code: str = "storage_auth_failed",
    ):
        super().__init__(message, code=code)


class StoragePermissionDeniedError(StorageError):
    """Raised when storage credentials lack permissions for the specified path."""

    def __init__(
        self,
        message: str = "Storage policy denies access to this path",
        code: str = "storage_permission_denied",
    ):
        super().__init__(message, code=code)


class StorageNotFoundError(StorageError):
    """Raised when secret or metadata does not exist at the requested path."""

    def __init__(
        self,
        message: str = "Secret or path not found in storage",
        code: str = "storage_not_found",
    ):
        super().__init__(message, code=code)


class StorageSealedError(StorageError):
    """Raised when the storage cluster (e.g. HashiCorp Vault) is sealed or unavailable."""

    def __init__(
        self,
        message: str = "Storage cluster is currently sealed or standby",
        code: str = "storage_sealed",
    ):
        super().__init__(message, code=code)


class CasMismatchError(StorageError):
    """Raised when a check-and-set (CAS) optimistic concurrency precondition fails."""

    def __init__(
        self,
        message: str = "CAS precondition failed: version mismatch or key exists",
        code: str = "cas_mismatch",
    ):
        super().__init__(message, code=code)


class RevocationError(StorageError):
    """Raised when secret revocation fails in the storage engine."""

    def __init__(
        self,
        message: str = "Failed to revoke secret in storage backend",
        code: str = "revocation_failed",
    ):
        super().__init__(message, code=code)


class RollbackError(AgentGuardError):
    """Raised when a compensating rollback fails following a metadata persistence failure.

    Carries safe, structured diagnostic identifiers without raw backend exception text.
    """

    def __init__(
        self,
        message: str = "Compensating rollback failed in storage engine",
        code: str = "rollback_failed",
        recovery_id: str | None = None,
        tenant_id: str | None = None,
        connector_id: str | None = None,
        secret_path: str | None = None,
        version: int | None = None,
        action: str | None = None,
        diagnostic_code: str | None = None,
    ):
        super().__init__(message, code=code)
        self.recovery_id = recovery_id
        self.tenant_id = tenant_id
        self.connector_id = connector_id
        self.secret_path = secret_path
        self.version = version
        self.action = action
        self.diagnostic_code = diagnostic_code
