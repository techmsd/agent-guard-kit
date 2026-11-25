"""AgentGuardKit: Tenant-isolated credential brokering, capability policies, and audit sanitization for AI agents."""

from __future__ import annotations

__version__ = "0.1.0a1"

from .audit.sanitizer import AuditSanitizer, scrub_string
from .broker import CredentialBroker
from .exceptions import (
    AgentGuardError,
    CasMismatchError,
    InsecureTransportError,
    InvalidPathError,
    InvalidPayloadError,
    RevocationError,
    RollbackError,
    SecurityError,
    StorageAuthenticationError,
    StorageConnectionError,
    StorageError,
    StorageNotFoundError,
    StoragePermissionDeniedError,
    StorageSealedError,
    TenantMismatchError,
    UnauthorizedActionError,
    UnsafeRedirectError,
    ValidationError,
)
from .interfaces import (
    BrokerReadiness,
    SecretMetadataResult,
    SecretPayload,
    SecretWriteResult,
    StorageHealthStatus,
)
from .metadata.base import (
    AuditEventRecord,
    ConnectionMetadata,
    CredentialMetadataStore,
    RollbackRecoveryRecord,
)
from .metadata.memory import InMemoryMetadataStore
from .path import derive_tenant_secret_path, validate_identifier
from .policy import AgentRole, AuthorizationContext, CredentialAction, PolicyDecision, PolicyEngine
from .storage.base import SecretStorageBackend
from .storage.kv2 import HashiCorpVaultKV2Storage
from .storage.memory import MockVaultStorage

__all__ = [
    "AgentGuardError",
    "AgentRole",
    "AuditEventRecord",
    "AuditSanitizer",
    "AuthorizationContext",
    "BrokerReadiness",
    "CasMismatchError",
    "ConnectionMetadata",
    "CredentialAction",
    "CredentialBroker",
    "CredentialMetadataStore",
    "HashiCorpVaultKV2Storage",
    "InMemoryMetadataStore",
    "InsecureTransportError",
    "InvalidPathError",
    "InvalidPayloadError",
    "MockVaultStorage",
    "PolicyDecision",
    "PolicyEngine",
    "RevocationError",
    "RollbackError",
    "RollbackRecoveryRecord",
    "SecretMetadataResult",
    "SecretPayload",
    "SecretStorageBackend",
    "SecretWriteResult",
    "SecurityError",
    "StorageAuthenticationError",
    "StorageConnectionError",
    "StorageError",
    "StorageHealthStatus",
    "StorageNotFoundError",
    "StoragePermissionDeniedError",
    "StorageSealedError",
    "TenantMismatchError",
    "UnauthorizedActionError",
    "UnsafeRedirectError",
    "ValidationError",
    "__version__",
    "derive_tenant_secret_path",
    "scrub_string",
    "validate_identifier",
]
