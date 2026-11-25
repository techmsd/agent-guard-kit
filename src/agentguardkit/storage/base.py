"""Abstract protocol defining the secret storage backend interface."""

from __future__ import annotations

import abc
from typing import Any

from ..interfaces import SecretMetadataResult, SecretWriteResult, StorageHealthStatus


class SecretStorageBackend(abc.ABC):
    """Abstract interface for secret engines (HashiCorp Vault, mock in-memory, etc.)."""

    @abc.abstractmethod
    def write_secret(
        self,
        path: str,
        data: dict[str, Any],
        cas: int | None = None,
    ) -> SecretWriteResult:
        """Store or rotate a secret at the specified path.

        Args:
            path: Relative storage path.
            data: Secret payload dictionary.
            cas: Optional check-and-set version precondition. If cas=0, key must not exist.
        """
        ...

    @abc.abstractmethod
    def read_secret_metadata(self, path: str) -> SecretMetadataResult:
        """Inspect secret existence and metadata without retrieving secret values."""
        ...

    @abc.abstractmethod
    def delete_secret(self, path: str, versions: list[int] | None = None) -> bool:
        """Revoke or soft-delete secret data at the specified path.

        Args:
            path: Relative storage path.
            versions: Specific versions to delete. If None, deletes the latest active version.
        Returns:
            True if deletion succeeded, False if deletion returned non-success.
        """
        ...

    @abc.abstractmethod
    def health_check(self) -> StorageHealthStatus:
        """Probe storage reachability, initialization, and seal status."""
        ...
