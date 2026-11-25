"""Thread-safe in-memory mock Vault KV v2 storage with fault injection for tests."""

from __future__ import annotations

import copy
import threading
from datetime import datetime, timezone
from typing import Any

from ..exceptions import (
    CasMismatchError,
    StorageAuthenticationError,
    StorageConnectionError,
    StoragePermissionDeniedError,
    StorageSealedError,
)
from ..interfaces import SecretMetadataResult, SecretWriteResult, StorageHealthStatus
from .base import SecretStorageBackend


class MockVaultStorage(SecretStorageBackend):
    """In-memory simulation of HashiCorp Vault Key-Value Version 2 engine.

    Supports multi-version history, CAS preconditions, soft-deletion semantics,
    and granular fault-injection toggles for negative security testing.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        # Structure: { path: { "current_version": int, "versions": { int: { "data": dict, "created_time": str, "destroyed": bool } } } }
        self._store: dict[str, dict[str, Any]] = {}

        # Fault injection toggles
        self.simulated_timeout: bool = False
        self.simulated_sealed: bool = False
        self.simulated_auth_failure: bool = False
        self.simulated_permission_denied: bool = False
        self.simulated_delete_failure: bool = False
        self.simulated_delete_returns_false: bool = False
        self.simulated_metadata_failure: bool = False
        self.simulated_cas_mismatch: bool = False

    def reset(self) -> None:
        """Clear all stored data and reset all fault injection toggles."""
        with self._lock:
            self._store.clear()
            self.simulated_timeout = False
            self.simulated_sealed = False
            self.simulated_auth_failure = False
            self.simulated_permission_denied = False
            self.simulated_delete_failure = False
            self.simulated_delete_returns_false = False
            self.simulated_metadata_failure = False
            self.simulated_cas_mismatch = False

    def _check_faults(self) -> None:
        if self.simulated_timeout:
            raise StorageConnectionError("Simulated connection timeout to storage engine")
        if self.simulated_auth_failure:
            raise StorageAuthenticationError("Simulated token expired or invalid")
        if self.simulated_permission_denied:
            raise StoragePermissionDeniedError("Simulated policy denies access to this path")
        if self.simulated_sealed:
            raise StorageSealedError("Simulated storage cluster is sealed")
        if self.simulated_cas_mismatch:
            raise CasMismatchError("Simulated CAS precondition failure")

    def write_secret(
        self,
        path: str,
        data: dict[str, Any],
        cas: int | None = None,
    ) -> SecretWriteResult:
        self._check_faults()
        clean_path = path.strip("/")
        now_iso = datetime.now(timezone.utc).isoformat()

        with self._lock:
            entry = self._store.get(clean_path)
            if entry is None:
                if cas is not None and cas != 0:
                    raise CasMismatchError(
                        f"CAS precondition failed: key does not exist, expected version {cas}"
                    )
                new_version = 1
                entry = {
                    "current_version": new_version,
                    "versions": {
                        new_version: {
                            "data": copy.deepcopy(data),
                            "created_time": now_iso,
                            "destroyed": False,
                        }
                    },
                }
                self._store[clean_path] = entry
            else:
                if cas == 0:
                    raise CasMismatchError(
                        "CAS precondition failed: key already exists at path (cas=0 requires absent key)"
                    )
                if cas is not None and entry["current_version"] != cas:
                    raise CasMismatchError(
                        f"CAS precondition failed: expected version {cas}, current is {entry['current_version']}"
                    )
                new_version = entry["current_version"] + 1
                entry["current_version"] = new_version
                entry["versions"][new_version] = {
                    "data": copy.deepcopy(data),
                    "created_time": now_iso,
                    "destroyed": False,
                }

            return SecretWriteResult(version=new_version, created_time=now_iso, destroyed=False)

    def read_secret_metadata(self, path: str) -> SecretMetadataResult:
        self._check_faults()
        if self.simulated_metadata_failure:
            raise StorageConnectionError("Simulated metadata query failure")
        clean_path = path.strip("/")

        with self._lock:
            entry = self._store.get(clean_path)
            if entry is None:
                return SecretMetadataResult(exists=False)

            cur_v = entry["current_version"]
            v_meta = entry["versions"].get(cur_v, {})
            is_destroyed = v_meta.get("destroyed", False)

            return SecretMetadataResult(
                exists=True,
                current_version=cur_v,
                created_time=entry["versions"].get(1, {}).get("created_time"),
                updated_time=v_meta.get("created_time"),
                destroyed=is_destroyed,
            )

    def delete_secret(self, path: str, versions: list[int] | None = None) -> bool:
        self._check_faults()
        if self.simulated_delete_failure:
            raise StorageConnectionError("Simulated connection error during secret deletion")
        if self.simulated_delete_returns_false:
            return False

        clean_path = path.strip("/")
        with self._lock:
            entry = self._store.get(clean_path)
            if entry is None:
                return False

            if versions:
                for v in versions:
                    if v in entry["versions"]:
                        entry["versions"][v]["destroyed"] = True
            else:
                cur_v = entry.get("current_version")
                if cur_v and cur_v in entry["versions"]:
                    entry["versions"][cur_v]["destroyed"] = True

            return True

    def health_check(self) -> StorageHealthStatus:
        if self.simulated_timeout:
            return StorageHealthStatus(
                initialized=False,
                sealed=False,
                standby=False,
                reachable=False,
                error="Simulated connection timeout",
            )
        if self.simulated_sealed:
            return StorageHealthStatus(
                initialized=True,
                sealed=True,
                standby=False,
                reachable=True,
                error="Simulated cluster sealed",
            )
        return StorageHealthStatus(
            initialized=True,
            sealed=False,
            standby=False,
            reachable=True,
            server_time=datetime.now(timezone.utc).isoformat(),
        )
