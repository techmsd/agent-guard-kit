"""Unit tests for MockVaultStorage with multi-versioning and fault injection."""

import pytest

from agentguardkit.exceptions import (
    CasMismatchError,
    StorageAuthenticationError,
    StorageConnectionError,
    StoragePermissionDeniedError,
    StorageSealedError,
)
from agentguardkit.storage.memory import MockVaultStorage


@pytest.fixture
def store():
    s = MockVaultStorage()
    s.reset()
    return s


def test_write_and_read_metadata(store):
    path = "tenants/t1/connectors/c1"
    res1 = store.write_secret(path, {"token": "secret1"}, cas=0)
    assert res1.version == 1

    meta1 = store.read_secret_metadata(path)
    assert meta1.exists is True
    assert meta1.current_version == 1
    assert meta1.destroyed is False

    # Rotate to v2
    res2 = store.write_secret(path, {"token": "secret2"}, cas=1)
    assert res2.version == 2

    meta2 = store.read_secret_metadata(path)
    assert meta2.current_version == 2


def test_cas_0_rejects_existing_key(store):
    path = "tenants/t1/connectors/c1"
    store.write_secret(path, {"token": "v1"}, cas=0)

    with pytest.raises(CasMismatchError):
        store.write_secret(path, {"token": "overwrite"}, cas=0)


def test_cas_version_mismatch(store):
    path = "tenants/t1/connectors/c1"
    store.write_secret(path, {"token": "v1"}, cas=0)

    # Wrong expected version
    with pytest.raises(CasMismatchError):
        store.write_secret(path, {"token": "v2"}, cas=99)


def test_soft_delete_preserves_older_versions(store):
    path = "tenants/t1/connectors/c1"
    store.write_secret(path, {"token": "v1"})
    store.write_secret(path, {"token": "v2"})

    # Soft delete latest version
    assert store.delete_secret(path) is True

    # Current version is marked destroyed in metadata
    meta = store.read_secret_metadata(path)
    assert meta.destroyed is True

    # Version 1 is still intact in internal history
    internal_entry = store._store[path]
    assert internal_entry["versions"][1]["destroyed"] is False
    assert internal_entry["versions"][1]["data"]["token"] == "v1"
    assert internal_entry["versions"][2]["destroyed"] is True


def test_fault_injection_toggles(store):
    path = "tenants/t1/connectors/c1"

    # 1. Timeout
    store.simulated_timeout = True
    with pytest.raises(StorageConnectionError):
        store.write_secret(path, {"k": "v"})
    health = store.health_check()
    assert health.reachable is False
    store.simulated_timeout = False

    # 2. Auth failure
    store.simulated_auth_failure = True
    with pytest.raises(StorageAuthenticationError):
        store.write_secret(path, {"k": "v"})
    store.simulated_auth_failure = False

    # 3. Permission denied
    store.simulated_permission_denied = True
    with pytest.raises(StoragePermissionDeniedError):
        store.read_secret_metadata(path)
    store.simulated_permission_denied = False

    # 4. Sealed
    store.simulated_sealed = True
    with pytest.raises(StorageSealedError):
        store.write_secret(path, {"k": "v"})
    health = store.health_check()
    assert health.sealed is True
    store.simulated_sealed = False

    # 5. Delete returns False
    store.simulated_delete_returns_false = True
    assert store.delete_secret(path) is False
    store.simulated_delete_returns_false = False

    # 6. Delete failure raises error
    store.simulated_delete_failure = True
    with pytest.raises(StorageConnectionError):
        store.delete_secret(path)
    store.simulated_delete_failure = False

    # 7. Metadata failure
    store.simulated_metadata_failure = True
    with pytest.raises(StorageConnectionError):
        store.read_secret_metadata(path)
    store.simulated_metadata_failure = False
