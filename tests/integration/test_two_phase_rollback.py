"""Integration tests for version-scoped compensating rollback on partial failures."""

from unittest.mock import patch

import pytest

from agentguardkit.exceptions import RollbackError, StorageError
from agentguardkit.interfaces import SecretPayload
from agentguardkit.path import derive_tenant_secret_path


def test_registration_rollback_on_metadata_failure(broker, admin_auth):
    tenant_id = "tenant_rollback_1"
    connector_id = "pabbly_key"
    path = derive_tenant_secret_path(tenant_id, connector_id)

    # Enable simulated metadata failure
    broker.metadata_store.simulated_save_failure = True
    payload = SecretPayload(secret_type="api_key", secret_value="synthetic_val")

    with pytest.raises(StorageError) as exc:
        broker.register_secret(tenant_id, connector_id, payload, auth_context=admin_auth)
    assert exc.value.code == "metadata_persistence_failed"

    # Verify compensating rollback executed in storage
    meta = broker.storage.read_secret_metadata(path)
    # The written version was deleted/destroyed by rollback
    assert meta.destroyed is True


def test_registration_rollback_on_metadata_retrieval_failure(broker, admin_auth):
    tenant_id = "tenant_rollback_retrieval"
    connector_id = "slack_key"
    path = derive_tenant_secret_path(tenant_id, connector_id)

    payload = SecretPayload(secret_type="api_key", secret_value="synthetic_val")

    # Simulate get_connection failure after storage write has completed
    with patch.object(
        broker.metadata_store,
        "get_connection",
        side_effect=StorageError("Database connection dropped during retrieval"),
    ):
        with pytest.raises(StorageError) as exc:
            broker.register_secret(tenant_id, connector_id, payload, auth_context=admin_auth)
        assert exc.value.code == "metadata_persistence_failed"

    # Invariant: Compensating rollback must have executed to delete the version in storage
    meta = broker.storage.read_secret_metadata(path)
    assert meta.destroyed is True


def test_rotation_rollback_preserves_previous_version(broker, admin_auth):
    tenant_id = "tenant_rollback_2"
    connector_id = "meta_token"
    path = derive_tenant_secret_path(tenant_id, connector_id)

    # Step 1: Register v1 successfully
    p1 = SecretPayload(secret_type="token", secret_value="secret_version_1")
    res1 = broker.register_secret(tenant_id, connector_id, p1, auth_context=admin_auth)
    assert res1["version"] == 1

    # Step 2: Trigger metadata failure during rotation
    broker.metadata_store.simulated_save_failure = True
    p2 = SecretPayload(secret_type="token", secret_value="secret_version_2")

    with pytest.raises(StorageError) as exc:
        broker.rotate_secret(tenant_id, connector_id, p2, auth_context=admin_auth)
    assert exc.value.code == "metadata_persistence_failed"

    # Step 3: Verify version-scoped rollback
    # v2 was rolled back (destroyed), but v1 survives intact
    internal_entry = broker.storage._store[path]
    assert internal_entry["versions"][2]["destroyed"] is True
    assert internal_entry["versions"][1]["destroyed"] is False
    assert internal_entry["versions"][1]["data"]["secret_value"] == "secret_version_1"


def test_catastrophic_failure_creates_recovery_record_and_raises_rollback_error(broker, admin_auth):
    tenant_id = "tenant_rollback_3"
    connector_id = "stripe_key"

    # Trigger both metadata save failure and storage deletion failure
    broker.metadata_store.simulated_save_failure = True
    broker.storage.simulated_delete_failure = True

    payload = SecretPayload(secret_type="key", secret_value="val")
    with pytest.raises(RollbackError) as exc:
        broker.register_secret(tenant_id, connector_id, payload, auth_context=admin_auth)
    assert "compensating rollback failed" in str(exc.value).lower()

    # Verify safe structured error attributes (no raw strings)
    assert exc.value.tenant_id == tenant_id
    assert exc.value.connector_id == connector_id
    assert exc.value.version == 1
    assert exc.value.diagnostic_code == "StorageConnectionError"

    # Verify RollbackRecoveryRecord was persisted
    records = broker.metadata_store.get_recovery_records(tenant_id=tenant_id)
    assert len(records) == 1
    rec = records[0]
    assert rec.tenant_id == tenant_id
    assert rec.connector_id == connector_id
    assert rec.version == 1
    assert rec.error == "StorageConnectionError"


def test_rollback_delete_returns_false_creates_recovery_record(broker, admin_auth):
    tenant_id = "tenant_rollback_false"
    connector_id = "stripe_key"

    broker.metadata_store.simulated_save_failure = True
    broker.storage.simulated_delete_returns_false = True

    payload = SecretPayload(secret_type="key", secret_value="val")
    with pytest.raises(RollbackError) as exc:
        broker.register_secret(tenant_id, connector_id, payload, auth_context=admin_auth)
    assert exc.value.code == "rollback_failed"
    assert exc.value.diagnostic_code == "StorageError"

    records = broker.metadata_store.get_recovery_records(tenant_id=tenant_id)
    assert len(records) == 1


def test_recovery_record_failure_does_not_mask_rollback_error(broker, admin_auth):
    tenant_id = "tenant_double_failure"
    connector_id = "webhook_key"

    # Both metadata save, storage delete, and recovery record save fail
    broker.metadata_store.simulated_save_failure = True
    broker.storage.simulated_delete_failure = True

    payload = SecretPayload(secret_type="key", secret_value="val")

    with patch.object(
        broker.metadata_store,
        "save_recovery_record",
        side_effect=StorageError("Metadata store totally offline"),
    ):
        with pytest.raises(RollbackError) as exc:
            broker.register_secret(tenant_id, connector_id, payload, auth_context=admin_auth)
        # Invariant: Structured RollbackError is still raised with full recovery context attached!
        assert exc.value.tenant_id == tenant_id
        assert exc.value.connector_id == connector_id
        assert exc.value.version == 1
        assert exc.value.recovery_id is not None
