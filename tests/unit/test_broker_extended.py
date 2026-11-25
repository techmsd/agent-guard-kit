"""Extended unit tests covering broker edge cases and testing exports."""

from unittest.mock import patch

import pytest

from agentguardkit.broker import CredentialBroker
from agentguardkit.exceptions import (
    AgentGuardError,
    RollbackError,
    StorageNotFoundError,
    UnauthorizedActionError,
)
from agentguardkit.interfaces import SecretPayload
from agentguardkit.metadata.base import ConnectionMetadata
from agentguardkit.metadata.memory import InMemoryMetadataStore
from agentguardkit.policy import AuthorizationContext
from agentguardkit.testing import MockVaultStorage


def test_testing_module_export():
    m = MockVaultStorage()
    assert m is not None


def test_readiness_probe_unreachable_and_sealed():
    storage = MockVaultStorage()
    metadata_store = InMemoryMetadataStore()
    broker = CredentialBroker(storage=storage, metadata_store=metadata_store)

    # 1. Unreachable
    storage.simulated_timeout = True
    r_unreachable = broker.get_readiness_status()
    assert r_unreachable.readiness_code == "storage_unreachable"
    assert r_unreachable.can_mutate is False
    assert r_unreachable.has_secret is False
    storage.simulated_timeout = False

    # 2. Sealed
    storage.simulated_sealed = True
    r_sealed = broker.get_readiness_status()
    assert r_sealed.readiness_code == "storage_sealed"
    assert r_sealed.can_mutate is False
    assert r_sealed.has_secret is False
    storage.simulated_sealed = False


def test_readiness_probe_uninitialized_and_standby(broker):
    # Uninitialized
    with patch.object(
        broker.storage,
        "health_check",
        return_value=type(
            "Health",
            (),
            {"reachable": True, "initialized": False, "sealed": False, "standby": False},
        )(),
    ):
        r_uninit = broker.get_readiness_status()
        assert r_uninit.readiness_code == "storage_uninitialized"
        assert r_uninit.can_mutate is False

    # Standby
    with patch.object(
        broker.storage,
        "health_check",
        return_value=type(
            "Health",
            (),
            {"reachable": True, "initialized": True, "sealed": False, "standby": True},
        )(),
    ):
        r_standby = broker.get_readiness_status()
        assert r_standby.readiness_code == "storage_standby"
        assert r_standby.can_mutate is False


def test_readiness_enforces_read_metadata_policy(broker, readonly_auth, admin_auth):
    from agentguardkit.policy import AgentRole

    tenant_id = "t_ready_auth"
    connector_id = "c_ready_auth"
    p = SecretPayload(secret_type="key", secret_value="val")
    broker.register_secret(tenant_id, connector_id, p, auth_context=admin_auth)

    # Specialist agent lacks READ_METADATA authority -> raises UnauthorizedActionError
    specialist_auth = AuthorizationContext(
        actor_id="agent_specialist_1",
        role=AgentRole.SPECIALIST,
        permitted_tenants=frozenset({"*"}),
        is_authenticated=True,
    )
    with pytest.raises(UnauthorizedActionError) as exc:
        broker.get_readiness_status(tenant_id, connector_id, auth_context=specialist_auth)
    assert "Unauthorized action" in str(exc.value)

    # Read-only auditor has READ_METADATA authority -> succeeds, but can_mutate MUST be False
    r_auditor = broker.get_readiness_status(tenant_id, connector_id, auth_context=readonly_auth)
    assert r_auditor.has_secret is True
    assert r_auditor.can_mutate is False

    # Human admin has mutation authority -> can_mutate is True
    r_admin = broker.get_readiness_status(tenant_id, connector_id, auth_context=admin_auth)
    assert r_admin.has_secret is True
    assert r_admin.can_mutate is True


def test_rotate_without_existing_secret_raises(broker, admin_auth):
    p = SecretPayload(secret_type="key", secret_value="v1")
    with pytest.raises(AgentGuardError) as exc:
        broker.rotate_secret("t_nonexistent", "c_nonexistent", p, auth_context=admin_auth)
    assert exc.value.code == "no_existing_secret"


def test_rotate_when_absent_in_storage_raises(broker, admin_auth):
    tenant_id = "tenant_missing_storage"
    connector_id = "conn_missing_storage"
    p = SecretPayload(secret_type="key", secret_value="v1")

    # Manually register in metadata with a reference, but delete from storage
    broker.register_secret(tenant_id, connector_id, p, auth_context=admin_auth)
    path = f"tenants/{tenant_id}/connectors/{connector_id}"
    del broker.storage._store[path]

    with pytest.raises(AgentGuardError) as exc:
        broker.rotate_secret(tenant_id, connector_id, p, auth_context=admin_auth)
    assert exc.value.code == "no_secret_to_rotate"


def test_revoke_without_secret_ref(broker, admin_auth):
    res = broker.revoke_secret("t_empty", "c_empty", auth_context=admin_auth)
    assert res["success"] is True
    assert "No active secret reference linked" in res["notice"]


def test_audit_failure_does_not_abort_operation(broker, admin_auth):
    # If audit event recording fails, the main credential operation should still succeed
    broker.metadata_store.simulated_audit_failure = True
    p = SecretPayload(secret_type="key", secret_value="v1")
    res = broker.register_secret("t_audit_fail", "c_audit_fail", p, auth_context=admin_auth)
    assert res["success"] is True
    assert res["status"] == "stored"


def test_get_connection_metadata_requires_auth(broker, admin_auth):
    p = SecretPayload(secret_type="key", secret_value="v1")
    broker.register_secret("t_meta", "c_meta", p, auth_context=admin_auth)

    # Valid query
    meta = broker.get_connection_metadata("t_meta", "c_meta", auth_context=admin_auth)
    assert meta is not None
    assert meta.tenant_id == "t_meta"

    # Unauthorized tenant query
    unauth_ctx = AuthorizationContext(
        actor_id="tenant_x_only",
        role="human_admin",
        permitted_tenants=frozenset({"other_tenant"}),
        is_authenticated=True,
    )
    with pytest.raises(UnauthorizedActionError):
        broker.get_connection_metadata("t_meta", "c_meta", auth_context=unauth_ctx)


def test_readiness_status_revoked_and_unverified(broker, admin_auth):
    # Test conn exists without secret ref and status != revoked
    broker.metadata_store.save_connection(
        ConnectionMetadata(
            tenant_id="t_awaiting",
            connector_id="c_awaiting",
            vault_secret_ref=None,
            status="pending_setup",
        )
    )
    r = broker.get_readiness_status("t_awaiting", "c_awaiting", auth_context=admin_auth)
    assert r.readiness_code == "awaiting_setup"
    assert r.has_secret is False


def test_readiness_status_verified(broker, admin_auth):
    p = SecretPayload(secret_type="key", secret_value="v1")
    broker.register_secret("t_ver", "c_ver", p, auth_context=admin_auth)
    conn = broker.metadata_store.get_connection("t_ver", "c_ver")
    assert conn is not None
    conn.status = "verified"
    broker.metadata_store.save_connection(conn)

    r = broker.get_readiness_status("t_ver", "c_ver", auth_context=admin_auth)
    assert r.readiness_code == "verified"
    assert r.has_secret is True


def test_rotate_rollback_failure_creates_recovery_record(broker, admin_auth):
    tenant_id = "t_rot_fail"
    connector_id = "c_rot_fail"
    p = SecretPayload(secret_type="key", secret_value="v1")
    broker.register_secret(tenant_id, connector_id, p, auth_context=admin_auth)

    broker.metadata_store.simulated_save_failure = True
    broker.storage.simulated_delete_failure = True
    p2 = SecretPayload(secret_type="key", secret_value="v2")

    with pytest.raises(RollbackError) as exc:
        broker.rotate_secret(tenant_id, connector_id, p2, auth_context=admin_auth)
    assert "rollback failed" in str(exc.value).lower()
    assert exc.value.diagnostic_code == "StorageConnectionError"

    records = broker.metadata_store.get_recovery_records(tenant_id=tenant_id)
    assert len(records) == 1
    assert records[0].version == 2


def test_revoke_secret_storage_not_found_handled(broker, admin_auth):
    tenant_id = "t_rev_404"
    connector_id = "c_rev_404"
    p = SecretPayload(secret_type="key", secret_value="v1")
    broker.register_secret(tenant_id, connector_id, p, auth_context=admin_auth)

    with patch.object(
        broker.storage, "delete_secret", side_effect=StorageNotFoundError("Already gone")
    ):
        res = broker.revoke_secret(tenant_id, connector_id, auth_context=admin_auth)
        assert res["success"] is True
        assert res["status"] == "revoked"
