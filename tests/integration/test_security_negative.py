"""Negative security tests verifying strict boundaries, leak prevention, and fail-closed state."""

from unittest.mock import patch

import pytest

from agentguardkit.exceptions import (
    InvalidPathError,
    RevocationError,
    RollbackError,
    StorageError,
    UnauthorizedActionError,
)
from agentguardkit.interfaces import SecretPayload
from agentguardkit.policy import AgentRole, AuthorizationContext

SYNTHETIC_LEAK_TARGET = "UNREDACTED_SUPER_SECRET_TOKEN_DO_NOT_LEAK"


def test_zero_secret_leakage_in_exceptions(broker, admin_auth):
    payload = SecretPayload(secret_type="api_key", secret_value=SYNTHETIC_LEAK_TARGET)
    # Trigger an error by invalid identifier
    with pytest.raises(InvalidPathError) as exc:
        broker.register_secret("../traversal", "connector", payload, auth_context=admin_auth)
    assert SYNTHETIC_LEAK_TARGET not in str(exc.value)


def test_zero_secret_leakage_in_audit_records(broker, admin_auth):
    tenant_id = "tenant_audit_test"
    connector_id = "conn_audit_test"
    payload = SecretPayload(secret_type="api_key", secret_value=SYNTHETIC_LEAK_TARGET)

    broker.register_secret(tenant_id, connector_id, payload, auth_context=admin_auth)
    broker.rotate_secret(
        tenant_id,
        connector_id,
        SecretPayload(secret_type="api_key", secret_value="another_secret"),
        auth_context=admin_auth,
    )

    events = broker.metadata_store.get_audit_events(tenant_id=tenant_id)
    assert len(events) >= 2
    for event in events:
        event_str = str(event)
        assert SYNTHETIC_LEAK_TARGET not in event_str
        assert "another_secret" not in event_str


def test_synthetic_sentinel_not_leaked_in_backend_exceptions(broker, admin_auth):
    """Ensure raw backend exception text containing secrets is NEVER leaked into public errors."""
    tenant_id = "tenant_sentinel_rev"
    connector_id = "conn_sentinel_rev"
    payload = SecretPayload(secret_type="key", secret_value="val")
    broker.register_secret(tenant_id, connector_id, payload, auth_context=admin_auth)

    # Simulate backend deletion raising exception with sensitive token in error text
    leaky_backend_exception = StorageError(
        f"Vault error communicating with token {SYNTHETIC_LEAK_TARGET}"
    )

    with patch.object(broker.storage, "delete_secret", side_effect=leaky_backend_exception):
        with pytest.raises(RevocationError) as exc:
            broker.revoke_secret(tenant_id, connector_id, auth_context=admin_auth)

        # Invariant: The exception message MUST NOT contain the raw backend error string
        assert SYNTHETIC_LEAK_TARGET not in str(exc.value)

    # Also verify in audit record
    events = broker.metadata_store.get_audit_events(tenant_id=tenant_id)
    latest_event = events[0]
    assert SYNTHETIC_LEAK_TARGET not in str(latest_event)


def test_synthetic_sentinel_not_leaked_in_rollback_recovery(broker, admin_auth):
    """Ensure raw backend exception in rollback does NOT leak into RollbackError or recovery records."""
    tenant_id = "tenant_sentinel_rollback"
    connector_id = "conn_sentinel_rollback"

    broker.metadata_store.simulated_save_failure = True
    leaky_delete_error = StorageError(
        f"Connection reset while passing header Bearer {SYNTHETIC_LEAK_TARGET}"
    )

    with patch.object(broker.storage, "delete_secret", side_effect=leaky_delete_error):
        payload = SecretPayload(secret_type="key", secret_value="val")
        with pytest.raises(RollbackError) as exc:
            broker.register_secret(tenant_id, connector_id, payload, auth_context=admin_auth)

        # Invariant: Secret must not appear in RollbackError message or diagnostic code
        assert SYNTHETIC_LEAK_TARGET not in str(exc.value)
        assert SYNTHETIC_LEAK_TARGET not in str(exc.value.diagnostic_code)

    # Invariant: Recovery record contains safe diagnostic error class, not raw message
    records = broker.metadata_store.get_recovery_records(tenant_id=tenant_id)
    assert len(records) == 1
    assert SYNTHETIC_LEAK_TARGET not in records[0].error
    assert records[0].error == "StorageError"


def test_fail_closed_revocation_on_storage_error(broker, admin_auth):
    tenant_id = "tenant_rev_fail"
    connector_id = "conn_rev_fail"
    payload = SecretPayload(secret_type="key", secret_value="val")
    broker.register_secret(tenant_id, connector_id, payload, auth_context=admin_auth)

    # Simulate deletion failure
    broker.storage.simulated_delete_failure = True

    with pytest.raises(RevocationError):
        broker.revoke_secret(tenant_id, connector_id, auth_context=admin_auth)

    # CRITICAL FAIL-CLOSED ASSERTION:
    # Metadata reference pointer must NOT be cleared, status marked revocation_failed
    conn = broker.metadata_store.get_connection(tenant_id, connector_id)
    assert conn is not None
    assert conn.vault_secret_ref is not None  # Preserved for manual/DR recovery!
    assert conn.status == "revocation_failed"

    # Readiness reflects failure
    readiness = broker.get_readiness_status(tenant_id, connector_id, auth_context=admin_auth)
    assert readiness.can_mutate is False
    assert readiness.readiness_code == "revocation_failed"
    assert readiness.has_secret is True


def test_fail_closed_revocation_on_delete_returns_false(broker, admin_auth):
    tenant_id = "tenant_rev_false"
    connector_id = "conn_rev_false"
    payload = SecretPayload(secret_type="key", secret_value="val")
    broker.register_secret(tenant_id, connector_id, payload, auth_context=admin_auth)

    broker.storage.simulated_delete_returns_false = True

    with pytest.raises(RevocationError):
        broker.revoke_secret(tenant_id, connector_id, auth_context=admin_auth)

    conn = broker.metadata_store.get_connection(tenant_id, connector_id)
    assert conn is not None
    assert conn.vault_secret_ref is not None
    assert conn.status == "revocation_failed"


def test_metadata_failure_readiness_fails_closed(broker, admin_auth):
    tenant_id = "tenant_meta_fail"
    connector_id = "conn_meta_fail"
    payload = SecretPayload(secret_type="key", secret_value="val")
    broker.register_secret(tenant_id, connector_id, payload, auth_context=admin_auth)

    broker.storage.simulated_metadata_failure = True
    readiness = broker.get_readiness_status(tenant_id, connector_id, auth_context=admin_auth)

    assert readiness.can_mutate is False
    assert readiness.readiness_code == "metadata_unavailable"
    assert readiness.readiness_label == "Metadata Unavailable"


def test_missing_auth_context_fails_closed(broker):
    payload = SecretPayload(secret_type="key", secret_value="val")
    with pytest.raises(UnauthorizedActionError) as exc_reg:
        broker.register_secret("t1", "c1", payload, auth_context=None)  # type: ignore
    assert "Missing or invalid AuthorizationContext" in str(exc_reg.value)

    with pytest.raises(UnauthorizedActionError) as exc_rot:
        broker.rotate_secret("t1", "c1", payload, auth_context=None)  # type: ignore
    assert "Missing or invalid AuthorizationContext" in str(exc_rot.value)

    with pytest.raises(UnauthorizedActionError) as exc_rev:
        broker.revoke_secret("t1", "c1", auth_context=None)  # type: ignore
    assert "Missing or invalid AuthorizationContext" in str(exc_rev.value)


def test_cross_tenant_access_denied(broker):
    tenant_scoped_auth = AuthorizationContext(
        actor_id="tenant_a_admin",
        role=AgentRole.HUMAN_ADMIN,
        permitted_tenants=frozenset({"tenant_a"}),
        permitted_connectors=frozenset({"stripe"}),
        is_authenticated=True,
    )
    payload = SecretPayload(secret_type="key", secret_value="val")

    # Accessing unauthorized tenant_b must fail closed
    with pytest.raises(UnauthorizedActionError) as exc:
        broker.register_secret("tenant_b", "stripe", payload, auth_context=tenant_scoped_auth)
    assert "Tenant boundary violation" in str(exc.value)


def test_unauthenticated_auth_context_denied(broker):
    unauth_ctx = AuthorizationContext(
        actor_id="attacker",
        role=AgentRole.HUMAN_ADMIN,
        permitted_tenants=frozenset({"*"}),
        is_authenticated=False,
    )
    payload = SecretPayload(secret_type="key", secret_value="val")

    with pytest.raises(UnauthorizedActionError) as exc:
        broker.register_secret("t1", "c1", payload, auth_context=unauth_ctx)
    assert "Unauthenticated" in str(exc.value)


def test_readiness_query_requires_auth_context_for_connection(broker):
    with pytest.raises(UnauthorizedActionError) as exc:
        broker.get_readiness_status("tenant_x", "conn_y", auth_context=None)
    assert "Missing or unauthenticated AuthorizationContext" in str(exc.value)
