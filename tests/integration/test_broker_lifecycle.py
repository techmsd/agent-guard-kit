"""Integration tests for CredentialBroker lifecycle operations."""

import pytest

from agentguardkit.broker import CredentialBroker
from agentguardkit.exceptions import AgentGuardError, UnauthorizedActionError
from agentguardkit.interfaces import SecretPayload


def test_full_lifecycle_register_rotate_revoke(broker, admin_auth):
    tenant_id = "tenant_alpha"
    connector_id = "zoom_api"

    # 1. Initial readiness
    r0 = broker.get_readiness_status(tenant_id, connector_id, auth_context=admin_auth)
    assert r0.has_secret is False
    assert r0.readiness_code == "awaiting_setup"

    # 2. Register secret
    p1 = SecretPayload(secret_type="oauth_token", secret_value="synthetic_token_v1")
    res_reg = broker.register_secret(tenant_id, connector_id, p1, auth_context=admin_auth)
    assert res_reg["success"] is True
    assert res_reg["version"] == 1
    assert res_reg["status"] == "stored"

    # Verify readiness after registration
    r1 = broker.get_readiness_status(tenant_id, connector_id, auth_context=admin_auth)
    assert r1.has_secret is True
    assert r1.secret_version == 1
    assert r1.readiness_code == "stored"

    # 3. Rotate secret
    p2 = SecretPayload(secret_type="oauth_token", secret_value="synthetic_token_v2")
    res_rot = broker.rotate_secret(tenant_id, connector_id, p2, auth_context=admin_auth)
    assert res_rot["success"] is True
    assert res_rot["version"] == 2

    r2 = broker.get_readiness_status(tenant_id, connector_id, auth_context=admin_auth)
    assert r2.secret_version == 2
    assert r2.has_secret is True

    # 4. Revoke secret
    res_rev = broker.revoke_secret(tenant_id, connector_id, auth_context=admin_auth)
    assert res_rev["success"] is True
    assert res_rev["status"] == "revoked"
    assert "External third-party credentials remain active externally" in res_rev["notice"]

    r3 = broker.get_readiness_status(tenant_id, connector_id, auth_context=admin_auth)
    assert r3.readiness_code == "revoked"
    assert r3.has_secret is False

    # 5. Verify audit trail
    events = broker.metadata_store.get_audit_events(tenant_id=tenant_id)
    assert len(events) == 3
    actions = [e.action for e in events]
    assert "vault:revoke" in actions
    assert "vault:rotate" in actions
    assert "vault:register" in actions


def test_broker_disabled_fails_closed(mock_storage, metadata_store, policy_engine, admin_auth):
    disabled_broker = CredentialBroker(
        storage=mock_storage,
        metadata_store=metadata_store,
        policy_engine=policy_engine,
        enabled=False,
    )
    p = SecretPayload(secret_type="key", secret_value="val")
    with pytest.raises(AgentGuardError) as exc:
        disabled_broker.register_secret("t1", "c1", p, auth_context=admin_auth)
    assert exc.value.code == "broker_disabled"

    readiness = disabled_broker.get_readiness_status()
    assert readiness.storage_enabled is False
    assert readiness.readiness_code == "disabled"


def test_agent_role_prohibited_from_mutations(broker, agent_auth):
    p = SecretPayload(secret_type="key", secret_value="val")
    with pytest.raises(UnauthorizedActionError):
        broker.register_secret("t1", "c1", p, auth_context=agent_auth)

    with pytest.raises(UnauthorizedActionError):
        broker.rotate_secret("t1", "c1", p, auth_context=agent_auth)

    with pytest.raises(UnauthorizedActionError):
        broker.revoke_secret("t1", "c1", auth_context=agent_auth)
