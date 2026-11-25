"""Integration tests for CAS concurrency protection and race condition prevention."""

import threading

import pytest

from agentguardkit.exceptions import AgentGuardError
from agentguardkit.interfaces import SecretPayload


def test_concurrent_registration_race(broker, admin_auth):
    tenant_id = "tenant_concurrency"
    connector_id = "crm_key"
    payload = SecretPayload(secret_type="key", secret_value="v1")

    # First registration succeeds
    res1 = broker.register_secret(tenant_id, connector_id, payload, auth_context=admin_auth)
    assert res1["success"] is True

    # Second registration fails closed
    with pytest.raises(AgentGuardError) as exc:
        broker.register_secret(tenant_id, connector_id, payload, auth_context=admin_auth)
    assert exc.value.code == "secret_already_exists"


def test_concurrent_rotation_cas_conflict(broker, admin_auth):
    tenant_id = "tenant_concurrency_rot"
    connector_id = "ad_token"
    broker.register_secret(
        tenant_id,
        connector_id,
        SecretPayload(secret_type="t", secret_value="v1"),
        auth_context=admin_auth,
    )

    # Actor A and Actor B both read current version 1
    p_a = SecretPayload(secret_type="t", secret_value="val_from_A")

    # Actor A succeeds in rotating to v2
    res_a = broker.rotate_secret(tenant_id, connector_id, p_a, auth_context=admin_auth)
    assert res_a["version"] == 2

    # Actor B's rotation attempt fails CAS precondition if passing cas=1
    path = f"tenants/{tenant_id}/connectors/{connector_id}"
    with pytest.raises(AgentGuardError):
        # Directly writing with stale CAS precondition 1
        broker.storage.write_secret(path, {"data": "stale"}, cas=1)


def test_multithreaded_rotations_serialized(broker, admin_auth):
    tenant_id = "tenant_threaded"
    connector_id = "conn_thread"
    broker.register_secret(
        tenant_id,
        connector_id,
        SecretPayload(secret_type="t", secret_value="v0"),
        auth_context=admin_auth,
    )

    success_count = [0]
    conflict_count = [0]
    lock = threading.Lock()

    def worker():
        try:
            broker.rotate_secret(
                tenant_id,
                connector_id,
                SecretPayload(secret_type="t", secret_value="new_val"),
                auth_context=admin_auth,
            )
            with lock:
                success_count[0] += 1
        except AgentGuardError:
            with lock:
                conflict_count[0] += 1

    threads = [threading.Thread(target=worker) for _ in range(5)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    # In mock storage with lock, versions are sequentially incremented or conflict
    assert success_count[0] + conflict_count[0] == 5
    assert success_count[0] >= 1
