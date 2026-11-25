"""Example 1: Basic In-Memory Quickstart with AgentGuardKit."""

from agentguardkit import (
    AgentRole,
    AuthorizationContext,
    CredentialBroker,
    MockVaultStorage,
    SecretPayload,
)


def main() -> None:
    print("--- 1. Initialize Broker with In-Memory Storage ---")
    storage = MockVaultStorage()
    broker = CredentialBroker(storage=storage)

    tenant_id = "tenant_alpha"
    connector_id = "payment_gateway"

    # Host-supplied authorization context for human administrator
    admin_auth = AuthorizationContext(
        actor_id="ops_admin",
        role=AgentRole.HUMAN_ADMIN,
        permitted_tenants=frozenset({tenant_id}),
        permitted_connectors=frozenset({connector_id}),
        is_authenticated=True,
    )

    print("--- 2. Register Credential (Human Admin) ---")
    payload = SecretPayload(
        secret_type="api_key",
        secret_value="synthetic_test_stripe_live_key_xyz",
        description="Stripe Payment Gateway Key",
    )
    result = broker.register_secret(
        tenant_id=tenant_id,
        connector_id=connector_id,
        payload=payload,
        auth_context=admin_auth,
    )
    print("Registration Result:", result)

    print("--- 3. Check Readiness Status ---")
    status = broker.get_readiness_status(tenant_id, connector_id, auth_context=admin_auth)
    print("Readiness Code:", status.readiness_code)
    print("Secret Version:", status.secret_version)

    print("--- 4. Rotate Credential ---")
    rotated_payload = SecretPayload(
        secret_type="api_key",
        secret_value="synthetic_test_stripe_live_key_rotated",
        description="Rotated Key",
    )
    rot_result = broker.rotate_secret(
        tenant_id=tenant_id,
        connector_id=connector_id,
        payload=rotated_payload,
        auth_context=admin_auth,
    )
    print("Rotation Result:", rot_result)

    print("--- 5. Revoke Credential ---")
    rev_result = broker.revoke_secret(
        tenant_id=tenant_id,
        connector_id=connector_id,
        auth_context=admin_auth,
    )
    print("Revocation Result:", rev_result["status"])
    print("Notice:", rev_result["notice"])


if __name__ == "__main__":
    main()
