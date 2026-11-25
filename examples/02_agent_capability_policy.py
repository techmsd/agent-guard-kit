"""Example 2: Enforcing Agent Capability Policies."""

from agentguardkit import AgentRole, AuthorizationContext, CredentialAction, PolicyEngine
from agentguardkit.exceptions import UnauthorizedActionError


def main() -> None:
    engine = PolicyEngine()
    print("--- Evaluating Agent Roles vs Actions ---")

    # 1. Human Operator Lifecycle Actions (Authenticated)
    owner_auth = AuthorizationContext(
        actor_id="admin_user",
        role=AgentRole.HUMAN_OWNER,
        permitted_tenants=frozenset({"tenant_acme"}),
        is_authenticated=True,
    )
    owner_dec = engine.evaluate(owner_auth, CredentialAction.REGISTER, tenant_id="tenant_acme")
    print(
        f"Human Owner Register Allowed? {owner_dec.allowed} (Approval required: {owner_dec.requires_human_approval})"
    )

    # 2. AI Specialist attempting to decrypt secret
    agent_auth = AuthorizationContext(
        actor_id="agent_worker",
        role=AgentRole.SPECIALIST,
        permitted_tenants=frozenset({"tenant_acme"}),
        is_authenticated=True,
    )
    agent_dec = engine.evaluate(agent_auth, CredentialAction.DECRYPT_VALUE, tenant_id="tenant_acme")
    print(f"AI Specialist Decrypt Allowed? {agent_dec.allowed} (Reason: {agent_dec.reason})")

    # 3. AI Orchestrator inspecting metadata
    orch_auth = AuthorizationContext(
        actor_id="orchestrator",
        role=AgentRole.ORCHESTRATOR,
        permitted_tenants=frozenset({"tenant_acme"}),
        is_authenticated=True,
    )
    orch_dec = engine.evaluate(orch_auth, CredentialAction.READ_METADATA, tenant_id="tenant_acme")
    print(f"AI Orchestrator Read Metadata Allowed? {orch_dec.allowed}")

    # 4. Enforce action gate (raises exception on violation)
    print("\n--- Testing Runtime Enforcement Gate ---")
    try:
        engine.enforce(agent_auth, CredentialAction.DECRYPT_VALUE, tenant_id="tenant_acme")
    except UnauthorizedActionError as e:
        print("Blocked Action Successfully:", e)


if __name__ == "__main__":
    main()
