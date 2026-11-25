"""Example 4: Recipe for MCP (Model Context Protocol) Tool Proxying with AgentGuardKit.

Illustrates how an MCP Tool Server can execute actions with third-party credentials
without exposing the plaintext token to the LLM agent prompt.
"""

from typing import Any, Dict

from agentguardkit import (
    AgentRole,
    AuditSanitizer,
    AuthorizationContext,
    CredentialBroker,
    MockVaultStorage,
    SecretPayload,
)


class McpPaymentToolServer:
    """Mock MCP server providing payment charge capability without token leakage."""

    def __init__(self, broker: CredentialBroker) -> None:
        self.broker = broker
        self.sanitizer = AuditSanitizer()

    def handle_tool_call(
        self, agent_role: str, tenant_id: str, connector_id: str, tool_params: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Gated execution endpoint evaluated by policy engine."""
        # Unauthenticated context attempting tool execution fails closed
        context = AuthorizationContext(
            actor_id="mcp_worker",
            role=AgentRole(agent_role),
            permitted_tenants=frozenset({tenant_id}),
            is_authenticated=True,
        )

        decision = self.broker.policy_engine.evaluate(
            auth_context=context,
            action="storage:write_secret",  # Agent proposing mutation
            tenant_id=tenant_id,
            connector_id=connector_id,
        )

        if not decision.allowed and decision.requires_human_approval:
            # Return capability proposal instead of executing autonomously
            return {
                "status": "approval_required",
                "proposal_token": f"prop_{tenant_id}_{connector_id}",
                "reason": "Mutation requires human approval.",
            }

        # Brokered execution: retrieve secret on server side, never pass to agent prompt
        metadata = self.broker.get_readiness_status(
            tenant_id=tenant_id, connector_id=connector_id, auth_context=context
        )
        if not metadata.has_secret:
            return {"status": "error", "message": "Connector secret not configured"}

        raw_audit = {
            "action": "mcp:charge_card",
            "actor": "mcp_worker",
            "amount": tool_params.get("amount"),
            "token": "sk_live_synthetic_token_in_trace",
        }
        sanitized_audit = self.sanitizer.sanitize(raw_audit)

        return {
            "status": "success",
            "result": {"charge_id": "ch_synthetic_12345", "amount": tool_params.get("amount")},
            "audit": sanitized_audit,
        }


def main() -> None:
    storage = MockVaultStorage()
    broker = CredentialBroker(storage=storage)

    admin_auth = AuthorizationContext(
        actor_id="admin_provisioner",
        role=AgentRole.HUMAN_ADMIN,
        permitted_tenants=frozenset({"tenant_acme"}),
        permitted_connectors=frozenset({"stripe"}),
        is_authenticated=True,
    )

    # Register connector
    broker.register_secret(
        "tenant_acme",
        "stripe",
        SecretPayload(secret_type="api_key", secret_value="sk_live_synthetic_123"),
        auth_context=admin_auth,
    )

    server = McpPaymentToolServer(broker)

    print("--- 1. Autonomous Agent calls Tool (Gated by Proposal) ---")
    response = server.handle_tool_call(
        agent_role=AgentRole.SPECIALIST.value,
        tenant_id="tenant_acme",
        connector_id="stripe",
        tool_params={"amount": 100},
    )
    print("Agent Response (Proposal Only):", response)


if __name__ == "__main__":
    main()
