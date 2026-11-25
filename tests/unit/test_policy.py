"""Unit tests for agent capability policy engine and AuthorizationContext."""

import pytest

from agentguardkit.exceptions import UnauthorizedActionError, ValidationError
from agentguardkit.policy import (
    AgentRole,
    AuthorizationContext,
    CredentialAction,
    PolicyDecision,
    PolicyEngine,
)


@pytest.fixture
def engine():
    return PolicyEngine()


@pytest.fixture
def admin_ctx():
    return AuthorizationContext(
        actor_id="admin-1",
        role=AgentRole.HUMAN_ADMIN,
        permitted_tenants=frozenset({"*"}),
        permitted_connectors=frozenset({"*"}),
        is_authenticated=True,
    )


def test_authorization_context_defaults_unauthenticated():
    ctx = AuthorizationContext(actor_id="admin-1", role=AgentRole.HUMAN_ADMIN)
    assert ctx.is_authenticated is False
    assert ctx.can_access("tenant-1") is False


def test_authorization_context_validation_rejects_malformed_fields():
    # Empty actor_id
    with pytest.raises(ValidationError):
        AuthorizationContext(actor_id="", role=AgentRole.HUMAN_ADMIN)

    # Actor ID with spaces or control characters
    with pytest.raises(ValidationError):
        AuthorizationContext(actor_id="admin with spaces", role=AgentRole.HUMAN_ADMIN)

    # Invalid role
    with pytest.raises(ValidationError):
        AuthorizationContext(actor_id="admin-1", role="")

    # Non-collection scopes
    with pytest.raises(ValidationError):
        AuthorizationContext(actor_id="admin-1", role="admin", permitted_tenants="tenant1")  # type: ignore

    # Collection with empty strings
    with pytest.raises(ValidationError):
        AuthorizationContext(actor_id="admin-1", role="admin", permitted_tenants=frozenset({""}))


def test_human_admin_permitted_lifecycle_actions(engine, admin_ctx):
    for action in [
        CredentialAction.REGISTER,
        CredentialAction.ROTATE,
        CredentialAction.REVOKE,
        CredentialAction.READ_METADATA,
    ]:
        decision = engine.evaluate(admin_ctx, action)
        assert decision.allowed is True
        assert decision.requires_human_approval is False
        assert decision.capability_proposal_only is False


def test_agent_unconditionally_denied_decrypt(engine):
    for role in [
        AgentRole.ORCHESTRATOR,
        AgentRole.SPECIALIST,
        AgentRole.READONLY_AUDITOR,
    ]:
        ctx = AuthorizationContext(
            actor_id="agent-test",
            role=role,
            permitted_tenants=frozenset({"*"}),
            is_authenticated=True,
        )
        decision = engine.evaluate(ctx, CredentialAction.DECRYPT_VALUE)
        assert decision.allowed is False
        assert "NEVER be returned to AI agent" in decision.reason
        assert decision.requires_human_approval is True
        assert decision.capability_proposal_only is False


def test_agent_denied_credential_mutations(engine):
    for role in [AgentRole.ORCHESTRATOR, AgentRole.SPECIALIST]:
        ctx = AuthorizationContext(
            actor_id="agent-mutation",
            role=role,
            permitted_tenants=frozenset({"*"}),
            is_authenticated=True,
        )
        for action in [
            CredentialAction.REGISTER,
            CredentialAction.ROTATE,
            CredentialAction.REVOKE,
        ]:
            decision = engine.evaluate(ctx, action)
            assert decision.allowed is False
            assert "restricted exclusively to authenticated human operator" in decision.reason
            assert decision.requires_human_approval is True


def test_metadata_inspection_privileges(engine):
    # Supervisory roles permitted
    for role in [
        AgentRole.ORCHESTRATOR,
        AgentRole.READONLY_AUDITOR,
        AgentRole.HUMAN_OWNER,
    ]:
        ctx = AuthorizationContext(
            actor_id="supervisory",
            role=role,
            permitted_tenants=frozenset({"*"}),
            is_authenticated=True,
        )
        decision = engine.evaluate(ctx, CredentialAction.READ_METADATA)
        assert decision.allowed is True
        assert decision.requires_human_approval is False

    # Specialist agent denied
    spec_ctx = AuthorizationContext(
        actor_id="spec-agent",
        role=AgentRole.SPECIALIST,
        permitted_tenants=frozenset({"*"}),
        is_authenticated=True,
    )
    spec_decision = engine.evaluate(spec_ctx, CredentialAction.READ_METADATA)
    assert spec_decision.allowed is False
    assert spec_decision.capability_proposal_only is True


def test_tool_execution_gated_by_proposal(engine):
    ctx = AuthorizationContext(
        actor_id="spec-agent",
        role=AgentRole.SPECIALIST,
        permitted_tenants=frozenset({"*"}),
        is_authenticated=True,
    )
    decision = engine.evaluate(ctx, CredentialAction.EXECUTE_TOOL)
    assert decision.allowed is False
    assert decision.capability_proposal_only is True
    assert decision.requires_human_approval is True
    assert "capability proposal only" in decision.reason.lower()


def test_deny_by_default_fallback(engine):
    ctx = AuthorizationContext(
        actor_id="hacker",
        role="unregistered_hacker_agent",
        permitted_tenants=frozenset({"*"}),
        is_authenticated=True,
    )
    decision = engine.evaluate(ctx, "unknown:destructive_action")
    assert decision.allowed is False
    assert "Deny-by-default" in decision.reason
    assert decision.requires_human_approval is True


def test_unauthenticated_context_fails_closed(engine):
    unauth_ctx = AuthorizationContext(
        actor_id="spoofed_admin",
        role=AgentRole.HUMAN_ADMIN,
        is_authenticated=False,
    )
    decision = engine.evaluate(unauth_ctx, CredentialAction.REGISTER)
    assert decision.allowed is False
    assert "Unauthenticated" in decision.reason


def test_tenant_scope_enforcement(engine):
    tenant_scoped_ctx = AuthorizationContext(
        actor_id="tenant_admin",
        role=AgentRole.HUMAN_ADMIN,
        permitted_tenants=frozenset({"tenant-a"}),
        permitted_connectors=frozenset({"stripe-live"}),
        is_authenticated=True,
    )

    # Permitted tenant
    dec_allowed = engine.evaluate(
        tenant_scoped_ctx,
        CredentialAction.REGISTER,
        tenant_id="tenant-a",
        connector_id="stripe-live",
    )
    assert dec_allowed.allowed is True

    # Prohibited tenant
    dec_denied = engine.evaluate(
        tenant_scoped_ctx,
        CredentialAction.REGISTER,
        tenant_id="tenant-b",
        connector_id="stripe-live",
    )
    assert dec_denied.allowed is False
    assert "Tenant boundary violation" in dec_denied.reason

    # Prohibited connector
    dec_conn_denied = engine.evaluate(
        tenant_scoped_ctx,
        CredentialAction.REGISTER,
        tenant_id="tenant-a",
        connector_id="unauthorized-connector",
    )
    assert dec_conn_denied.allowed is False
    assert "Tenant boundary violation" in dec_conn_denied.reason


# -----------------------------------------------------------------------------
# Non-Overridable Security Invariants Tests
# -----------------------------------------------------------------------------


def test_custom_rule_cannot_override_decrypt_restriction(engine):
    # Rogue custom rule attempting to grant decrypt to an AI agent
    def rogue_rule(ctx, action, tenant_id, connector_id):
        return PolicyDecision(
            allowed=True,
            role=str(ctx.role),
            action=str(action),
            reason="Rogue rule attempting to bypass decrypt invariant",
            requires_human_approval=False,
            capability_proposal_only=False,
        )

    engine.register_rule(rogue_rule)

    agent_ctx = AuthorizationContext(
        actor_id="agent_1",
        role=AgentRole.SPECIALIST,
        permitted_tenants=frozenset({"*"}),
        is_authenticated=True,
    )

    decision = engine.evaluate(agent_ctx, CredentialAction.DECRYPT_VALUE)
    # MUST BE DENIED: baseline invariant blocks decrypt for agent unconditionally
    assert decision.allowed is False
    assert "Absolute Security Boundary" in decision.reason


def test_custom_rule_cannot_override_agent_mutation_restriction(engine):
    def rogue_rule(ctx, action, tenant_id, connector_id):
        return PolicyDecision(
            allowed=True,
            role=str(ctx.role),
            action=str(action),
            reason="Rogue rule attempting to allow agent mutation",
            requires_human_approval=False,
            capability_proposal_only=False,
        )

    engine.register_rule(rogue_rule)

    agent_ctx = AuthorizationContext(
        actor_id="agent_1",
        role=AgentRole.SPECIALIST,
        permitted_tenants=frozenset({"*"}),
        is_authenticated=True,
    )

    for mut_action in [
        CredentialAction.REGISTER,
        CredentialAction.ROTATE,
        CredentialAction.REVOKE,
    ]:
        decision = engine.evaluate(agent_ctx, mut_action)
        assert decision.allowed is False
        assert "restricted exclusively to authenticated human operator" in decision.reason


def test_custom_rule_cannot_override_unauthenticated_context(engine):
    def rogue_rule(ctx, action, tenant_id, connector_id):
        return PolicyDecision(
            allowed=True,
            role=str(ctx.role),
            action=str(action),
            reason="Rogue rule attempting to allow unauthenticated access",
            requires_human_approval=False,
            capability_proposal_only=False,
        )

    engine.register_rule(rogue_rule)

    unauth_ctx = AuthorizationContext(
        actor_id="hacker",
        role=AgentRole.HUMAN_ADMIN,
        permitted_tenants=frozenset({"*"}),
        is_authenticated=False,
    )

    decision = engine.evaluate(unauth_ctx, CredentialAction.REGISTER)
    assert decision.allowed is False
    assert "Unauthenticated" in decision.reason


def test_custom_rule_cannot_override_tenant_scope_violation(engine):
    def rogue_rule(ctx, action, tenant_id, connector_id):
        return PolicyDecision(
            allowed=True,
            role=str(ctx.role),
            action=str(action),
            reason="Rogue rule attempting to allow cross-tenant access",
            requires_human_approval=False,
            capability_proposal_only=False,
        )

    engine.register_rule(rogue_rule)

    scoped_ctx = AuthorizationContext(
        actor_id="admin_1",
        role=AgentRole.HUMAN_ADMIN,
        permitted_tenants=frozenset({"tenant-a"}),
        is_authenticated=True,
    )

    decision = engine.evaluate(scoped_ctx, CredentialAction.REGISTER, tenant_id="tenant-b")
    assert decision.allowed is False
    assert "Tenant boundary violation" in decision.reason


def test_custom_rule_can_narrow_permissions(engine, admin_ctx):
    # Valid custom rule that narrows permissions (e.g. locks PCI vault)
    def lock_pci_rule(ctx, action, tenant_id, connector_id):
        if connector_id == "pci-vault":
            return PolicyDecision(
                allowed=False,
                role=str(ctx.role),
                action=str(action),
                reason="PCI-vault connectors are permanently locked by custom rule.",
                requires_human_approval=True,
                capability_proposal_only=False,
            )
        return None

    engine.register_rule(lock_pci_rule)

    # Normal connector is allowed by baseline
    normal_dec = engine.evaluate(
        admin_ctx,
        CredentialAction.REGISTER,
        tenant_id="t1",
        connector_id="normal-conn",
    )
    assert normal_dec.allowed is True

    # PCI connector is narrowed and denied by custom rule
    pci_dec = engine.evaluate(
        admin_ctx,
        CredentialAction.REGISTER,
        tenant_id="t1",
        connector_id="pci-vault",
    )
    assert pci_dec.allowed is False
    assert "PCI-vault connectors are permanently locked" in pci_dec.reason


def test_custom_rule_failure_fails_closed(engine, admin_ctx):
    def buggy_rule(ctx, action, tenant_id, connector_id):
        raise RuntimeError("Buggy rule crash")

    engine.register_rule(buggy_rule)
    decision = engine.evaluate(admin_ctx, CredentialAction.REGISTER, tenant_id="t1")
    assert decision.allowed is False
    assert "failed closed" in decision.reason


def test_enforce_raises_unauthorized_action_error(engine):
    ctx = AuthorizationContext(
        actor_id="spec",
        role=AgentRole.SPECIALIST,
        permitted_tenants=frozenset({"*"}),
        is_authenticated=True,
    )
    with pytest.raises(UnauthorizedActionError) as exc_info:
        engine.enforce(ctx, CredentialAction.DECRYPT_VALUE)
    assert "Unauthorized action" in str(exc_info.value)
    assert exc_info.value.code == "unauthorized_action"


def test_enforce_returns_decision_when_allowed(engine):
    owner_ctx = AuthorizationContext(
        actor_id="owner",
        role=AgentRole.HUMAN_OWNER,
        permitted_tenants=frozenset({"*"}),
        is_authenticated=True,
    )
    decision = engine.enforce(owner_ctx, CredentialAction.REGISTER)
    assert decision.allowed is True


def test_enforce_non_context_raises():
    engine = PolicyEngine()
    with pytest.raises(UnauthorizedActionError) as exc:
        engine.enforce("not_an_auth_context", CredentialAction.REGISTER)  # type: ignore
    assert "Missing or invalid AuthorizationContext" in str(exc.value)
