"""Configurable deny-by-default agent capability policy engine."""

from __future__ import annotations

import enum
import re
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from .exceptions import UnauthorizedActionError, ValidationError

# Permitted actor_id identifier pattern (clean alphanumeric, underscores, hyphens, periods, colons, @)
ACTOR_ID_PATTERN = re.compile(r"^[a-zA-Z0-9_\-\.\:\@]{1,64}$")


class AgentRole(str, enum.Enum):
    """Standardized actor roles distinguishing trusted humans from untrusted agents."""

    HUMAN_OWNER = "human_owner"
    HUMAN_ADMIN = "human_admin"
    ORCHESTRATOR = "agent_orchestrator"
    SPECIALIST = "agent_specialist"
    READONLY_AUDITOR = "readonly_auditor"


class CredentialAction(str, enum.Enum):
    """Actions applicable to tenant credentials."""

    REGISTER = "vault:register"
    ROTATE = "vault:rotate"
    REVOKE = "vault:revoke"
    READ_METADATA = "vault:read_metadata"
    DECRYPT_VALUE = "vault:decrypt_value"
    EXECUTE_TOOL = "credential:execute_tool"


@dataclass(frozen=True)
class AuthorizationContext:
    """Explicit host-application authorization context binding an actor to tenant/connector scopes.

    Security Model & Invariants:
    ----------------------------
    - Authentication defaults to FALSE unless explicitly established and asserted by the trusted host.
    - Raw role strings from untrusted LLMs or agent prompts MUST NEVER be used to construct this context.
    - Validates actor_id format and scope collections fail-closed.
    - If is_authenticated is False or requested scopes fall outside permitted scopes, access is denied.
    """

    actor_id: str
    role: AgentRole | str
    permitted_tenants: frozenset[str] = field(default_factory=frozenset)
    permitted_connectors: frozenset[str] = field(default_factory=frozenset)
    is_authenticated: bool = False

    def __post_init__(self) -> None:
        if not isinstance(self.actor_id, str) or not ACTOR_ID_PATTERN.match(self.actor_id.strip()):
            raise ValidationError(
                f"Invalid actor_id '{self.actor_id}': must be 1-64 alphanumeric/identifier characters"
            )

        if not isinstance(self.role, (AgentRole, str)) or not str(self.role).strip():
            raise ValidationError(
                "AuthorizationContext role must be a non-empty string or AgentRole"
            )

        if not isinstance(self.permitted_tenants, (frozenset, set, list, tuple)):
            raise ValidationError("permitted_tenants must be a collection of strings")
        for t in self.permitted_tenants:
            if not isinstance(t, str) or not t.strip():
                raise ValidationError("All elements in permitted_tenants must be non-empty strings")

        if not isinstance(self.permitted_connectors, (frozenset, set, list, tuple)):
            raise ValidationError("permitted_connectors must be a collection of strings")
        for c in self.permitted_connectors:
            if not isinstance(c, str) or not c.strip():
                raise ValidationError(
                    "All elements in permitted_connectors must be non-empty strings"
                )

    def can_access(self, tenant_id: str | None = None, connector_id: str | None = None) -> bool:
        """Check whether this authorization context permits access to the given tenant and connector."""
        if not self.is_authenticated:
            return False

        if tenant_id is not None:
            clean_t = str(tenant_id).lower()
            allowed_tenants = {t.lower() for t in self.permitted_tenants}
            if "*" not in allowed_tenants and clean_t not in allowed_tenants:
                return False

        if connector_id is not None:
            clean_c = str(connector_id).lower()
            allowed_connectors = {c.lower() for c in self.permitted_connectors}
            if "*" not in allowed_connectors and clean_c not in allowed_connectors:
                return False

        return True


@dataclass(frozen=True)
class PolicyDecision:
    """Evaluation result for an attempted action."""

    allowed: bool
    role: str
    action: str
    reason: str
    requires_human_approval: bool
    capability_proposal_only: bool

    def to_dict(self) -> dict[str, Any]:
        return {
            "allowed": self.allowed,
            "role": self.role,
            "action": self.action,
            "reason": self.reason,
            "requires_human_approval": self.requires_human_approval,
            "capability_proposal_only": self.capability_proposal_only,
        }


RuleCallable = Callable[
    [AuthorizationContext, CredentialAction | str, str | None, str | None],
    PolicyDecision | None,
]


class PolicyEngine:
    """Evaluates and enforces capability policies for human users and autonomous AI agents.

    Architecture Note:
    ------------------
    Policy enforcement is an in-process memory evaluation performed within the host process.
    It does not constitute an operating-system level sandbox or hardware isolation boundary.
    The host environment must enforce isolation across agent execution contexts.

    Non-Overridable Security Invariants:
    ------------------------------------
    Custom rules can only NARROW permissions; they cannot override or bypass:
    1. Authentication requirements.
    2. Tenant and connector authorization.
    3. Denial of plaintext credential access (vault:decrypt_value).
    4. Restrictions on agent credential mutations (vault:register, vault:rotate, vault:revoke).
    5. Human approval requirements for tool execution (credential:execute_tool).
    6. Deny-by-default on unrecognized roles or unknown actions.
    """

    def __init__(self, custom_rules: list[RuleCallable] | None = None):
        self._custom_rules: list[RuleCallable] = list(custom_rules or [])

    def register_rule(self, rule: RuleCallable) -> None:
        """Register a custom rule evaluation function.

        Custom rules can further restrict permissions or attach conditions to actions that are
        otherwise permitted by baseline policy. They cannot bypass baseline invariants.
        """
        if not callable(rule):
            raise TypeError("Custom rule must be a callable")
        self._custom_rules.append(rule)

    def _evaluate_baseline(
        self,
        auth_context: AuthorizationContext,
        action_str: str,
        role_str: str,
        tenant_id: str | None = None,
        connector_id: str | None = None,
    ) -> PolicyDecision:
        """Evaluate baseline built-in security invariants fail-closed."""
        # 1. Invariant: Decrypting plaintext secrets is unconditionally PROHIBITED for all AI agents
        if action_str == CredentialAction.DECRYPT_VALUE.value:
            return PolicyDecision(
                allowed=False,
                role=role_str,
                action=action_str,
                reason=(
                    "Absolute Security Boundary: Raw decrypted credentials can NEVER be returned to AI agent "
                    "contexts or prompt memory loops. Use brokered server-side tool execution instead."
                ),
                requires_human_approval=True,
                capability_proposal_only=False,
            )

        # 2. Invariant: AI agents cannot directly mutate credentials in storage
        if action_str in (
            CredentialAction.REGISTER.value,
            CredentialAction.ROTATE.value,
            CredentialAction.REVOKE.value,
        ):
            if role_str in (AgentRole.HUMAN_OWNER.value, AgentRole.HUMAN_ADMIN.value):
                return PolicyDecision(
                    allowed=True,
                    role=role_str,
                    action=action_str,
                    reason="Authenticated human operator possesses administrative authority for credential lifecycle.",
                    requires_human_approval=False,
                    capability_proposal_only=False,
                )
            return PolicyDecision(
                allowed=False,
                role=role_str,
                action=action_str,
                reason="Credential mutations are restricted exclusively to authenticated human operator sessions.",
                requires_human_approval=True,
                capability_proposal_only=False,
            )

        # 3. Metadata inspection: Only supervisory roles may inspect sanitized metadata
        if action_str == CredentialAction.READ_METADATA.value:
            if role_str in (
                AgentRole.HUMAN_OWNER.value,
                AgentRole.HUMAN_ADMIN.value,
                AgentRole.ORCHESTRATOR.value,
                AgentRole.READONLY_AUDITOR.value,
            ):
                return PolicyDecision(
                    allowed=True,
                    role=role_str,
                    action=action_str,
                    reason="Supervisory role authorized to inspect connection presence and sanitized metadata.",
                    requires_human_approval=False,
                    capability_proposal_only=False,
                )
            return PolicyDecision(
                allowed=False,
                role=role_str,
                action=action_str,
                reason="Specialist agent role does not require metadata inspection privileges.",
                requires_human_approval=True,
                capability_proposal_only=True,
            )

        # 4. Tool execution with credentials: Returns capability proposal requiring human sign-off
        if action_str == CredentialAction.EXECUTE_TOOL.value:
            return PolicyDecision(
                allowed=False,
                role=role_str,
                action=action_str,
                reason=(
                    "Runtime Execution Gating: Autonomous execution with third-party credentials requires "
                    "explicit human-in-the-loop approval. Agent may generate a capability proposal only."
                ),
                requires_human_approval=True,
                capability_proposal_only=True,
            )

        # 5. Fallback: Deny all unhandled actions and unknown roles by default
        return PolicyDecision(
            allowed=False,
            role=role_str,
            action=action_str,
            reason="Deny-by-default: Action or role not recognized by capability policy.",
            requires_human_approval=True,
            capability_proposal_only=True,
        )

    def evaluate(
        self,
        auth_context: AuthorizationContext,
        action: CredentialAction | str,
        tenant_id: str | None = None,
        connector_id: str | None = None,
    ) -> PolicyDecision:
        """Evaluate whether an actor context is permitted to perform a credential action."""
        action_str = str(action.value if isinstance(action, CredentialAction) else action).lower()

        # Invariant 1: Fail closed immediately if auth_context is missing or not authenticated
        if not isinstance(auth_context, AuthorizationContext) or not auth_context.is_authenticated:
            role_name = getattr(auth_context, "role", "unknown")
            return PolicyDecision(
                allowed=False,
                role=str(role_name),
                action=action_str,
                reason="Unauthenticated or invalid authorization context: access denied fail-closed.",
                requires_human_approval=True,
                capability_proposal_only=False,
            )

        role_str = str(
            auth_context.role.value
            if isinstance(auth_context.role, AgentRole)
            else auth_context.role
        ).lower()

        # Invariant 2: Enforce tenant and connector scope boundary fail-closed
        if tenant_id is not None or connector_id is not None:
            if not auth_context.can_access(tenant_id=tenant_id, connector_id=connector_id):
                return PolicyDecision(
                    allowed=False,
                    role=role_str,
                    action=action_str,
                    reason=(
                        f"Tenant boundary violation: actor '{auth_context.actor_id}' is not authorized "
                        f"for tenant '{tenant_id}' / connector '{connector_id}'."
                    ),
                    requires_human_approval=True,
                    capability_proposal_only=False,
                )

        # Invariant 3: Evaluate baseline built-in security rules first
        baseline = self._evaluate_baseline(
            auth_context=auth_context,
            action_str=action_str,
            role_str=role_str,
            tenant_id=tenant_id,
            connector_id=connector_id,
        )

        # NON-OVERRIDABLE INVARIANT: If baseline denies the action, custom rules CANNOT override it
        if not baseline.allowed:
            return baseline

        # Invariant 4: Custom rules execute ONLY to narrow/restrict permissions, never to expand them
        for rule in self._custom_rules:
            try:
                custom_decision = rule(auth_context, action_str, tenant_id, connector_id)
                if custom_decision is not None and not custom_decision.allowed:
                    # Custom rule narrowed/denied the permission
                    return custom_decision
            except Exception as e:
                # Custom rule evaluation errors fail closed
                return PolicyDecision(
                    allowed=False,
                    role=role_str,
                    action=action_str,
                    reason=f"Custom policy rule failed closed: {e.__class__.__name__}",
                    requires_human_approval=True,
                    capability_proposal_only=False,
                )

        return baseline

    def enforce(
        self,
        auth_context: AuthorizationContext,
        action: CredentialAction | str,
        tenant_id: str | None = None,
        connector_id: str | None = None,
    ) -> PolicyDecision:
        """Evaluate policy and raise UnauthorizedActionError if the action is not allowed."""
        if not isinstance(auth_context, AuthorizationContext):
            raise UnauthorizedActionError(
                "Missing or invalid AuthorizationContext. Explicit authorization context is required fail-closed."
            )

        decision = self.evaluate(
            auth_context=auth_context,
            action=action,
            tenant_id=tenant_id,
            connector_id=connector_id,
        )
        if not decision.allowed:
            raise UnauthorizedActionError(
                f"Unauthorized action '{decision.action}' for actor '{auth_context.actor_id}' "
                f"({decision.role}): {decision.reason}"
            )
        return decision
