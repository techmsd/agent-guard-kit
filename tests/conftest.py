"""Pytest configuration and synthetic fixtures for AgentGuardKit."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

# Ensure src/ is on python path for tests
src_path = str(Path(__file__).parent.parent / "src")
if src_path not in sys.path:
    sys.path.insert(0, src_path)

from agentguardkit.broker import CredentialBroker
from agentguardkit.metadata.memory import InMemoryMetadataStore
from agentguardkit.policy import AgentRole, AuthorizationContext, PolicyEngine
from agentguardkit.storage.memory import MockVaultStorage


@pytest.fixture
def mock_storage() -> MockVaultStorage:
    storage = MockVaultStorage()
    storage.reset()
    return storage


@pytest.fixture
def metadata_store() -> InMemoryMetadataStore:
    store = InMemoryMetadataStore()
    store.reset()
    return store


@pytest.fixture
def policy_engine() -> PolicyEngine:
    return PolicyEngine()


@pytest.fixture
def broker(
    mock_storage: MockVaultStorage,
    metadata_store: InMemoryMetadataStore,
    policy_engine: PolicyEngine,
) -> CredentialBroker:
    return CredentialBroker(
        storage=mock_storage,
        metadata_store=metadata_store,
        policy_engine=policy_engine,
        enabled=True,
    )


@pytest.fixture
def admin_auth() -> AuthorizationContext:
    """Global admin authorization context permitted for all tenants."""
    return AuthorizationContext(
        actor_id="admin_user_1",
        role=AgentRole.HUMAN_ADMIN,
        permitted_tenants=frozenset({"*"}),
        permitted_connectors=frozenset({"*"}),
        is_authenticated=True,
    )


@pytest.fixture
def tenant_admin_auth() -> AuthorizationContext:
    """Scoped admin authorization context permitted only for specific tenants."""
    return AuthorizationContext(
        actor_id="tenant_admin_1",
        role=AgentRole.HUMAN_ADMIN,
        permitted_tenants=frozenset({"tenant-a", "tenant-1", "t1"}),
        permitted_connectors=frozenset({"stripe-live", "connector-1", "c1"}),
        is_authenticated=True,
    )


@pytest.fixture
def agent_auth() -> AuthorizationContext:
    """Agent orchestrator authorization context."""
    return AuthorizationContext(
        actor_id="agent_orchestrator_1",
        role=AgentRole.ORCHESTRATOR,
        permitted_tenants=frozenset({"*"}),
        permitted_connectors=frozenset({"*"}),
        is_authenticated=True,
    )


@pytest.fixture
def readonly_auth() -> AuthorizationContext:
    """Read-only auditor authorization context."""
    return AuthorizationContext(
        actor_id="auditor_user_1",
        role=AgentRole.READONLY_AUDITOR,
        permitted_tenants=frozenset({"*"}),
        permitted_connectors=frozenset({"*"}),
        is_authenticated=True,
    )
