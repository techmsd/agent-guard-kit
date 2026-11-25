# AgentGuardKit

> **Tenant-isolated credential brokering, deny-by-default capabilities, and typed audit sanitization for AI agents.**

> [!WARNING]
> ### EXPERIMENTAL PRE-RELEASE ALPHA (`v0.1.0a3`)
> **AgentGuardKit is currently an experimental proof-of-concept release.**
> 
> - **NOT Independently Security Audited**: This codebase has undergone internal automated testing and architectural review, but has **NOT** yet been audited by an independent third-party application security firm.
> - **NOT Recommended for Production**: **Do NOT use this package to manage live production credentials, financial keys, or sensitive customer data.**
> - **Unstable API**: Interfaces, authorization contexts, and storage adapters are subject to breaking changes prior to the stable `v1.0.0` release.
> - **In-Process Boundary**: AgentGuardKit evaluates policy in host memory; it is not an operating system container, sandbox, or network firewall.

[![CI](https://github.com/techmsd/agent-guard-kit/actions/workflows/ci.yml/badge.svg)](https://github.com/techmsd/agent-guard-kit/actions/workflows/ci.yml)
[![Python Versions](https://img.shields.io/badge/python-3.10%20%7C%203.11%20%7C%203.12%20%7C%203.13-blue)](https://github.com/techmsd/agent-guard-kit)
[![License](https://img.shields.io/badge/license-Apache--2.0-green)](LICENSE)
[![Zero Dependencies](https://img.shields.io/badge/dependencies-zero%20runtime-brightgreen)](#framework-independence)

---

## The Problem: Why LLM Agents Break Traditional Secrets Management

Most secrets managers (HashiCorp Vault, AWS Secrets Manager, Doppler) store credentials securely at rest and return them upon authentication. However, when an autonomous AI agent interacts with third-party tools, **yielding raw plaintext credentials directly to the agent runtime creates severe vulnerabilities**:

1. **Prompt Injection & Exfiltration**: LLMs process instructions and untrusted data (user emails, scraped web content, tool responses) in the same context window. If a long-lived API key or OAuth token enters the model's prompt or context, indirect prompt injection can induce the agent to emit or transmit that secret. *System prompts are not security boundaries.*
2. **Over-Privileged Non-Human Identities**: Agents executing autonomous sub-tasks often receive broad service account permissions rather than tightly scoped, tenant-isolated credentials.
3. **Audit Blindness**: Tracing tools and LLM observability platforms often capture unredacted tool inputs and error dumps, inadvertently recording sensitive authentication material in telemetry tables.

---

## What AgentGuardKit Provides

AgentGuardKit is a lightweight, embeddable Python security library that introduces a brokered credential isolation layer between autonomous agents and secret stores:

- **Plaintext Credential Withholding**: AI agents receive only opaque references and capability proposals—never raw tokens.
- **Tenant-Scoped Authorization & Path Isolation**: Requires an explicit, host-authenticated `AuthorizationContext` binding callers to permitted tenant and connector scopes.
- **Deny-by-Default Capability Engine**: Non-overridable security invariants unconditionally prohibit agents from reading decrypted credentials, requiring human-in-the-loop sign-off for lifecycle operations.
- **Optimistic Concurrency & Compensating Rollback**: Enforces CAS=0 on registration to prevent overwriting existing keys, CAS on rotation to prevent lost updates, and version-scoped compensating deletion with structured recovery records if metadata persistence fails.
- **Strict Typed Audit Sanitization**: Scrubs telemetry and logs using typed scalar allowlists (IPs, HTTP verbs, status codes) and regex pattern scrubbers (AWS keys, GitHub tokens, Bearer headers, JWTs).
- **Framework-Independent & Zero Runtime Dependencies**: Pure Python standard library implementation (`urllib.request`, `ssl`, `json`, `dataclasses`). No mandatory Django, FastAPI, or third-party HTTP client dependencies.

---

## Security Boundary & Host Application Responsibilities

> [!WARNING]
> **In-Process Scope**: AgentGuardKit evaluates capability policies and manages credential paths within the host application process. It is **not** an operating system sandbox, container isolation layer, or hypervisor boundary.
>
> **Host Responsibilities**:
> 1. **Authentication**: The host application must authenticate users/agents and generate a verified `AuthorizationContext`. Untrusted inputs from LLM chat loops or prompts must never be trusted to set identity or scopes.
> 2. **Execution Sandboxing**: To protect against prompt injection and tool misuse, the host must execute untrusted agent processes in isolated environments (e.g. sandboxed containers or microVMs) with strict network egress filtering.
> 3. **Proxy Execution**: Downstream tools requiring third-party credentials should execute through trusted server-side brokers rather than passing credentials into agent contexts.

---

## Installation

```bash
# Direct installation from PyPI
pip install agent-guard-kit-sdk

# Or installation from source
git clone https://github.com/techmsd/agent-guard-kit.git
cd agent-guard-kit
pip install -e .
```

*(Note: The official distribution package name on PyPI is `agent-guard-kit-sdk`. The Python import namespace remains `agentguardkit`.)*

---

## Quick Start

### 1. In-Memory Mock (for Local Development & Tests)

```python
from agentguardkit import (
    CredentialBroker,
    SecretPayload,
    AgentRole,
    AuthorizationContext,
    MockVaultStorage,
)

# Initialize standalone broker with mock storage
storage = MockVaultStorage()
broker = CredentialBroker(storage=storage)

# Operator authorization context supplied by trusted host application
admin_ctx = AuthorizationContext(
    actor_id="admin_user",
    role=AgentRole.HUMAN_ADMIN,
    permitted_tenants=frozenset({"tenant_acme"}),
    permitted_connectors=frozenset({"stripe_payments"}),
    is_authenticated=True,
)

# Register a credential
payload = SecretPayload(
    secret_type="api_key",
    secret_value="synthetic_token_12345",
    description="Primary payment gateway connector",
)

result = broker.register_secret(
    tenant_id="tenant_acme",
    connector_id="stripe_payments",
    payload=payload,
    auth_context=admin_ctx,
)
print("Registered:", result)

# AI agents attempting to decrypt credentials are denied fail-closed
from agentguardkit.exceptions import UnauthorizedActionError

agent_ctx = AuthorizationContext(
    actor_id="specialist_agent",
    role=AgentRole.SPECIALIST,
    permitted_tenants=frozenset({"tenant_acme"}),
    is_authenticated=True,
)

try:
    broker.policy_engine.enforce(
        auth_context=agent_ctx,
        action="vault:decrypt_value",
        tenant_id="tenant_acme",
        connector_id="stripe_payments",
    )
except UnauthorizedActionError as e:
    print("Blocked agent action:", e)
```

### 2. HashiCorp Vault KV v2 Production Storage

```python
from agentguardkit.storage.kv2 import HashiCorpVaultKV2Storage

# Enforces remote HTTPS and TLS certificate verification fail-closed
storage = HashiCorpVaultKV2Storage(
    base_url="https://vault.internal.corp:8200",
    mount_point="secret",
    token="s.synthetic_vault_token",
    verify_ssl=True,
    timeout=5.0,
)
```

### 3. Strict Audit Sanitization

```python
from agentguardkit import AuditSanitizer

sanitizer = AuditSanitizer()

raw_telemetry = {
    "ip": "10.0.0.1",
    "method": "POST",
    "status_code": 200,
    "user_agent": "Mozilla/5.0 Bearer ya29.secretBearerToken123",
    "password": "RawPasswordMustBeScrubbed",
    "admin_note": "Rotated synthetic token for prod",
}

clean = sanitizer.sanitize(raw_telemetry)
print(clean)
# Output: {'ip': '10.0.0.1', 'method': 'POST', 'status_code': 200}
```

---

## Implemented vs. Future Roadmap

| Capability | Status in v0.1.0a3 | Notes |
| :--- | :--- | :--- |
| **Tenant Path Derivation** | **Implemented & Tested** | Canonical hierarchical validation (`^[a-zA-Z0-9_-]+$`) |
| **Tenant Authorization Context** | **Implemented & Tested** | Explicit `AuthorizationContext` scope binding fail-closed |
| **Pluggable Storage Protocol** | **Implemented & Tested** | `SecretStorageBackend` protocol |
| **HashiCorp Vault KV v2** | **Implemented & Tested** | Pure Python TLS REST adapter with schema validation |
| **Mock Vault Storage** | **Implemented & Tested** | Thread-safe in-memory engine with fault injection |
| **CAS Concurrency** | **Implemented & Tested** | CAS=0 registration and CAS version rotation |
| **Compensating Rollback** | **Implemented & Tested** | Version rollback with structured recovery records |
| **Deny-by-Default Policy** | **Implemented & Tested** | In-process capability engine with non-overridable invariants |
| **Typed Audit Sanitizer** | **Implemented & Tested** | Typed allowlists and regex pattern scrubbing |
| **Django / FastAPI Adapters** | *Future Roadmap* | Optional framework integrations |
| **Remote MCP Gateway** | *Future Roadmap* | Brokered tool proxy executing outside LLM context |
