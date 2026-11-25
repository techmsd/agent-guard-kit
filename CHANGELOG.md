# Changelog

All notable changes to AgentGuardKit will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [0.1.0a3] - 2026-11-25

> **Experimental Alpha** — Corrected PyPI distribution name to match registered Trusted Publisher project.

### Changed
- **PyPI Distribution Package Name**: Updated package name from `agentguardkit-sdk` to `agent-guard-kit-sdk` in `pyproject.toml` to match the PyPI project registered under the Trusted Publisher configuration.
- **Brand & Import Namespace**: Retained the `AgentGuardKit` brand identity, GitHub repository (`techmsd/agent-guard-kit`), and standard Python import namespace (`import agentguardkit`).
- **Publishing & Documentation**: Updated distribution URLs in `.github/workflows/publish.yml`, `README.md`, and version references for `v0.1.0a3`.

---

## [0.1.0a2] - 2026-11-25

> **Experimental Alpha** — Updated distribution package name for PyPI.

### Changed
- **PyPI Distribution Package Name**: Updated package name from `agent-guard-kit` to `agentguardkit-sdk` in `pyproject.toml` due to similarity collision with an existing project on PyPI.
- **Brand & Import Namespace**: Retained the `AgentGuardKit` brand identity, GitHub repository (`techmsd/agent-guard-kit`), and standard Python import namespace (`import agentguardkit`).
- **Publishing & Documentation**: Updated distribution URLs in `.github/workflows/publish.yml`, `README.md`, and security references for `v0.1.0a2`.

---

## [0.1.0a1] - 2026-11-25

> **Experimental Alpha** — Public API may change before the stable 0.1.0 release.
> This release has NOT been published to PyPI.

### Added
- **Core Broker Engine**: Framework-independent `CredentialBroker` managing tenant secret lifecycles across pluggable backends.
- **Pluggable Storage Protocol**: `SecretStorageBackend` interface with production `HashiCorpVaultKV2Storage` and in-memory `MockVaultStorage`.
- **Pure Standard Library Vault Adapter**: Lightweight HTTPS client supporting Token and AppRole authentication, TLS verification, CAS preconditions (mapping HTTP 400 and 412), and safe redirect handling.
- **Tenant Path Derivation & Validation**: Hierarchical path derivation (`tenants/{tenant_id}/connectors/{connector_id}`) rejecting path traversal (`..`), null bytes, and invalid character sequences.
- **Two-Phase Compensating Rollback**: Version-scoped compensating deletion in storage engines upon metadata persistence failures, preventing orphaned credentials.
- **Deny-by-Default Policy Engine**: Strict actor role matrix unconditionally denying secret decryption to autonomous AI agents and gating tool execution behind capability proposals.
- **Strict Typed Audit Sanitizer**: Typed allowlisting and secret scrubbing for telemetry data, preventing credential leakage in logs and traces.
- **Comprehensive Security Test Suite**: 130 automated tests achieving 92.45% coverage across tenant isolation, CAS conflicts, rollback, fault injection, and policy invariant bypass attempts.

### Security Hardening (pre-release, PR #1)
- **Non-Overridable Policy Invariants**: Custom rules evaluate *after* baseline security rules and can only narrow permissions; they cannot override authentication, tenant boundary, decrypt denial, mutation restriction, or proposal gating checks. `AuthorizationContext.is_authenticated` defaults to `False` (fail-closed).
- **Complete Rollback Protection**: Every post-write metadata operation (retrieval and persistence) is inside the compensating rollback try block. Rollback failure produces a structured `RollbackRecoveryRecord` and raises `RollbackError` with safe diagnostic codes even if the metadata store is offline.
- **Secret Leakage Path Elimination**: Raw backend exception strings replaced with stable `diagnostic_code` values (`e.__class__.__name__`). `SecretPayload.__repr__` redacts `secret_value`, hides description text (`has_description`), masks arbitrary non-standard secret types as `'[CUSTOM]'`, and emits only metadata counts (`custom_metadata_count`) without metadata keys or values.
- **Complete Readiness Authorization**: Tenant readiness queries enforce `READ_METADATA` policy via `PolicyEngine.enforce()`. Read-only actors receive `can_mutate=False`. Explicit handling added for `storage_uninitialized` and `storage_standby` states without exposing raw backend errors.
- **Vault Response Schema Validation**: Write response validated for positive integer `version >= 1`; fallback assumptions removed. Finite float enforcement for timeout configuration.
- **Hardened Audit Sanitizer**: Sensitive key terms blocked unconditionally regardless of custom validators. Only valid bounded scalar types survive. Input strings bounded prior to regex pattern scrubbing.

### Known Limitations (alpha)
- No optional framework adapters (Django, FastAPI) yet — planned for 0.2.0.
- `HashiCorpVaultKV2Storage` does not support Vault namespaces or transit-encrypted fields.
- External SaaS credential revocation (Stripe, AWS, Google) is out of scope; soft-delete only.
- AgentGuardKit operates in-process; it is not an OS or container isolation boundary.
- PyPI publication pending independent security review and stable API confirmation.

### Breaking Changes
- `AuthorizationContext.is_authenticated` now defaults to `False`. Host applications that relied on the previous `True` default must explicitly set `is_authenticated=True` after authenticating the caller.
- `AuthorizationContext` raises `ValueError` on empty/whitespace `actor_id` and empty `permitted_tenant_ids`/`permitted_connector_ids` collections.
