# AgentGuardKit Architecture

## 1. Architectural Philosophy

AgentGuardKit is designed around targeted security principles for autonomous agent systems:

1. **Credential Exclusion Principle**: Plaintext credentials are never yielded to LLM execution contexts, prompt loops, or tool parameters by the library.
2. **Explicit Authorization Context**: All credential lifecycle and readiness operations require an explicit `AuthorizationContext` asserted by the trusted host application. Untrusted raw strings from agent prompts cannot establish permissions.
3. **Non-Overridable Invariants**: Custom capability rules can only narrow permissions. Baseline security restrictions (authentication, tenant boundaries, decrypt prohibition, mutation restrictions, execution approval) cannot be bypassed.
4. **In-Process Boundary Awareness**: AgentGuardKit evaluates capability policies and scopes within the host application process. It is **not** an operating system sandbox or hypervisor boundary. The host application is strictly responsible for authenticating users, establishing `AuthorizationContext`, and providing isolated runtime environments for untrusted agent processes.
5. **Zero Mandatory Runtime Dependencies**: The core package relies exclusively on Python standard library modules (`urllib.request`, `ssl`, `json`, `dataclasses`, `threading`). This minimizes attack surface and supply-chain vulnerabilities.
6. **Fail-Closed by Design**: Unconfigured features, unreachable backends, unauthenticated contexts, and ambiguous inputs halt execution safely rather than degrading to insecure defaults.

---

## 2. Component Topology

```
+---------------------------------------------------------------------------------+
|                               Host Application                                  |
|   (Authentication, Session Verification, Process Isolation, Tool Proxies)       |
+----------------------------------------+----------------------------------------+
                                         | Provides verified AuthorizationContext
                                         v
+---------------------------------------------------------------------------------+
|                         AgentGuardKit CredentialBroker                          |
|                                                                                 |
|  +-----------------------+     +-------------------+    +---------------------+ |
|  |     PolicyEngine      |     |  PathDerivation   |    |    AuditSanitizer   | |
|  | - Invariant checking  |     | - Traversal check |    | - Scalar allowlist  | |
|  | - Tenant scope check  |     | - Alphanumeric    |    | - Token pattern scrub| |
|  | - Custom rule engine  |     | - Server-derived  |    | - Size & ReDoS caps | |
|  +-----------------------+     +-------------------+    +---------------------+ |
+--------------------+------------------------------------+-----------------------+
                     |                                    |
                     v                                    v
+------------------------------------+   +------------------------------------+
|        SecretStorageBackend        |   |      CredentialMetadataStore       |
|                                    |   |                                    |
|  [HashiCorpVaultKV2Storage]        |   |  [InMemoryMetadataStore]           |
|  - REST KV v2 TLS client           |   |  - Thread-safe memory store        |
|  - Strict TLS & schema validation  |   |  - Opaque references (vault://...) |
|  - CAS=0 & CAS rotation            |   |  - Sanitized audit event trail     |
|  - Bounded 1MB response reads      |   |  - RollbackRecoveryRecord store    |
|  - Soft-delete semantics           |   |                                    |
|                                    |   |  (Optional Future Adapters:        |
|  [MockVaultStorage]                |   |   PostgreSQL, SQLAlchemy, Redis)   |
|  - Multi-version in-memory engine  |   |                                    |
|  - Granular fault injection testing|   |                                    |
+------------------------------------+   +------------------------------------+
```

---

## 3. Coordinated Write & Compensating Rollback

When registering or rotating a secret:

1. **Step 1 — Authorization Gate**: Verify that the caller supplies a valid, authenticated `AuthorizationContext` authorized for the target resource scope.
2. **Step 2 — Policy Evaluation**: Verify that the caller role possesses administrative privileges for the requested action (`REGISTER` or `ROTATE`), and that custom narrowing rules permit the operation.
3. **Step 3 — Storage Write**: Persist the secret in the storage backend using optimistic concurrency control (`cas=0` for new registrations; `cas=current_version` for rotations). Strictly validate write response schema and positive integer version.
4. **Step 4 — Protected Metadata Operations**: Retrieve and update the metadata connection record within a dedicated try block.
5. **Step 5 — Compensating Rollback (on Error)**: If any post-write metadata operation raises an exception, the broker immediately executes a version-scoped deletion in the storage backend (`storage.delete_secret(path, versions=[new_version])`).
   - *Consistency Note*: This implements an **eventual-consistency compensating rollback pattern**, not an ACID distributed 2PC transaction.
   - *Structured Recovery Records*: If compensating deletion fails or returns False, the broker creates a `RollbackRecoveryRecord` in the metadata store and raises `RollbackError` containing structured recovery identifiers (without raw backend error messages).
6. **Step 6 — Sanitized Audit**: Record a sanitized audit event where all metadata fields are passed through `AuditSanitizer`.
