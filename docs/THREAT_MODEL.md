# Threat Model & Security Boundaries

## 1. Threat Scenarios & Mitigations

| Threat | Attack Vector | Mitigation in AgentGuardKit |
| :--- | :--- | :--- |
| **T1: Prompt Injection Exfiltration** | Malicious content in agent input induces the LLM to output credentials. | Agent capability policy unconditionally denies `vault:decrypt_value` to agent roles. The agent never receives plaintext secrets. |
| **T2: Implicit / Spoofed Role Permissions** | Caller omits authorization or passes a raw string like `"human_admin"` from an agent prompt. | Default admin parameters are completely eliminated. All broker operations require an explicit, authenticated `AuthorizationContext` supplied by the trusted host application. Missing, unauthenticated, or invalid contexts fail closed. |
| **T3: Custom Rule Privilege Escalation** | Custom policy rule attempts to grant agents permission to decrypt credentials or mutate secrets. | Non-overridable security invariants: baseline built-in restrictions evaluate first. Custom rules can only narrow permissions; they cannot override denials. |
| **T4: Cross-Tenant Data Access** | Actor operating under Tenant A attempts to mutate or access Tenant B's credentials. | `AuthorizationContext` enforces tenant and connector scopes fail-closed. Storage paths are strictly namespaced (`tenants/{id}/connectors/{id}`) with alphanumeric validation. |
| **T5: Concurrency Lost Updates** | Two processes attempt to mutate the same credential concurrently. | Enforces `cas=0` on registration and `cas=current_version` on rotation. Conflicting updates fail closed with `CasMismatchError`. |
| **T6: Telemetry & Log Leakage** | Tokens or passwords dumped into error traces, dataclass reprs, recovery records, or audit records. | `SecretPayload` custom `__repr__` redacts `secret_value`, hides `description` text, and exposes only metadata keys. Raw backend exception strings are excluded from errors and logs. `AuditSanitizer` enforces typed scalar allowlists and token pattern scrubbing. |
| **T7: Insecure Transport & Vault Response Manipulation** | Remote HTTP endpoints, disabled TLS verification, or malformed Vault responses. | Remote plaintext HTTP and disabling TLS verification for remote endpoints are strictly prohibited fail-closed (`InsecureTransportError`). Vault write responses are validated for schema integrity and positive integer version. |
| **T8: Split-Brain / Orphaned Secrets** | Storage write succeeds but metadata retrieval or persistence fails. | Every post-write metadata operation is protected in a try block. If an error occurs, the broker coordinates a version-scoped compensating deletion. Structured recovery records track uncompleted rollbacks. |
| **T9: Telemetry Injection & Nested Dumps** | Malformed telemetry or custom validators injecting nested dicts or bypassing sensitive key checks. | Sensitive key terms are blocked unconditionally. Custom validators cannot return non-scalar objects. Inputs are bounded prior to pattern scrubbing. |

---

## 2. Non-Goals and Explicit Exclusions

1. **In-Process vs. OS Sandbox Boundary**:
   AgentGuardKit operates within the Python runtime of the host application. It is **not** an operating system sandbox, container boundary, or hypervisor isolation layer. The host application must enforce isolated execution environments for untrusted agent runtimes.
2. **Host Authentication Responsibility**:
   AgentGuardKit does not authenticate human users or manage user password hashes; the host application must authenticate the principal and construct the `AuthorizationContext`.
3. **Immunity to Prompt Injection**:
   AgentGuardKit withholds credential material from the agent's memory. It does not prevent an agent from being tricked into misusing permitted tools (e.g. asking an authorized email tool to send a phishing message).
4. **External SaaS Credential Revocation**:
   Deleting a credential in storage removes it from the vault. It does not notify third-party providers (Stripe, AWS, Meta) to invalidate the external API key.
