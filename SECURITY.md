# Security Policy

> [!WARNING]
> ### Experimental Alpha Security Notice (`v0.1.0a3`)
> **AgentGuardKit is an experimental pre-release alpha.**
> - **No Independent Security Audit**: This software has **NOT** undergone an independent external security audit.
> - **In-Process Boundary**: AgentGuardKit operates in host process memory; it is not an OS sandbox, hypervisor, or network proxy.
> - **Not Recommended for Production**: **Do NOT use this package to manage live production credentials or sensitive customer data.**

---

## Reporting Security Issues

We take the security of AgentGuardKit seriously. If you believe you have discovered a vulnerability, please do not open a public issue.

Instead, please report security issues privately:
- **Private Reporting**: Use GitHub Security Advisories tab on the repository (once enabled) or contact the project maintainers directly.
- **Expected Information**:
  - Description of the vulnerability and attack vector.
  - Minimal reproducible example or test case.
  - Impact assessment (e.g. cross-tenant leakage, secret disclosure in memory/logs).
- **Response Timeline**:
  - Initial acknowledgment: Within 48 hours.
  - Triage and mitigation assessment: Within 7 business days.

---

## Security Boundaries & Design Capabilities

Within its in-process Python library scope, AgentGuardKit provides the following capabilities:

1. **Brokered Metadata Storage**:
   The metadata layer persists only opaque storage references (`vault://...`) and status badges. The core broker does not store plaintext secrets in business tables or audit logs.

2. **Prohibition of Plaintext Secret Decryption for Agents**:
   AI agent roles are denied `vault:decrypt_value` requests fail-closed by the policy engine. Downstream actions are gated behind capability proposals. Note: Host applications remain strictly responsible for isolating agent execution environments and preventing secret disclosure outside this library.

3. **Strict Path Derivation & Identifier Validation**:
   Paths are strictly server-derived from sanitized tenant and connector identifiers (`tenants/{tenant_id}/connectors/{connector_id}`). Caller-controlled arbitrary paths, traversal sequences (`..`), null bytes, and delimiters are rejected fail-closed.

4. **TLS Enforcement & Redirect Protection**:
   Remote HTTP endpoints are rejected fail-closed. Loopback HTTP (`127.0.0.1`, `localhost`, `::1`) is permitted solely for local developer testing. HTTP redirects are inspected to disallow scheme downgrades (HTTPS -> HTTP) and cross-domain token forwarding.

5. **Eventual-Consistency Compensating Rollback**:
   If metadata persistence fails after a secret write, the broker attempts compensating deletion of the newly written version. If rollback itself fails, a structured `RollbackRecoveryRecord` is preserved for operator reconciliation. This is an eventual-consistency compensating mechanism, not an atomic distributed 2PC transaction.

---

## Known Limitations & Host Application Responsibilities

- **Prompt Injection Defense-in-Depth**:
  While AgentGuardKit prevents agents from reading raw credentials directly through broker APIs, an autonomous agent with tool invocation permissions may still be manipulated by adversarial prompt injections into requesting unauthorized actions. Host applications must implement independent prompt sanitization, execution sandboxing, and output filtering.
- **Third-Party External Invalidation**:
  Soft-deleting a secret in HashiCorp Vault KV v2 marks the secret destroyed in Vault. It does **not** invalidate or revoke the credential at external third-party providers (e.g. Stripe, Zoom, AWS). External provider revocation must be managed independently.
- **Host Process Memory**:
  Because AgentGuardKit executes within the host Python process, code with arbitrary process memory read access (e.g., C extensions or untrusted Python code running in the same process) can inspect memory. Untrusted agent tools must run in separate sandboxed processes.
