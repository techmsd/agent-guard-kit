# Security Policy

## Reporting Security Issues

We take the security of AgentGuardKit seriously. If you believe you have discovered a vulnerability, please do not open a public issue.

Instead, please report security issues privately:
- **Private Reporting**: Use GitHub Security Advisories tab on the repository (once public) or contact the project maintainers directly.
- **Expected Information**:
  - Description of the vulnerability and attack vector.
  - Minimal reproducible example or test case.
  - Impact assessment (e.g. cross-tenant leakage, secret disclosure in memory/logs).
- **Response Timeline**:
  - Initial acknowledgment: Within 48 hours.
  - Triage and mitigation assessment: Within 7 business days.

---

## Security Boundaries & Design Invariants

AgentGuardKit enforces several invariants by design:

1. **Zero Secret Storage in Metadata / DB**:
   The metadata layer persists only opaque references (`vault://...`) and status badges. Plaintext secrets are never stored in business tables, audit logs, or error responses.

2. **Zero Plaintext Credentials in Agent Prompts or Memory**:
   AI agent roles are unconditionally prohibited from requesting decrypted credentials (`vault:decrypt_value`). Agents receive only sanitized status or capability proposals.

3. **Strict Path Derivation & Identifier Validation**:
   Paths are strictly server-derived from sanitized tenant and connector identifiers (`tenants/{tenant_id}/connectors/{connector_id}`). Caller-controlled arbitrary paths, traversal sequences (`..`), and delimiters are rejected fail-closed.

4. **TLS Enforcement & Redirect Protection**:
   Remote HTTP endpoints are rejected fail-closed. Loopback HTTP (`127.0.0.1`, `localhost`) is permitted solely for local developer testing. HTTP redirects are inspected to disallow scheme downgrades (HTTPS -> HTTP) and cross-domain token forwarding.

5. **Compensating Rollback**:
   If metadata persistence fails after a secret write, the newly written secret version is automatically revoked/deleted from storage to eliminate orphaned secrets.

---

## Known Limitations

- **Prompt Injection Defense-in-Depth**:
  While AgentGuardKit prevents agents from reading raw credentials directly, granting an agent permission to invoke a tool proxy means that an adversarial prompt injection may still trick the model into executing unintended tool actions. Complementary prompt inspection and output filtering must be applied.
- **Third-Party External Invalidation**:
  Soft-deleting a secret in HashiCorp Vault KV v2 removes the key from the vault store. It does **not** invalidate or revoke the credential at the external third-party provider (e.g. Stripe, Zoom, Meta). External provider revocation must be managed independently.
