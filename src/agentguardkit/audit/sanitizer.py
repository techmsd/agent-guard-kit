"""Strict typed allowlist metadata sanitizer and secret scrubber.

Security Model:
---------------
Audit metadata and tool execution logs are UNTRUSTED data originating from LLM agents,
external tool responses, and background tasks. They may contain arbitrary key/value pairs,
accidental tokens, prompt-injected strings, or malformed dumps.

We apply a strict TYPED allowlist for metadata:
- Only explicitly registered fields with declared scalar types survive.
- Custom validators MUST NOT bypass sensitive-key restrictions or introduce nested structures.
- Non-scalar objects (dicts, lists, custom classes) are NEVER coerced to strings and are dropped.
- Semantic validators are enforced:
  - 'ip': parsed strictly with ipaddress.ip_address
  - 'method': validated against safe HTTP verbs
  - 'target_resource', 'target_model', 'resource_type': validated as clean alphanumeric identifiers
  - 'status_code': bounded integer [100, 599]
  - 'duration_ms': non-negative numeric value
  - 'version': positive integer
  - 'created_time', 'rotated_time', 'revoked_at': bounded timestamp strings
  - 'error': bounded clean identifier string
- All surviving strings are scrubbed for known token signatures (AWS keys, GitHub tokens, JWTs, Bearer headers)
  before length clamping, with input bounded to prevent ReDoS.
- Total serialized metadata payload is capped at MAX_METADATA_BYTES (4096 bytes).
"""

from __future__ import annotations

import ipaddress
import json
import math
import re
from collections.abc import Callable
from typing import Any

SENSITIVE_KEY_TERMS = frozenset(
    {
        "secret",
        "key",
        "token",
        "password",
        "cookie",
        "auth",
        "bearer",
        "credential",
        "hash",
        "private",
        "vault",
        "jwt",
        "sign",
        "hmac",
        "api",
    }
)

ALLOWED_HTTP_METHODS = frozenset({"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"})

SECRET_VALUE_REGEXES = [
    # Specific high-entropy token signatures
    (re.compile(r"gh[pousr]_[A-Za-z0-9_]{20,255}"), "[REDACTED_TOKEN]"),
    (re.compile(r"AKIA[0-9A-Z]{16}"), "[REDACTED_AWS_KEY]"),
    (re.compile(r"(?i)bearer\s+[a-zA-Z0-9_\-\.]+"), "Bearer [REDACTED]"),
    (
        re.compile(r"eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}"),
        "[REDACTED_JWT]",
    ),
    # General key=value / key: value patterns
    (
        re.compile(
            r"(?i)(password|secret|token|api[_-]?key|jwt|access[_-]?token|bearer[_-]?token)\s*(?:is|to|[:=])\s*(?!\[REDACTED)\S+"
        ),
        r"\1=[REDACTED]",
    ),
]

MAX_INPUT_STRING_LEN = 1000
MAX_STRING_LEN = 120
MAX_METADATA_BYTES = 4096


def scrub_string(s: str) -> str:
    """Scrub known secret patterns from string and clamp output length."""
    if not isinstance(s, str):
        return ""
    # Bound input length to protect against regex denial of service
    bounded_input = s[:MAX_INPUT_STRING_LEN]
    scrubbed = bounded_input
    for pattern, replacement in SECRET_VALUE_REGEXES:
        scrubbed = pattern.sub(replacement, scrubbed)
    return scrubbed[:MAX_STRING_LEN]


def _validate_ip(value: Any) -> tuple[bool, str | None]:
    if not isinstance(value, str) or isinstance(value, bool):
        return False, None
    clean = value.strip()
    try:
        ipaddress.ip_address(clean)
        return True, clean
    except ValueError:
        return False, None


def _validate_method(value: Any) -> tuple[bool, str | None]:
    if not isinstance(value, str) or isinstance(value, bool):
        return False, None
    clean = value.strip().upper()
    if clean in ALLOWED_HTTP_METHODS:
        return True, clean
    return False, None


def _validate_target_resource(value: Any) -> tuple[bool, str | None]:
    if not isinstance(value, str) or isinstance(value, bool):
        return False, None
    clean = value.strip()
    if re.match(r"^[A-Za-z][a-zA-Z0-9_\-]{0,63}$", clean):
        if not any(term in clean.lower() for term in SENSITIVE_KEY_TERMS):
            return True, clean
    return False, None


def _validate_status_code(value: Any) -> tuple[bool, int | None]:
    if isinstance(value, bool) or not isinstance(value, int):
        return False, None
    if 100 <= value <= 599:
        return True, value
    return False, None


def _validate_duration_ms(value: Any) -> tuple[bool, float | None]:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return False, None
    if not math.isfinite(value):
        return False, None
    if 0 <= value <= 3_600_000:
        return True, round(float(value), 2)
    return False, None


def _validate_version(value: Any) -> tuple[bool, int | None]:
    if isinstance(value, bool) or not isinstance(value, int):
        return False, None
    if 1 <= value <= 1_000_000:
        return True, value
    return False, None


def _validate_timestamp_str(value: Any) -> tuple[bool, str | None]:
    if not isinstance(value, str) or isinstance(value, bool):
        return False, None
    clean = value.strip()
    if len(clean) <= 50 and re.match(r"^[0-9TZ:\-\.\+]+$", clean):
        return True, clean
    return False, None


def _validate_clean_str(value: Any) -> tuple[bool, str | None]:
    if not isinstance(value, str) or isinstance(value, bool):
        return False, None
    clean = value.strip()
    if len(clean) <= 100 and re.match(r"^[a-zA-Z0-9_\-]+$", clean):
        return True, clean
    return False, None


DEFAULT_FIELD_VALIDATORS: dict[str, Callable[[Any], tuple[bool, Any]]] = {
    "ip": _validate_ip,
    "method": _validate_method,
    "target_resource": _validate_target_resource,
    "target_model": _validate_target_resource,
    "resource_type": _validate_clean_str,
    "status_code": _validate_status_code,
    "duration_ms": _validate_duration_ms,
    "version": _validate_version,
    "created_time": _validate_timestamp_str,
    "rotated_time": _validate_timestamp_str,
    "revoked_at": _validate_timestamp_str,
    "error": _validate_clean_str,
}


class AuditSanitizer:
    """Strict typed-allowlist sanitizer for audit and telemetry metadata."""

    def __init__(
        self,
        custom_validators: dict[str, Callable[[Any], tuple[bool, Any]]] | None = None,
        max_bytes: int = MAX_METADATA_BYTES,
    ):
        self.validators = dict(DEFAULT_FIELD_VALIDATORS)
        if custom_validators:
            self.validators.update(custom_validators)
        self.max_bytes = max_bytes

    def sanitize(self, raw_metadata: Any) -> dict[str, Any]:
        """Sanitize an untrusted dictionary of audit metadata."""
        if not isinstance(raw_metadata, dict):
            return {}

        out: dict[str, Any] = {}
        for k, v in raw_metadata.items():
            if not isinstance(k, str):
                continue
            k_clean = k.lower().strip()

            # NON-OVERRIDABLE INVARIANT: Drop any key containing sensitive terms unconditionally
            if any(term in k_clean for term in SENSITIVE_KEY_TERMS):
                continue

            validator = self.validators.get(k_clean)
            if validator is not None:
                try:
                    result = validator(v)
                    if not isinstance(result, tuple) or len(result) != 2:
                        continue
                    accepted, cleaned = result
                except Exception:
                    # Fail-closed if a validator raises an unexpected error
                    continue

                if accepted:
                    # Invariant: Only valid bounded scalar types survive sanitization
                    if isinstance(cleaned, bool):
                        out[k_clean] = cleaned
                    elif isinstance(cleaned, (int, float)):
                        if math.isfinite(cleaned):
                            out[k_clean] = cleaned
                    elif isinstance(cleaned, str):
                        out[k_clean] = scrub_string(cleaned)
                    else:
                        # Non-scalar values (dicts, lists, objects) are dropped fail-closed
                        continue

        try:
            serialized = json.dumps(out)
        except (TypeError, ValueError):
            return {}

        if len(serialized.encode("utf-8")) > self.max_bytes:
            return {"_error": "metadata_too_large"}

        return out
