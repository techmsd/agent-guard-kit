"""Unit tests for typed audit metadata sanitizer and secret scrubber."""

import pytest

from agentguardkit.audit.sanitizer import AuditSanitizer, scrub_string


@pytest.fixture
def sanitizer():
    return AuditSanitizer()


def test_allowlisted_fields_pass(sanitizer):
    raw = {
        "ip": "192.168.1.10",
        "method": "POST",
        "target_resource": "ClientConnector",
        "status_code": 201,
        "duration_ms": 45.67,
        "version": 1,
        "resource_type": "api_key",
        "created_time": "2026-11-25T11:00:00Z",
    }
    clean = sanitizer.sanitize(raw)
    assert clean["ip"] == "192.168.1.10"
    assert clean["method"] == "POST"
    assert clean["target_resource"] == "ClientConnector"
    assert clean["status_code"] == 201
    assert clean["duration_ms"] == 45.67
    assert clean["version"] == 1
    assert clean["resource_type"] == "api_key"
    assert clean["created_time"] == "2026-11-25T11:00:00Z"


def test_ip_validation_semantic(sanitizer):
    valid_ipv4 = sanitizer.sanitize({"ip": "10.0.0.1"})
    assert valid_ipv4.get("ip") == "10.0.0.1"

    valid_ipv6 = sanitizer.sanitize({"ip": "2001:db8::1"})
    assert valid_ipv6.get("ip") == "2001:db8::1"

    invalid_ip = sanitizer.sanitize({"ip": "999.999.999.999"})
    assert "ip" not in invalid_ip

    non_string_ip = sanitizer.sanitize({"ip": 12345})
    assert "ip" not in non_string_ip


def test_method_validation(sanitizer):
    assert sanitizer.sanitize({"method": "get"}) == {"method": "GET"}
    assert sanitizer.sanitize({"method": "DELETE"}) == {"method": "DELETE"}
    assert sanitizer.sanitize({"method": "HACK"}) == {}


def test_sensitive_keys_dropped_unconditionally():
    # Sensitive keys must be dropped even if a custom validator is registered for them
    san = AuditSanitizer(custom_validators={"user_secret": lambda v: (True, "allowed_value")})
    raw = {
        "password": "SuperSecretPassword123!",
        "auth_token": "Bearer token123",
        "api_key": "xyz123",
        "vault_secret": "my-secret",
        "jwt_signature": "sig",
        "user_secret": "custom_val",
    }
    clean = san.sanitize(raw)
    assert clean == {}


def test_custom_validator_cannot_inject_nested_structures():
    # Custom validator returning a dictionary or list MUST be dropped fail-closed
    san = AuditSanitizer(
        custom_validators={
            "nested_field": lambda v: (True, {"injected_key": "injected_val"}),
            "list_field": lambda v: (True, [1, 2, 3]),
        }
    )
    clean = san.sanitize({"nested_field": "val", "list_field": "val"})
    assert "nested_field" not in clean
    assert "list_field" not in clean


def test_malformed_custom_validator_return_fails_closed():
    # Validator returning non-tuple or wrong length
    san = AuditSanitizer(
        custom_validators={
            "bad_return_1": lambda v: True,  # type: ignore
            "bad_return_2": lambda v: (True, "val", "extra"),  # type: ignore
        }
    )
    clean = san.sanitize({"bad_return_1": "val", "bad_return_2": "val"})
    assert clean == {}


def test_nested_structures_and_free_text_dropped(sanitizer):
    raw = {
        "user_agent": "Mozilla/5.0 with Bearer ya29.token",
        "change_summary": "Rotated key for admin",
        "nested_dict": {"token": "secret"},
        "nested_list": [1, 2, 3],
    }
    clean = sanitizer.sanitize(raw)
    assert clean == {}


def test_non_string_keys_handled_safely(sanitizer):
    raw = {
        123: "val",
        ("tuple", "key"): "val2",
        None: "val3",
        "ip": "127.0.0.1",
    }
    clean = sanitizer.sanitize(raw)
    assert clean == {"ip": "127.0.0.1"}


def test_custom_validator_exception_fails_closed():
    def buggy_validator(v):
        raise ValueError("Buggy validator crash")

    sanitizer = AuditSanitizer(custom_validators={"buggy_field": buggy_validator})
    clean = sanitizer.sanitize({"buggy_field": "test_value"})
    assert "buggy_field" not in clean


def test_secret_scrubbing_patterns():
    # AWS key pattern test (synthetic)
    synthetic_aws_key = "AKIA" + "IOSFODNN7EXAMPLE"
    aws_text = f"Target is {synthetic_aws_key} in us-east-1"
    scrubbed_aws = scrub_string(aws_text)
    assert synthetic_aws_key not in scrubbed_aws
    assert "[REDACTED_AWS_KEY]" in scrubbed_aws

    # GitHub token
    gh_token = "ghp_" + "a" * 36
    scrubbed_gh = scrub_string(f"Token: {gh_token}")
    assert gh_token not in scrubbed_gh
    assert "[REDACTED_TOKEN]" in scrubbed_gh

    # Bearer token
    bearer_text = "Authorization: Bearer secret_bearer_token_12345"
    scrubbed_bearer = scrub_string(bearer_text)
    assert "secret_bearer_token_12345" not in scrubbed_bearer
    assert "Bearer [REDACTED]" in scrubbed_bearer

    # JWT
    jwt_text = "Token eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.doNotLeakThisSignature"
    scrubbed_jwt = scrub_string(jwt_text)
    assert "eyJhbGciOiJIUzI1NiJ9" not in scrubbed_jwt
    assert "[REDACTED_JWT]" in scrubbed_jwt


def test_oversized_metadata_capped(sanitizer):
    # Pack oversized valid metadata to exceed 4096 bytes
    custom = {f"custom_{i}": f"safe_value_{i}" for i in range(300)}
    sanitizer_with_custom = AuditSanitizer(
        custom_validators={k: lambda v: (True, str(v)) for k in custom}
    )
    clean = sanitizer_with_custom.sanitize(custom)
    assert clean == {"_error": "metadata_too_large"}


def test_semantic_validators_direct_coverage():
    from agentguardkit.audit.sanitizer import (
        _validate_clean_str,
        _validate_duration_ms,
        _validate_status_code,
        _validate_target_resource,
        _validate_timestamp_str,
        _validate_version,
    )

    # _validate_target_resource
    assert _validate_target_resource("ValidResource_1")[0] is True
    assert _validate_target_resource("invalid resource space")[0] is False
    assert _validate_target_resource(123)[0] is False
    assert _validate_target_resource("contains_secret_key")[0] is False

    # _validate_status_code
    assert _validate_status_code(200) == (True, 200)
    assert _validate_status_code(99)[0] is False
    assert _validate_status_code(600)[0] is False
    assert _validate_status_code(True)[0] is False
    assert _validate_status_code("200")[0] is False

    # _validate_duration_ms
    assert _validate_duration_ms(150.5)[0] is True
    assert _validate_duration_ms(-1)[0] is False
    assert _validate_duration_ms(4_000_000)[0] is False
    assert _validate_duration_ms("150")[0] is False
    assert _validate_duration_ms(True)[0] is False
    assert _validate_duration_ms(float("inf"))[0] is False

    # _validate_version
    assert _validate_version(1) == (True, 1)
    assert _validate_version(0)[0] is False
    assert _validate_version(2_000_000)[0] is False
    assert _validate_version(True)[0] is False
    assert _validate_version("1")[0] is False

    # _validate_timestamp_str
    assert _validate_timestamp_str("2026-11-25T11:00:00Z")[0] is True
    assert _validate_timestamp_str("bad timestamp with spaces")[0] is False
    assert _validate_timestamp_str("x" * 60)[0] is False
    assert _validate_timestamp_str(12345)[0] is False
    assert _validate_timestamp_str(True)[0] is False

    # _validate_clean_str
    assert _validate_clean_str("valid-clean_123")[0] is True
    assert _validate_clean_str("invalid char &^%")[0] is False
    assert _validate_clean_str("x" * 150)[0] is False
    assert _validate_clean_str(99)[0] is False
    assert _validate_clean_str(True)[0] is False
