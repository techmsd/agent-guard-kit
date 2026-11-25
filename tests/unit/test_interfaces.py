"""Unit tests for typed interfaces and SecretPayload validation."""

import pytest

from agentguardkit.exceptions import InvalidPayloadError
from agentguardkit.interfaces import (
    MAX_DESCRIPTION_LENGTH,
    MAX_METADATA_BYTES,
    MAX_METADATA_KEYS,
    MAX_SECRET_LENGTH_BYTES,
    BrokerReadiness,
    SecretPayload,
)


def test_secret_payload_valid():
    p = SecretPayload(
        secret_type="api_key",
        secret_value="synthetic_value_123",
        description="test description",
        custom_metadata={"env": "dev"},
    )
    assert p.secret_type == "api_key"
    assert p.secret_value == "synthetic_value_123"
    assert p.description == "test description"
    assert p.custom_metadata == {"env": "dev"}


def test_secret_payload_repr_excludes_sensitive_fields():
    secret_val = "SECRET_VALUE_MUST_NOT_BE_IN_REPR"
    desc_val = "CONFIDENTIAL_DESCRIPTION_DO_NOT_LEAK"
    meta_val = "PRIVATE_METADATA_VALUE"
    p = SecretPayload(
        secret_type="api_key",
        secret_value=secret_val,
        description=desc_val,
        custom_metadata={"client_id": meta_val},
    )
    payload_repr = repr(p)

    # Invariants: None of secret_value, description text, metadata values, or metadata keys appear in repr
    assert secret_val not in payload_repr
    assert desc_val not in payload_repr
    assert meta_val not in payload_repr
    assert "has_description=True" in payload_repr
    assert "client_id" not in payload_repr  # Metadata keys must not leak
    assert "custom_metadata_count=1" in payload_repr
    assert "secret_type='api_key'" in payload_repr
    assert str(p) == payload_repr


def test_secret_payload_repr_masks_arbitrary_secret_types():
    arbitrary_type = "sensitive_internal_token_type_99"
    p = SecretPayload(
        secret_type=arbitrary_type,
        secret_value="synthetic_value",
    )
    payload_repr = repr(p)

    # Invariant: Arbitrary non-standard secret-type strings are masked to prevent token leakage
    assert arbitrary_type not in payload_repr
    assert "secret_type='[CUSTOM]'" in payload_repr
    assert str(p) == payload_repr


@pytest.mark.parametrize("invalid_type", ["", "   ", 123, None, True])
def test_secret_payload_rejects_invalid_type(invalid_type):
    with pytest.raises(InvalidPayloadError):
        SecretPayload(secret_type=invalid_type, secret_value="valid")  # type: ignore


@pytest.mark.parametrize("invalid_val", [123, None, True, ["secret"]])
def test_secret_payload_rejects_invalid_value(invalid_val):
    with pytest.raises(InvalidPayloadError):
        SecretPayload(secret_type="api_key", secret_value=invalid_val)  # type: ignore


def test_secret_payload_rejects_oversized_value():
    huge_secret = "x" * (MAX_SECRET_LENGTH_BYTES + 1)
    with pytest.raises(InvalidPayloadError) as exc:
        SecretPayload(secret_type="api_key", secret_value=huge_secret)
    assert "exceeds maximum permitted size" in str(exc.value)


def test_secret_payload_rejects_oversized_description():
    huge_desc = "d" * (MAX_DESCRIPTION_LENGTH + 1)
    with pytest.raises(InvalidPayloadError) as exc:
        SecretPayload(secret_type="api_key", secret_value="val", description=huge_desc)
    assert "description exceeds maximum permitted length" in str(exc.value)


def test_secret_payload_rejects_too_many_metadata_keys():
    many_keys = {f"k{i}": f"v{i}" for i in range(MAX_METADATA_KEYS + 1)}
    with pytest.raises(InvalidPayloadError) as exc:
        SecretPayload(secret_type="api_key", secret_value="val", custom_metadata=many_keys)
    assert "exceeds maximum allowed 50 keys" in str(exc.value)


def test_secret_payload_rejects_deeply_nested_metadata():
    deep_meta = {"l1": {"l2": {"l3": {"l4": "too_deep"}}}}
    with pytest.raises(InvalidPayloadError) as exc:
        SecretPayload(secret_type="api_key", secret_value="val", custom_metadata=deep_meta)
    assert "exceeds maximum nesting depth" in str(exc.value)


def test_secret_payload_rejects_non_json_serializable_metadata():
    class Unserializable:
        pass

    with pytest.raises(InvalidPayloadError) as exc:
        SecretPayload(
            secret_type="api_key",
            secret_value="val",
            custom_metadata={"obj": Unserializable()},
        )
    assert "JSON-serializable" in str(exc.value)


def test_secret_payload_rejects_oversized_metadata():
    large_meta = {"key": "x" * (MAX_METADATA_BYTES + 10)}
    with pytest.raises(InvalidPayloadError) as exc:
        SecretPayload(secret_type="api_key", secret_value="val", custom_metadata=large_meta)
    assert "serialized size exceeds maximum permitted" in str(exc.value)


def test_broker_readiness_to_dict():
    r = BrokerReadiness(
        storage_enabled=True,
        readiness_code="ready",
        readiness_label="Ready",
        has_secret=True,
        status="stored",
        secret_version=2,
        last_updated="2026-11-25T00:00:00Z",
        can_mutate=True,
        notice="Operational",
    )
    d = r.to_dict()
    assert d["storage_enabled"] is True
    assert d["readiness_code"] == "ready"
    assert d["secret_version"] == 2
