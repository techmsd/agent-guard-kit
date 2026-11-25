"""Unit tests for tenant-scoped path derivation and identifier validation."""

import uuid

import pytest

from agentguardkit.exceptions import InvalidPathError
from agentguardkit.path import derive_tenant_secret_path, validate_identifier


def test_validate_identifier_valid_uuid():
    u = uuid.uuid4()
    clean = validate_identifier(u)
    assert clean == str(u).lower()


def test_validate_identifier_valid_alphanumeric():
    assert validate_identifier("tenant-123_abc") == "tenant-123_abc"
    assert validate_identifier("ACME_Corp") == "acme_corp"


@pytest.mark.parametrize(
    "invalid_input",
    [
        "",
        "   ",
        "../traversal",
        "tenant/subpath",
        "tenant\\subpath",
        "tenant\0nullbyte",
        "tenant*wildcard",
        "tenant;command",
        "tenant$variable",
        "a" * 65,  # Exceeds 64 chars
        12345,  # Non-string/UUID
        True,  # Boolean
        None,  # None
    ],
)
def test_validate_identifier_rejects_malformed(invalid_input):
    with pytest.raises(InvalidPathError):
        validate_identifier(invalid_input)  # type: ignore


def test_derive_tenant_secret_path_standard():
    tid = "client_alpha"
    cid = "zoom_prod"
    path = derive_tenant_secret_path(tid, cid)
    assert path == "tenants/client_alpha/connectors/zoom_prod"
    assert ".." not in path
    assert not path.startswith("/")


def test_derive_tenant_secret_path_with_uuids():
    tid = uuid.uuid4()
    cid = uuid.uuid4()
    path = derive_tenant_secret_path(tid, cid)
    assert path == f"tenants/{str(tid).lower()}/connectors/{str(cid).lower()}"


def test_derive_tenant_secret_path_custom_prefix():
    path = derive_tenant_secret_path("cust_1", "meta_ads", prefix="organizations")
    assert path == "organizations/cust_1/connectors/meta_ads"


def test_derive_tenant_secret_path_rejects_traversal_in_prefix():
    with pytest.raises(InvalidPathError):
        derive_tenant_secret_path("cust_1", "meta_ads", prefix="../hack")
