"""Unit tests for HashiCorpVaultKV2Storage adapter and security boundaries."""

import io
import urllib.error
from unittest.mock import patch

import pytest

from agentguardkit.exceptions import (
    CasMismatchError,
    InsecureTransportError,
    StorageAuthenticationError,
    StorageError,
    StorageNotFoundError,
    StoragePermissionDeniedError,
    StorageSealedError,
    UnsafeRedirectError,
    ValidationError,
)
from agentguardkit.storage.kv2 import HashiCorpVaultKV2Storage, _SafeRedirectHandler


def test_transport_validation_remote_http_rejected():
    with pytest.raises(InsecureTransportError) as exc:
        HashiCorpVaultKV2Storage(base_url="http://vault.example.com:8200")
    assert "remote Vault endpoint" in str(exc.value)
    assert exc.value.code == "insecure_transport"


def test_transport_validation_remote_verify_ssl_false_prohibited():
    with pytest.raises(InsecureTransportError) as exc:
        HashiCorpVaultKV2Storage(base_url="https://vault.example.com:8200", verify_ssl=False)
    assert "verify_ssl=False" in str(exc.value)


def test_transport_validation_loopback_http_allowed():
    # 127.0.0.1 and localhost permitted for local development
    storage1 = HashiCorpVaultKV2Storage(base_url="http://127.0.0.1:8200")
    assert storage1.base_url == "http://127.0.0.1:8200"

    storage2 = HashiCorpVaultKV2Storage(base_url="http://localhost:8200")
    assert storage2.base_url == "http://localhost:8200"


def test_transport_validation_invalid_scheme():
    with pytest.raises(InsecureTransportError):
        HashiCorpVaultKV2Storage(base_url="ftp://127.0.0.1:8200")


def test_transport_validation_rejects_userinfo():
    with pytest.raises(InsecureTransportError) as exc:
        HashiCorpVaultKV2Storage(base_url="https://admin:secret@vault.corp:8200")
    assert "user credentials" in str(exc.value)


def test_transport_validation_rejects_query_and_fragment():
    with pytest.raises(InsecureTransportError) as exc1:
        HashiCorpVaultKV2Storage(base_url="https://vault.corp:8200/path?key=val")
    assert "query parameters" in str(exc1.value)

    with pytest.raises(InsecureTransportError) as exc2:
        HashiCorpVaultKV2Storage(base_url="https://vault.corp:8200#frag")
    assert "fragments" in str(exc2.value)


def test_configuration_validation_invalid_mount_and_timeout():
    with pytest.raises(ValidationError) as exc_mount:
        HashiCorpVaultKV2Storage(base_url="http://127.0.0.1:8200", mount_point="secret/../bad")
    assert "Invalid mount point format" in str(exc_mount.value)

    with pytest.raises(ValidationError) as exc_timeout:
        HashiCorpVaultKV2Storage(base_url="http://127.0.0.1:8200", timeout=-5)
    assert "Timeout must be a finite positive number" in str(exc_timeout.value)

    # Non-finite timeouts
    with pytest.raises(ValidationError):
        HashiCorpVaultKV2Storage(base_url="http://127.0.0.1:8200", timeout=float("inf"))

    with pytest.raises(ValidationError):
        HashiCorpVaultKV2Storage(base_url="http://127.0.0.1:8200", timeout=float("nan"))


def test_bounded_response_overflow_raises_storage_error():
    storage = HashiCorpVaultKV2Storage(base_url="http://127.0.0.1:8200", token="synthetic-token")
    huge_data = b"x" * (1024 * 1024 + 10)
    mock_resp = io.BytesIO(huge_data)
    with patch.object(storage._opener, "open", return_value=mock_resp):
        with pytest.raises(StorageError) as exc:
            storage._request("GET", "secret/test")
        assert "exceeded maximum allowed payload size" in str(exc.value)


def test_safe_redirect_handler_downgrade_rejected():
    handler = _SafeRedirectHandler(allowed_netloc="vault.corp:8200", allowed_scheme="https")
    with pytest.raises(UnsafeRedirectError) as exc:
        handler.redirect_request(None, None, 301, "Moved", {}, "http://vault.corp:8200/secret")
    assert "scheme downgrade" in str(exc.value)


def test_safe_redirect_handler_cross_domain_rejected():
    handler = _SafeRedirectHandler(allowed_netloc="vault.corp:8200", allowed_scheme="https")
    with pytest.raises(UnsafeRedirectError) as exc:
        handler.redirect_request(None, None, 302, "Found", {}, "https://evil.attacker.com/secret")
    assert "destination evil.attacker.com does not match" in str(exc.value)


def test_cas_error_mapping_http_400_and_412():
    storage = HashiCorpVaultKV2Storage(base_url="http://127.0.0.1:8200", token="synthetic-token")

    # 1. HTTP 400 with check-and-set error string
    body_400 = io.BytesIO(b'{"errors": ["check-and-set parameter did not match current version"]}')
    http_400 = urllib.error.HTTPError(
        url="http://127.0.0.1:8200/v1/secret/data/test",
        code=400,
        msg="Bad Request",
        hdrs={},
        fp=body_400,
    )
    with patch.object(storage._opener, "open", side_effect=http_400):
        with pytest.raises(CasMismatchError):
            storage.write_secret("test", {"k": "v"}, cas=1)

    # 2. HTTP 412 Precondition Failed
    http_412 = urllib.error.HTTPError(
        url="http://127.0.0.1:8200/v1/secret/data/test",
        code=412,
        msg="Precondition Failed",
        hdrs={},
        fp=io.BytesIO(b""),
    )
    with patch.object(storage._opener, "open", side_effect=http_412):
        with pytest.raises(CasMismatchError):
            storage.write_secret("test", {"k": "v"}, cas=1)

    # 3. Generic 400 without CAS in body
    body_gen = io.BytesIO(b'{"errors": ["unrecognized key foo"]}')
    http_gen = urllib.error.HTTPError(
        url="http://127.0.0.1:8200/v1/secret/data/test",
        code=400,
        msg="Bad Request",
        hdrs={},
        fp=body_gen,
    )
    with patch.object(storage._opener, "open", side_effect=http_gen):
        with pytest.raises(StorageError) as exc_gen:
            storage.write_secret("test", {"k": "v"}, cas=1)
        assert not isinstance(exc_gen.value, CasMismatchError)
        assert exc_gen.value.code == "vault_bad_request"


def test_http_status_code_mappings():
    storage = HashiCorpVaultKV2Storage(base_url="http://127.0.0.1:8200", token="synthetic-token")

    # 401 Auth
    http_401 = urllib.error.HTTPError("", 401, "Unauthorized", {}, io.BytesIO(b""))
    with patch.object(storage._opener, "open", side_effect=http_401):
        with pytest.raises(StorageAuthenticationError):
            storage.write_secret("test", {"k": "v"})
        assert storage.token is None  # Token was invalidated

    # 403 Permission
    storage.token = "synthetic-token"
    http_403 = urllib.error.HTTPError("", 403, "Forbidden", {}, io.BytesIO(b""))
    with patch.object(storage._opener, "open", side_effect=http_403):
        with pytest.raises(StoragePermissionDeniedError):
            storage.write_secret("test", {"k": "v"})

    # 404 Not Found
    storage.token = "synthetic-token"
    http_404 = urllib.error.HTTPError("", 404, "Not Found", {}, io.BytesIO(b""))
    with patch.object(storage._opener, "open", side_effect=http_404):
        with pytest.raises(StorageNotFoundError):
            storage._request("GET", "secret/test")

    # 503 Sealed
    storage.token = "synthetic-token"
    http_503 = urllib.error.HTTPError("", 503, "Sealed", {}, io.BytesIO(b""))
    with patch.object(storage._opener, "open", side_effect=http_503):
        with pytest.raises(StorageSealedError):
            storage.write_secret("test", {"k": "v"})


def test_approle_login_success():
    storage = HashiCorpVaultKV2Storage(
        base_url="http://127.0.0.1:8200",
        role_id="my-role-id",
        secret_id="my-secret-id",
    )
    mock_cm = io.BytesIO(b'{"auth": {"client_token": "approle_token_xyz"}}')
    with patch.object(storage._opener, "open", return_value=mock_cm):
        token = storage._get_active_token()
        assert token == "approle_token_xyz"


def test_approle_login_missing_token_raises():
    storage = HashiCorpVaultKV2Storage(
        base_url="http://127.0.0.1:8200",
        role_id="my-role-id",
        secret_id="my-secret-id",
    )
    mock_cm = io.BytesIO(b'{"auth": {}}')
    with patch.object(storage._opener, "open", return_value=mock_cm):
        with pytest.raises(StorageAuthenticationError) as exc:
            storage._get_active_token()
        assert "missing client_token" in str(exc.value)


def test_read_secret_metadata_destroyed():
    storage = HashiCorpVaultKV2Storage(base_url="http://127.0.0.1:8200", token="synthetic-token")
    mock_response = {
        "data": {
            "current_version": 2,
            "created_time": "2026-11-25T00:00:00Z",
            "versions": {
                "1": {"destroyed": True},
                "2": {"destroyed": True},
            },
        }
    }
    with patch.object(storage, "_request", return_value=mock_response):
        meta = storage.read_secret_metadata("test/path")
        assert meta.exists is False
        assert meta.destroyed is True


# -----------------------------------------------------------------------------
# Vault Response Schema Validation Tests
# -----------------------------------------------------------------------------


def test_write_secret_validates_response_schema():
    storage = HashiCorpVaultKV2Storage(base_url="http://127.0.0.1:8200", token="synthetic-token")

    # Missing data object
    with patch.object(storage, "_request", return_value={"status": "ok"}):
        with pytest.raises(StorageError) as exc:
            storage.write_secret("test", {"k": "v"})
        assert exc.value.code == "malformed_vault_response"

    # Missing version
    with patch.object(storage, "_request", return_value={"data": {}}):
        with pytest.raises(StorageError) as exc:
            storage.write_secret("test", {"k": "v"})
        assert exc.value.code == "malformed_vault_response"
        assert "Invalid or missing version" in str(exc.value)

    # Non-integer version (string, bool, <= 0)
    with patch.object(storage, "_request", return_value={"data": {"version": "1"}}):
        with pytest.raises(StorageError):
            storage.write_secret("test", {"k": "v"})

    with patch.object(storage, "_request", return_value={"data": {"version": True}}):
        with pytest.raises(StorageError):
            storage.write_secret("test", {"k": "v"})

    with patch.object(storage, "_request", return_value={"data": {"version": 0}}):
        with pytest.raises(StorageError):
            storage.write_secret("test", {"k": "v"})

    # Valid response succeeds
    with patch.object(
        storage,
        "_request",
        return_value={"data": {"version": 3, "created_time": "2026-11-25T00:00:00Z"}},
    ):
        res = storage.write_secret("test", {"k": "v"})
        assert res.version == 3


def test_health_check_sealed_and_error_states():
    storage = HashiCorpVaultKV2Storage(base_url="http://127.0.0.1:8200")

    # 1. HTTP 503 Sealed
    h503 = urllib.error.HTTPError("", 503, "Sealed", {}, io.BytesIO(b'{"sealed": true}'))
    with patch.object(storage._opener, "open", side_effect=h503):
        health = storage.health_check()
        assert health.sealed is True
        assert health.reachable is True

    # 2. HTTP 429 Standby
    h429 = urllib.error.HTTPError("", 429, "Standby", {}, io.BytesIO(b'{"standby": true}'))
    with patch.object(storage._opener, "open", side_effect=h429):
        health = storage.health_check()
        assert health.standby is True
        assert health.reachable is True

    # 3. Network connection exception
    with patch.object(storage._opener, "open", side_effect=TimeoutError("Connection timeout")):
        health = storage.health_check()
        assert health.reachable is False
        assert health.error == "TimeoutError"


def test_delete_secret_default_versions():
    storage = HashiCorpVaultKV2Storage(base_url="http://127.0.0.1:8200", token="tok")
    with patch.object(storage, "_request") as mock_req:
        res = storage.delete_secret("path/to/key")
        assert res is True
        mock_req.assert_called_once_with("DELETE", "secret/data/path/to/key")


def test_delete_secret_explicit_versions():
    storage = HashiCorpVaultKV2Storage(base_url="http://127.0.0.1:8200", token="tok")
    with patch.object(storage, "_request") as mock_req:
        res = storage.delete_secret("path/to/key", versions=[1, 2])
        assert res is True
        mock_req.assert_called_once_with(
            "POST", "secret/delete/path/to/key", body={"versions": [1, 2]}
        )


def test_safe_redirect_handler_preserves_token():
    import urllib.request

    handler = _SafeRedirectHandler(allowed_netloc="vault.corp:8200", allowed_scheme="https")
    req = urllib.request.Request(
        "https://vault.corp:8200/secret", headers={"X-Vault-Token": "s.token123"}
    )
    new_req = handler.redirect_request(
        req, None, 307, "Temporary Redirect", {}, "https://vault.corp:8200/secret/new"
    )
    assert new_req is not None
    assert new_req.get_header("X-vault-token") == "s.token123"
