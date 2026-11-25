"""HashiCorp Vault Key-Value Version 2 REST API storage adapter.

Uses pure Python standard library (urllib.request, ssl, json) with zero third-party dependencies.
Enforces TLS certificate validation, rejects insecure remote HTTP, prevents redirect credential
leakage, bounds response payload sizes, verifies response schemas, and handles CAS concurrency.
"""

from __future__ import annotations

import json
import logging
import math
import re
import ssl
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlparse

from ..exceptions import (
    CasMismatchError,
    InsecureTransportError,
    StorageAuthenticationError,
    StorageConnectionError,
    StorageError,
    StorageNotFoundError,
    StoragePermissionDeniedError,
    StorageSealedError,
    UnsafeRedirectError,
    ValidationError,
)
from ..interfaces import SecretMetadataResult, SecretWriteResult, StorageHealthStatus
from .base import SecretStorageBackend

logger = logging.getLogger(__name__)

# Permitted unencrypted loopback hosts for local development/testing only
LOOPBACK_HOSTS = frozenset({"127.0.0.1", "localhost", "::1"})

# Maximum permitted HTTP response payload size (1 MB) to prevent memory exhaustion
MAX_RESPONSE_BYTES = 1024 * 1024

# Valid mount point identifier pattern
MOUNT_POINT_REGEX = re.compile(r"^[a-zA-Z0-9_\-]+$")


class _SafeRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Custom redirect handler that prevents credential leakage across domains or scheme downgrade."""

    def __init__(self, allowed_netloc: str, allowed_scheme: str):
        super().__init__()
        self._allowed_netloc = allowed_netloc.lower()
        self._allowed_scheme = allowed_scheme.lower()

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[no-untyped-def]
        parsed = urlparse(newurl)
        # 1. Disallow scheme downgrade (HTTPS -> HTTP)
        if self._allowed_scheme == "https" and parsed.scheme.lower() != "https":
            raise UnsafeRedirectError(
                f"Prohibited redirect: scheme downgrade from https to {parsed.scheme}"
            )
        # 2. Disallow cross-host redirects that could leak tokens
        if parsed.netloc.lower() != self._allowed_netloc:
            raise UnsafeRedirectError(
                f"Prohibited redirect: destination {parsed.netloc} does not match base {self._allowed_netloc}"
            )
        # 3. Create redirect request without leaking sensitive headers across unexpected hops
        new_req = super().redirect_request(req, fp, code, msg, headers, newurl)
        if new_req is not None:
            # Preserve Vault token only if same origin
            token = req.headers.get("X-vault-token") or req.headers.get("X-Vault-Token")
            if token:
                new_req.add_unredirected_header("X-Vault-Token", token)
        return new_req


class HashiCorpVaultKV2Storage(SecretStorageBackend):
    """Production storage backend for HashiCorp Vault KV v2 secret engine."""

    def __init__(
        self,
        base_url: str = "http://127.0.0.1:8200",
        mount_point: str = "secret",
        token: str | None = None,
        role_id: str | None = None,
        secret_id: str | None = None,
        timeout: float = 5.0,
        verify_ssl: bool = True,
        ca_cert_file: str | None = None,
    ):
        self.base_url = base_url.rstrip("/")
        self.mount_point = mount_point.strip("/")
        self.token = token
        self.role_id = role_id
        self.secret_id = secret_id
        self.timeout = float(timeout)
        self.verify_ssl = verify_ssl
        self.ca_cert_file = ca_cert_file

        self._validate_configuration()
        self._ssl_context = self._build_ssl_context()
        self._opener = self._build_url_opener()

    def _validate_configuration(self) -> None:
        """Validate URL scheme, host, mount point, and timeout constraints fail-closed."""
        if (
            not isinstance(self.timeout, (int, float))
            or isinstance(self.timeout, bool)
            or self.timeout <= 0
            or not math.isfinite(self.timeout)
            or self.timeout > 300
        ):
            raise ValidationError("Timeout must be a finite positive number <= 300 seconds")

        if not MOUNT_POINT_REGEX.match(self.mount_point):
            raise ValidationError(
                f"Invalid mount point format '{self.mount_point}': must contain only alphanumeric characters, underscores, and hyphens."
            )

        parsed = urlparse(self.base_url)
        scheme = (parsed.scheme or "").lower()
        host = (parsed.hostname or "").lower()

        # Reject embedded userinfo (credentials in URL)
        if parsed.username or parsed.password or "@" in parsed.netloc:
            raise InsecureTransportError(
                "Vault endpoint URL must not contain embedded user credentials/userinfo"
            )

        # Reject query parameters
        if parsed.query:
            raise InsecureTransportError("Vault endpoint URL must not contain query parameters")

        # Reject URL fragments
        if parsed.fragment:
            raise InsecureTransportError("Vault endpoint URL must not contain fragments")

        # Port validation if specified
        if parsed.port is not None and not (1 <= parsed.port <= 65535):
            raise ValidationError(f"Invalid port number: {parsed.port}")

        if scheme == "http":
            if host not in LOOPBACK_HOSTS:
                raise InsecureTransportError(
                    f"Insecure transport: remote Vault endpoint '{self.base_url}' must use HTTPS. "
                    "Unencrypted HTTP is restricted strictly to loopback (127.0.0.1, localhost, ::1)."
                )
        elif scheme != "https":
            raise InsecureTransportError(
                f"Invalid Vault endpoint scheme '{scheme}'. Must be 'https' (or 'http' for loopback only)."
            )

        # Prohibit verify_ssl=False for remote endpoints
        if not self.verify_ssl and host not in LOOPBACK_HOSTS:
            raise InsecureTransportError(
                "Disabling TLS certificate verification (verify_ssl=False) is strictly prohibited for remote Vault endpoints. "
                "It is permitted only for unencrypted local loopback endpoints during testing."
            )

    def _build_ssl_context(self) -> ssl.SSLContext:
        """Configure TLS verification context."""
        parsed = urlparse(self.base_url)
        if parsed.scheme.lower() != "https":
            return ssl.create_default_context()

        if not self.verify_ssl:
            logger.warning(
                "TLS certificate verification is DISABLED for local test endpoint: %s",
                self.base_url,
            )
            return ssl._create_unverified_context()

        if self.ca_cert_file:
            ctx = ssl.create_default_context(cafile=self.ca_cert_file)
        else:
            ctx = ssl.create_default_context()
        return ctx

    def _build_url_opener(self) -> urllib.request.OpenerDirector:
        """Build urllib opener with safe redirect handler and HTTPS context."""
        parsed = urlparse(self.base_url)
        redirect_handler = _SafeRedirectHandler(
            allowed_netloc=parsed.netloc,
            allowed_scheme=parsed.scheme,
        )
        https_handler = urllib.request.HTTPSHandler(context=self._ssl_context)
        return urllib.request.build_opener(redirect_handler, https_handler)

    def _get_active_token(self) -> str:
        """Return the active Vault token or authenticate via AppRole."""
        if self.token:
            return self.token
        if self.role_id and self.secret_id:
            return self._login_approle()
        raise StorageAuthenticationError("No Vault token or AppRole credentials configured")

    def _login_approle(self) -> str:
        """Authenticate via AppRole endpoint."""
        url = f"{self.base_url}/v1/auth/approle/login"
        payload = json.dumps({"role_id": self.role_id, "secret_id": self.secret_id}).encode("utf-8")
        req = urllib.request.Request(
            url,
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )

        try:
            with self._opener.open(req, timeout=self.timeout) as resp:
                raw_bytes = resp.read(MAX_RESPONSE_BYTES + 1)
                if len(raw_bytes) > MAX_RESPONSE_BYTES:
                    raise StorageError(
                        "AppRole login response exceeded maximum permitted size",
                        code="response_payload_too_large",
                    )
                data = json.loads(raw_bytes.decode("utf-8"))
                token = data.get("auth", {}).get("client_token")
                if not token:
                    raise StorageAuthenticationError("AppRole login response missing client_token")
                token_str = str(token)
                self.token = token_str
                return token_str
        except urllib.error.HTTPError as e:
            if e.code in (400, 401, 403):
                raise StorageAuthenticationError(
                    f"Vault AppRole authentication rejected (HTTP {e.code})"
                ) from e
            raise StorageConnectionError(
                f"Vault AppRole authentication failed (HTTP {e.code})"
            ) from e
        except (urllib.error.URLError, TimeoutError) as e:
            raise StorageConnectionError(
                f"Vault server unreachable at {self.base_url}", code="storage_unreachable"
            ) from e

    def _request(
        self,
        method: str,
        path: str,
        body: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Execute authenticated request against Vault REST API with bounded reads."""
        token = self._get_active_token()
        url = f"{self.base_url}/v1/{path.lstrip('/')}"
        data_bytes = json.dumps(body).encode("utf-8") if body is not None else None

        req = urllib.request.Request(
            url,
            data=data_bytes,
            headers={
                "Content-Type": "application/json",
                "X-Vault-Token": token,
            },
            method=method,
        )

        try:
            with self._opener.open(req, timeout=self.timeout) as resp:
                raw = resp.read(MAX_RESPONSE_BYTES + 1)
                if len(raw) > MAX_RESPONSE_BYTES:
                    raise StorageError(
                        f"Vault response exceeded maximum allowed payload size of {MAX_RESPONSE_BYTES} bytes",
                        code="response_payload_too_large",
                    )
                if not raw:
                    return {}
                raw_parsed = json.loads(raw.decode("utf-8"))
                if isinstance(raw_parsed, dict):
                    return raw_parsed
                return {}
        except urllib.error.HTTPError as e:
            if e.code == 400:
                err_msg = ""
                try:
                    raw_err = e.read(MAX_RESPONSE_BYTES + 1)
                    if raw_err:
                        err_json = json.loads(raw_err.decode("utf-8"))
                        err_msg = " ".join(str(i) for i in err_json.get("errors", [])).lower()
                except Exception:
                    err_msg = ""

                if "check-and-set" in err_msg or "cas" in err_msg:
                    raise CasMismatchError(
                        "Check-and-set (CAS) violation: secret version mismatch or key exists"
                    ) from e
                raise StorageError(
                    "Vault request rejected: invalid payload or parameters",
                    code="vault_bad_request",
                ) from e
            if e.code == 403:
                raise StoragePermissionDeniedError("Access denied by Vault policy for path") from e
            if e.code == 404:
                raise StorageNotFoundError("Secret not found at specified path") from e
            if e.code == 412:
                raise CasMismatchError(
                    "Check-and-set (CAS) violation: version mismatch or precondition failed"
                ) from e
            if e.code == 503:
                raise StorageSealedError("Vault cluster is sealed or in standby") from e
            if e.code == 401:
                self.token = None  # Invalidate cached token
                raise StorageAuthenticationError("Vault token rejected or expired") from e
            raise StorageError(
                f"Vault operation failed with HTTP {e.code}", code="vault_http_error"
            ) from e
        except (urllib.error.URLError, TimeoutError) as e:
            raise StorageConnectionError(
                "Vault server unreachable or timed out", code="storage_unreachable"
            ) from e

    def write_secret(
        self,
        path: str,
        data: dict[str, Any],
        cas: int | None = None,
    ) -> SecretWriteResult:
        clean_path = path.strip("/")
        req_path = f"{self.mount_point}/data/{clean_path}"
        body: dict[str, Any] = {"data": data}
        if cas is not None:
            body["options"] = {"cas": cas}

        res = self._request("POST", req_path, body=body)
        if not isinstance(res, dict):
            raise StorageError(
                "Malformed Vault response: expected JSON object", code="malformed_vault_response"
            )

        meta = res.get("data")
        if not isinstance(meta, dict):
            raise StorageError(
                "Malformed Vault KV v2 response: missing 'data' object",
                code="malformed_vault_response",
            )

        version = meta.get("version")
        if (
            version is None
            or isinstance(version, bool)
            or not isinstance(version, int)
            or version < 1
        ):
            raise StorageError(
                "Invalid or missing version in Vault KV v2 write response",
                code="malformed_vault_response",
            )

        created_time = meta.get("created_time")
        if not isinstance(created_time, str) or not created_time.strip():
            created_time = datetime.now(timezone.utc).isoformat()

        return SecretWriteResult(version=version, created_time=created_time, destroyed=False)

    def read_secret_metadata(self, path: str) -> SecretMetadataResult:
        clean_path = path.strip("/")
        req_path = f"{self.mount_point}/metadata/{clean_path}"

        try:
            res = self._request("GET", req_path)
        except StorageNotFoundError:
            return SecretMetadataResult(exists=False)

        data = res.get("data", {})
        current_version = data.get("current_version")
        created_time = data.get("created_time")
        updated_time = data.get("updated_time")

        versions_dict = data.get("versions") or {}
        is_destroyed = False
        if current_version:
            v_info = versions_dict.get(str(current_version)) or {}
            if v_info.get("destroyed") is True or bool(v_info.get("deletion_time")):
                is_destroyed = True
        elif not versions_dict:
            is_destroyed = True

        return SecretMetadataResult(
            exists=bool(current_version is not None and current_version > 0 and not is_destroyed),
            current_version=current_version,
            created_time=created_time,
            updated_time=updated_time,
            destroyed=is_destroyed,
            custom_metadata=data.get("custom_metadata") or {},
        )

    def delete_secret(self, path: str, versions: list[int] | None = None) -> bool:
        """Soft-delete secret data in Vault KV v2."""
        clean_path = path.strip("/")
        if versions:
            req_path = f"{self.mount_point}/delete/{clean_path}"
            self._request("POST", req_path, body={"versions": versions})
        else:
            req_path = f"{self.mount_point}/data/{clean_path}"
            self._request("DELETE", req_path)
        return True

    def health_check(self) -> StorageHealthStatus:
        url = f"{self.base_url}/v1/sys/health"
        req = urllib.request.Request(url, method="GET")

        try:
            with self._opener.open(req, timeout=self.timeout) as resp:
                raw_bytes = resp.read(MAX_RESPONSE_BYTES + 1)
                data = json.loads(raw_bytes.decode("utf-8"))
                return StorageHealthStatus(
                    initialized=data.get("initialized", False),
                    sealed=data.get("sealed", True),
                    standby=data.get("standby", False),
                    reachable=True,
                    server_time=data.get("server_time_utc"),
                )
        except urllib.error.HTTPError as e:
            try:
                body = json.loads(e.read(MAX_RESPONSE_BYTES + 1).decode("utf-8"))
            except Exception:
                body = {}
            return StorageHealthStatus(
                initialized=body.get("initialized", False),
                sealed=body.get("sealed", e.code == 503),
                standby=body.get("standby", e.code == 429),
                reachable=True,
                error=f"Vault HTTP status {e.code}",
            )
        except Exception as e:
            return StorageHealthStatus(
                initialized=False,
                sealed=False,
                standby=False,
                reachable=False,
                error=e.__class__.__name__,
            )
