"""Example 3: HashiCorp Vault KV v2 Production Storage."""

from agentguardkit import CredentialBroker, HashiCorpVaultKV2Storage
from agentguardkit.exceptions import InsecureTransportError


def main() -> None:
    print("--- Demonstrating Transport Security Boundaries ---")

    # 1. Insecure remote HTTP is rejected fail-closed
    try:
        HashiCorpVaultKV2Storage(base_url="http://remote-vault.corporate.com:8200")
    except InsecureTransportError as e:
        print("Rejected Insecure Remote Transport:", e)

    # 2. Production TLS Endpoint
    vault = HashiCorpVaultKV2Storage(
        base_url="https://127.0.0.1:8200",
        mount_point="secret",
        token="s.synthetic_vault_root_token",
        timeout=5,
        verify_ssl=False,  # Set to True in production with verified CA
    )

    broker = CredentialBroker(storage=vault)
    readiness = broker.get_readiness_status()
    print("Vault Storage Probe:", readiness.readiness_label)


if __name__ == "__main__":
    main()
