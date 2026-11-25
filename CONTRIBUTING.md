# Contributing to AgentGuardKit

Thank you for contributing to AgentGuardKit! We welcome issues, documentation improvements, and pull requests that adhere to our security architecture and quality standards.

---

## Code of Conduct & Development Principles

1. **Security-First Invariants**:
   Every change must preserve core security invariants: zero plaintext secrets in logs/exceptions, deny-by-default capability policies, and strict tenant isolation.
2. **Framework Independence**:
   The core package (`agentguardkit`) must retain **zero mandatory third-party runtime dependencies**. All adapters for external frameworks (FastAPI, Django, SQLAlchemy) belong in optional contrib subpackages or example recipes.
3. **Truthful Documentation**:
   Do not claim features exist unless they are implemented and verified by automated tests.

---

## Development Setup

```bash
# Clone the repository
git clone https://github.com/techmsd/agent-guard-kit.git
cd agent-guard-kit

# Create a virtual environment
python -m venv .venv

# Activate environment (Linux/macOS)
source .venv/bin/activate
# Or on Windows (PowerShell)
.venv\Scripts\Activate.ps1

# Install development dependencies
pip install -e ".[dev]"
```

---

## Running Verification

Before submitting a pull request, run the complete verification suite:

```bash
# 1. Run tests with coverage (minimum 90% required)
pytest --cov=agentguardkit --cov-report=term-missing

# 2. Run static type checking
mypy src/agentguardkit

# 3. Run linting and formatting checks
ruff check .
ruff format --check .
```

---

## Pull Request Guidelines

- Keep pull requests focused on a single logical change or bug fix.
- Add negative security tests for any new path, policy, or storage handling logic.
- Ensure all CI workflow checks pass cleanly.
