# AGENTS.md

Diffused finds fixed and newly introduced container image vulnerabilities by diffing scanner results.
Stack: Python 3.9+, Click, Rich, Hatchling.

## Architecture
Scans two versions of an image/SBOM via a third-party scanner. Vulnerabilities in the older scan but missing from the newer are reported as fixed; vulnerabilities in the newer scan but missing from the older are reported as newly introduced.
- `diffused/diffused/`: Core lib (`differ.py`, `scanners/` [base, trivy, acs, models])
- `diffusedcli/diffusedcli/`: CLI package (`cli.py` using Click)
- `diffused/tests/` & `diffusedcli/tests/`: Pytest suites

## Commands
- **Setup**: `pip install -e ./diffused/.[dev] && pip install -e ./diffusedcli/.[dev]`
- **Run all checks**: `tox`
- **Lint/Type/Format**: `tox -e py39-black,py39-flake8,py39-isort,py39-mypy,black-format`
- **Test**: `tox -e py39-pytest,py39-pytest-cli`

## Agent Directives
- **Formatting**: PEP 8. Assume Black and isort with 100-char line length.
- **Typing**: Type hints are strictly REQUIRED on all functions and methods.
- **Testing**: Write function-based tests only (no classes). Target 100% coverage.
- **CLI Testing**: Use `click.testing.CliRunner`. Strip ANSI escape codes when testing `Rich` outputs.
- **Mocking**: NEVER execute live network requests or binaries in tests. Use fixtures from `diffused/tests/conftest.py` and `diffusedcli/tests/conftest.py` to simulate scanner outputs.
- **Data Models**: Map raw scanner JSON payloads to `scanners/models.py` immediately. Do not pass raw dictionaries.
- **Dependencies**: Uses Hatchling. If adding packages, ONLY modify `pyproject.toml`. 
- **Comments**: Inline comments must always start with a lowercase letter.
- **Commits**: Use conventional commits (e.g., `feat:`, `fix:`, `chore:`).
- **Prohibitions**: Do NOT modify `.github/workflows/` or `pyproject.toml` dependencies unless explicitly commanded.
