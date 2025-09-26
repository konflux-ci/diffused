"""Shared fixtures for CLI tests."""

import pytest
from click.testing import CliRunner


@pytest.fixture
def runner():
    """Create a Click test runner."""
    return CliRunner()


@pytest.fixture
def test_previous_sbom_path():
    """Fixture to provide a consistent test previous SBOM path."""
    return "/path/to/prev.json"


@pytest.fixture
def test_next_sbom_path():
    """Fixture to provide a consistent test next SBOM path."""
    return "/path/to/next.json"


@pytest.fixture
def test_previous_image():
    """Fixture to provide a consistent test previous image name."""
    return "prev:latest"


@pytest.fixture
def test_next_image():
    """Fixture to provide a consistent test next image name."""
    return "next:latest"


@pytest.fixture
def sample_vulnerabilities_list():
    """Sample vulnerability list for testing."""
    return ["CVE-2024-1234", "CVE-2024-5678", "CVE-2024-9999"]


@pytest.fixture
def sample_vulnerabilities_all_info():
    """Sample vulnerability data with all info for testing."""
    return {
        "CVE-2024-1234": [
            {"package1": {"previous_version": "1.0.0", "new_version": "1.1.0", "removed": False}}
        ],
        "CVE-2024-5678": [
            {"package2": {"previous_version": "2.0.0", "new_version": "", "removed": True}}
        ],
    }
