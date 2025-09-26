"""Shared fixtures for all library tests."""

from unittest.mock import patch

import pytest


@pytest.fixture
def rox_env():
    """Fixture to provide valid ROX environment variables."""
    with patch.dict(
        "os.environ", {"ROX_ENDPOINT": "https://localhost:8443", "ROX_API_TOKEN": "test-token"}
    ):
        yield


@pytest.fixture
def test_image():
    """Fixture to provide a consistent test image name."""
    return "test-image:latest"


@pytest.fixture
def test_sbom_path():
    """Fixture to provide a consistent test SBOM path."""
    return "/path/to/sbom.json"


@pytest.fixture
def test_output_path():
    """Fixture to provide a consistent test output path."""
    return "/path/to/output.json"


@pytest.fixture
def test_previous_sbom_path():
    """Fixture to provide a consistent test previous SBOM path."""
    return "/path/to/previous.json"


@pytest.fixture
def test_next_sbom_path():
    """Fixture to provide a consistent test next SBOM path."""
    return "/path/to/next.json"


@pytest.fixture
def test_previous_image():
    """Fixture to provide a consistent test previous image name."""
    return "previous:latest"


@pytest.fixture
def test_next_image():
    """Fixture to provide a consistent test next image name."""
    return "next:latest"


@pytest.fixture
def sample_vulnerabilities():
    """Fixture to provide sample vulnerability data for testing."""
    return [
        {
            "cveId": "CVE-2023-1234",
            "componentName": "package1",
            "componentVersion": "1.0.0",
        },
        {
            "cveId": "CVE-2023-5678",
            "componentName": "package2",
            "componentVersion": "2.0.0",
        },
        {
            "cveId": "CVE-2023-1234",  # Duplicate vulnerability
            "componentName": "package3",
            "componentVersion": "1.5.0",
        },
    ]


@pytest.fixture
def sample_acs_response(sample_vulnerabilities):
    """Fixture to provide a sample ACS response with vulnerabilities."""
    return {"result": {"vulnerabilities": sample_vulnerabilities}}


@pytest.fixture
def empty_acs_response():
    """Fixture to provide an empty ACS response."""
    return {"result": {"vulnerabilities": []}}


@pytest.fixture
def vulnerabilities_without_cve_id():
    """Fixture to provide vulnerability data with missing CVE IDs for testing filtering."""
    return [
        {
            "cveId": "CVE-2023-1234",
            "componentName": "package1",
            "componentVersion": "1.0.0",
        },
        {
            "componentName": "package2",
            "componentVersion": "2.0.0",
            # Missing cveId
        },
    ]


@pytest.fixture
def mixed_vulnerability_data():
    """Fixture to provide mixed vulnerability data (some with IDs, some without)."""
    return [
        {
            "cveId": "CVE-2023-1234",
            "componentName": "package1",
            "componentVersion": "1.0.0",
        },
        {
            "cveId": "",  # Empty CVE ID
            "componentName": "package2",
            "componentVersion": "2.0.0",
        },
        {
            # Missing cveId entirely
            "componentName": "package3",
            "componentVersion": "3.0.0",
        },
        {
            "cveId": "CVE-2023-5678",
            "componentName": "package4",
            "componentVersion": "4.0.0",
        },
    ]


@pytest.fixture
def integration_vulnerability_data():
    """Fixture to provide vulnerability data for integration testing."""
    return [
        {
            "cveId": "CVE-2023-1234",
            "componentName": "package1",
            "componentVersion": "1.0.0",
        }
    ]


@pytest.fixture
def vulnerabilities_without_cve_id_response(vulnerabilities_without_cve_id):
    """Fixture to provide ACS response with vulnerabilities missing CVE IDs."""
    return {"result": {"vulnerabilities": vulnerabilities_without_cve_id}}


@pytest.fixture
def mixed_vulnerability_response(mixed_vulnerability_data):
    """Fixture to provide ACS response with mixed vulnerability data."""
    return {"result": {"vulnerabilities": mixed_vulnerability_data}}


@pytest.fixture
def integration_acs_response(integration_vulnerability_data):
    """Fixture to provide ACS response for integration testing."""
    return {"result": {"vulnerabilities": integration_vulnerability_data}}
