"""Unit tests for TrivyScanner class."""

import json
import subprocess
from unittest.mock import MagicMock, patch

import pytest

from diffused.scanners.models import Package
from diffused.scanners.trivy import TrivyScanner


def test_init_with_image(test_image):
    """Test TrivyScanner initialization with image."""
    scanner = TrivyScanner(image=test_image)
    assert scanner.image == test_image
    assert scanner.sbom is None
    assert scanner.raw_result is None
    assert scanner.processed_result == {}
    assert scanner.error == ""


def test_init_with_sbom(test_sbom_path):
    """Test TrivyScanner initialization with SBOM."""
    scanner = TrivyScanner(sbom=test_sbom_path)
    assert scanner.sbom == test_sbom_path
    assert scanner.image is None
    assert scanner.raw_result is None
    assert scanner.processed_result == {}
    assert scanner.error == ""


def test_init_with_both(test_image, test_sbom_path):
    """Test TrivyScanner initialization with both image and SBOM."""
    scanner = TrivyScanner(image=test_image, sbom=test_sbom_path)
    assert scanner.image == test_image
    assert scanner.sbom == test_sbom_path


def test_init_with_neither_raises_error():
    """Test TrivyScanner initialization fails without image or SBOM."""
    with pytest.raises(ValueError, match="You must set sbom or image"):
        TrivyScanner()


@patch("diffused.scanners.trivy.subprocess.run")
def test_run_trivy_command_success(mock_run, test_image):
    """Test successful _run_trivy_command execution."""
    scanner = TrivyScanner(image=test_image)
    mock_result = MagicMock()
    mock_result.returncode = 0
    mock_run.return_value = mock_result

    result = scanner._run_trivy_command(["trivy", "--version"], "test operation")

    mock_run.assert_called_once_with(
        ["trivy", "--version"], capture_output=True, shell=False, text=True, timeout=120
    )
    assert result == mock_result


@patch("diffused.scanners.trivy.subprocess.run")
def test_run_trivy_command_called_process_error(mock_run, test_image):
    """Test _run_trivy_command with CalledProcessError."""
    scanner = TrivyScanner(image=test_image)
    mock_run.side_effect = subprocess.CalledProcessError(1, ["trivy"], stderr="error output")

    with pytest.raises(subprocess.CalledProcessError):
        scanner._run_trivy_command(["trivy", "--version"], "test operation")

    assert "Trivy test operation failed" in scanner.error
    assert "error output" in scanner.error


@patch("diffused.scanners.trivy.subprocess.run")
def test_run_trivy_command_timeout(mock_run, test_image):
    """Test _run_trivy_command with timeout."""
    scanner = TrivyScanner(image=test_image)
    mock_run.side_effect = subprocess.TimeoutExpired(["trivy"], 120)

    with pytest.raises(subprocess.TimeoutExpired):
        scanner._run_trivy_command(["trivy", "--version"], "test operation")

    assert "Trivy test operation timed out" in scanner.error


@patch("diffused.scanners.trivy.subprocess.run")
def test_run_trivy_command_unexpected_error(mock_run, test_image):
    """Test _run_trivy_command with unexpected error."""
    scanner = TrivyScanner(image=test_image)
    mock_run.side_effect = Exception("Unexpected error")

    with pytest.raises(Exception):
        scanner._run_trivy_command(["trivy", "--version"], "test operation")

    assert "Unexpected error during Trivy test operation" in scanner.error


@patch.object(TrivyScanner, "_run_trivy_command")
def test_retrieve_sbom_success(mock_run_command, test_image, test_output_path):
    """Test successful SBOM retrieval."""
    scanner = TrivyScanner(image=test_image)
    mock_run_command.return_value = MagicMock()

    scanner.retrieve_sbom(test_output_path)

    mock_run_command.assert_called_once_with(
        [
            "trivy",
            "image",
            "--format",
            "spdx-json",
            "--output",
            test_output_path,
            test_image,
        ],
        f"SBOM generation for {test_image}",
    )
    assert scanner.sbom == test_output_path


def test_retrieve_sbom_no_image(test_sbom_path, test_output_path):
    """Test retrieve_sbom fails without image."""
    scanner = TrivyScanner(sbom=test_sbom_path)
    with pytest.raises(ValueError, match="You must set the image to retrieve the SBOM"):
        scanner.retrieve_sbom(test_output_path)


def test_retrieve_sbom_no_output_file(test_image):
    """Test retrieve_sbom fails without output file."""
    scanner = TrivyScanner(image=test_image)
    with pytest.raises(ValueError, match="You must set the output_file with a valid path"):
        scanner.retrieve_sbom("")


@patch.object(TrivyScanner, "_run_trivy_command")
def test_retrieve_sbom_command_failure(mock_run_command, test_image, test_output_path):
    """Test retrieve_sbom handles command failure."""
    scanner = TrivyScanner(image=test_image)
    mock_run_command.side_effect = subprocess.CalledProcessError(1, ["trivy"])

    scanner.retrieve_sbom(test_output_path)

    # Should not raise exception, error should be stored
    assert scanner.sbom is None  # Should not be set on failure


@patch.object(TrivyScanner, "_run_trivy_command")
def test_scan_sbom_success(mock_run_command, test_sbom_path):
    """Test successful SBOM scan."""
    scanner = TrivyScanner(sbom=test_sbom_path)
    mock_result = MagicMock()
    mock_result.stdout = '{"Results": []}'
    mock_run_command.return_value = mock_result

    scanner.scan_sbom()

    mock_run_command.assert_called_once_with(
        ["trivy", "sbom", "--format", "json", test_sbom_path],
        f"SBOM scan for {test_sbom_path}",
    )
    assert scanner.raw_result == {"Results": []}


def test_scan_sbom_no_sbom(test_image):
    """Test scan_sbom fails without SBOM."""
    scanner = TrivyScanner(image=test_image)
    with pytest.raises(
        ValueError, match="You must set the SBOM path or retrieve from a container image"
    ):
        scanner.scan_sbom()


@patch.object(TrivyScanner, "_run_trivy_command")
def test_scan_sbom_json_decode_error(mock_run_command, test_sbom_path):
    """Test scan_sbom handles JSON decode error."""
    scanner = TrivyScanner(sbom=test_sbom_path)
    mock_result = MagicMock()
    mock_result.stdout = "invalid json"
    mock_run_command.return_value = mock_result

    scanner.scan_sbom()

    assert "Error parsing Trivy output" in scanner.error
    assert scanner.raw_result is None


@patch.object(TrivyScanner, "_run_trivy_command")
def test_scan_sbom_command_failure(mock_run_command, test_sbom_path):
    """Test scan_sbom handles command failure."""
    scanner = TrivyScanner(sbom=test_sbom_path)
    mock_run_command.side_effect = subprocess.CalledProcessError(1, ["trivy"])

    scanner.scan_sbom()

    # Should not raise exception, error should be stored
    assert scanner.raw_result is None


def test_process_result_no_raw_result(test_image):
    """Test process_result fails without raw result."""
    scanner = TrivyScanner(image=test_image)
    with pytest.raises(ValueError, match="Run a scan before processing its output"):
        scanner.process_result()


def test_process_result_no_results(test_image):
    """Test process_result with no Results in raw_result."""
    scanner = TrivyScanner(image=test_image)
    scanner.raw_result = {}

    scanner.process_result()

    assert scanner.processed_result == {}


def test_process_result_empty_results(test_image):
    """Test process_result with empty Results array."""
    scanner = TrivyScanner(image=test_image)
    scanner.raw_result = {"Results": []}

    scanner.process_result()

    assert scanner.processed_result == {}


def test_process_result_no_vulnerabilities(test_image):
    """Test process_result with no vulnerabilities."""
    scanner = TrivyScanner(image=test_image)
    scanner.raw_result = {"Results": [{"Target": "test", "Class": "os-pkgs"}]}

    scanner.process_result()

    assert scanner.processed_result == {}


def test_process_result_with_vulnerabilities(test_image):
    """Test process_result with vulnerabilities."""
    scanner = TrivyScanner(image=test_image)
    scanner.raw_result = {
        "Results": [
            {
                "Target": "test",
                "Class": "os-pkgs",
                "Vulnerabilities": [
                    {
                        "VulnerabilityID": "CVE-2023-1234",
                        "PkgName": "package1",
                        "InstalledVersion": "1.0.0",
                    },
                    {
                        "VulnerabilityID": "CVE-2023-5678",
                        "PkgName": "package2",
                        "InstalledVersion": "2.0.0",
                    },
                    {
                        "VulnerabilityID": "CVE-2023-1234",  # Duplicate vulnerability
                        "PkgName": "package3",
                        "InstalledVersion": "1.5.0",
                    },
                ],
            }
        ]
    }

    # Process_result will handle creating the sets automatically
    scanner.process_result()

    assert len(scanner.processed_result) == 2
    assert "CVE-2023-1234" in scanner.processed_result
    assert "CVE-2023-5678" in scanner.processed_result

    # Check that CVE-2023-1234 has both packages
    cve_1234_packages = scanner.processed_result["CVE-2023-1234"]
    assert len(cve_1234_packages) == 2
    assert Package(name="package1", version="1.0.0") in cve_1234_packages
    assert Package(name="package3", version="1.5.0") in cve_1234_packages

    # Check that CVE-2023-5678 has one package
    cve_5678_packages = scanner.processed_result["CVE-2023-5678"]
    assert len(cve_5678_packages) == 1
    assert Package(name="package2", version="2.0.0") in cve_5678_packages


def test_process_result_skip_vulnerabilities_without_id(test_image):
    """Test process_result skips vulnerabilities without ID."""
    scanner = TrivyScanner(image=test_image)
    scanner.raw_result = {
        "Results": [
            {
                "Target": "test",
                "Class": "os-pkgs",
                "Vulnerabilities": [
                    {
                        "VulnerabilityID": "CVE-2023-1234",
                        "PkgName": "package1",
                        "InstalledVersion": "1.0.0",
                    },
                    {
                        "PkgName": "package2",
                        "InstalledVersion": "2.0.0",
                        # Missing VulnerabilityID
                    },
                ],
            }
        ]
    }

    scanner.process_result()

    assert len(scanner.processed_result) == 1
    assert "CVE-2023-1234" in scanner.processed_result


def test_process_result_multiple_result_sections(test_image):
    """Test process_result with multiple result sections."""
    scanner = TrivyScanner(image=test_image)
    scanner.raw_result = {
        "Results": [
            {
                "Target": "test1",
                "Class": "os-pkgs",
                "Vulnerabilities": [
                    {
                        "VulnerabilityID": "CVE-2023-1234",
                        "PkgName": "package1",
                        "InstalledVersion": "1.0.0",
                    }
                ],
            },
            {
                "Target": "test2",
                "Class": "lang-pkgs",
                "Vulnerabilities": [
                    {
                        "VulnerabilityID": "CVE-2023-5678",
                        "PkgName": "package2",
                        "InstalledVersion": "2.0.0",
                    }
                ],
            },
        ]
    }

    scanner.process_result()

    assert len(scanner.processed_result) == 2
    assert "CVE-2023-1234" in scanner.processed_result
    assert "CVE-2023-5678" in scanner.processed_result


def test_process_result_clears_previous_results(test_image):
    """Test process_result clears previous results."""
    scanner = TrivyScanner(image=test_image)
    scanner.processed_result.clear()
    scanner.processed_result["CVE-2023-OLD"] = {Package(name="old", version="1.0.0")}
    scanner.raw_result = {"Results": []}

    scanner.process_result()

    assert scanner.processed_result == {}


@patch("diffused.scanners.trivy.subprocess.run")
def test_get_version_success(mock_run):
    """Test successful get_version."""
    mock_result = MagicMock()
    mock_result.stdout = "Version: 0.45.0\n"
    mock_result.returncode = 0
    mock_run.return_value = mock_result

    version = TrivyScanner.get_version()

    mock_run.assert_called_once_with(
        ["trivy", "--version"], capture_output=True, shell=False, text=True, timeout=10
    )
    assert version == "0.45.0"


@patch("diffused.scanners.trivy.subprocess.run")
def test_get_version_called_process_error(mock_run):
    """Test get_version with CalledProcessError."""
    mock_run.side_effect = subprocess.CalledProcessError(1, ["trivy"])

    version = TrivyScanner.get_version()

    assert version == "unknown"


@patch("diffused.scanners.trivy.subprocess.run")
def test_get_version_timeout(mock_run):
    """Test get_version with timeout."""
    mock_run.side_effect = subprocess.TimeoutExpired(["trivy"], 10)

    version = TrivyScanner.get_version()

    assert version == "unknown"


@patch("diffused.scanners.trivy.subprocess.run")
def test_get_version_unexpected_error(mock_run):
    """Test get_version with unexpected error."""
    mock_run.side_effect = Exception("Unexpected error")

    version = TrivyScanner.get_version()

    assert version == "unknown"


@patch("diffused.scanners.trivy.subprocess.run")
def test_get_version_malformed_output(mock_run):
    """Test get_version with malformed output."""
    mock_result = MagicMock()
    mock_result.stdout = "Invalid output format\n"
    mock_result.returncode = 0
    mock_run.return_value = mock_result

    with pytest.raises(IndexError):
        TrivyScanner.get_version()


@patch("diffused.scanners.trivy.subprocess.run")
def test_get_version_complex_output(mock_run):
    """Test get_version with complex output format."""
    mock_result = MagicMock()
    mock_result.stdout = "Version: 0.45.0\nOther info\nMore info\n"
    mock_result.returncode = 0
    mock_run.return_value = mock_result

    version = TrivyScanner.get_version()

    assert version == "0.45.0"


def test_integration_workflow(test_image, test_sbom_path):
    """Test complete workflow integration."""
    scanner = TrivyScanner(image=test_image)

    # Mock the entire workflow
    with patch.object(scanner, "_run_trivy_command") as mock_run:
        # Test retrieve_sbom
        scanner.retrieve_sbom(test_sbom_path)
        assert scanner.sbom == test_sbom_path

        # Test scan_sbom
        mock_result = MagicMock()
        mock_result.stdout = json.dumps(
            {
                "Results": [
                    {
                        "Target": "test",
                        "Class": "os-pkgs",
                        "Vulnerabilities": [
                            {
                                "VulnerabilityID": "CVE-2023-1234",
                                "PkgName": "package1",
                                "InstalledVersion": "1.0.0",
                            }
                        ],
                    }
                ]
            }
        )
        mock_run.return_value = mock_result

        scanner.scan_sbom()
        assert scanner.raw_result is not None

        # Test process_result
        scanner.process_result()
        assert len(scanner.processed_result) == 1
        assert "CVE-2023-1234" in scanner.processed_result
