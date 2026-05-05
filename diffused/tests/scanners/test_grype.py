"""Unit tests for GrypeScanner class."""

import json
import subprocess
from unittest.mock import MagicMock, patch

import pytest

from diffused.scanners.grype import GrypeScanner
from diffused.scanners.models import Package


def test_init_with_image(test_image):
    """Test GrypeScanner initialization with image."""
    scanner = GrypeScanner(image=test_image)
    assert scanner.image == test_image
    assert scanner.sbom is None
    assert scanner.raw_result is None
    assert scanner.processed_result == {}
    assert scanner.error == ""


def test_init_with_sbom(test_sbom_path):
    """Test GrypeScanner initialization with SBOM."""
    scanner = GrypeScanner(sbom=test_sbom_path)
    assert scanner.sbom == test_sbom_path
    assert scanner.image is None
    assert scanner.raw_result is None
    assert scanner.processed_result == {}
    assert scanner.error == ""


def test_init_with_both(test_image, test_sbom_path):
    """Test GrypeScanner initialization with both image and SBOM."""
    scanner = GrypeScanner(image=test_image, sbom=test_sbom_path)
    assert scanner.image == test_image
    assert scanner.sbom == test_sbom_path


def test_init_with_neither_raises_error():
    """Test GrypeScanner initialization fails without image or SBOM."""
    with pytest.raises(ValueError, match="You must set sbom or image"):
        GrypeScanner()


@patch("diffused.scanners.grype.subprocess.run")
def test_run_grype_command_success(mock_run, test_image):
    """Test successful _run_grype_command execution."""
    scanner = GrypeScanner(image=test_image)
    mock_result = MagicMock()
    mock_result.returncode = 0
    mock_run.return_value = mock_result

    result = scanner._run_grype_command(["grype", "version"], "test operation")

    mock_run.assert_called_once_with(
        ["grype", "version"], capture_output=True, shell=False, text=True, timeout=120
    )
    assert result == mock_result


@patch("diffused.scanners.grype.subprocess.run")
def test_run_grype_command_called_process_error(mock_run, test_image):
    """Test _run_grype_command with CalledProcessError."""
    scanner = GrypeScanner(image=test_image)
    mock_run.side_effect = subprocess.CalledProcessError(1, ["grype"], stderr="error output")

    with pytest.raises(subprocess.CalledProcessError):
        scanner._run_grype_command(["grype", "version"], "test operation")

    assert "Grype test operation failed" in scanner.error
    assert "error output" in scanner.error


@patch("diffused.scanners.grype.subprocess.run")
def test_run_grype_command_timeout(mock_run, test_image):
    """Test _run_grype_command with timeout."""
    scanner = GrypeScanner(image=test_image)
    mock_run.side_effect = subprocess.TimeoutExpired(["grype"], 120)

    with pytest.raises(subprocess.TimeoutExpired):
        scanner._run_grype_command(["grype", "version"], "test operation")

    assert "Grype test operation timed out" in scanner.error


@patch("diffused.scanners.grype.subprocess.run")
def test_run_grype_command_unexpected_error(mock_run, test_image):
    """Test _run_grype_command with unexpected error."""
    scanner = GrypeScanner(image=test_image)
    mock_run.side_effect = Exception("Unexpected error")

    with pytest.raises(Exception):
        scanner._run_grype_command(["grype", "version"], "test operation")

    assert "Unexpected error during Grype test operation" in scanner.error


@patch.object(GrypeScanner, "_run_grype_command")
def test_scan_sbom_success(mock_run_command, test_sbom_path):
    """Test successful SBOM scan."""
    scanner = GrypeScanner(sbom=test_sbom_path)
    mock_result = MagicMock()
    mock_result.stdout = '{"matches": []}'
    mock_run_command.return_value = mock_result

    scanner.scan_sbom()

    mock_run_command.assert_called_once_with(
        ["grype", f"sbom:{test_sbom_path}", "-o", "json"],
        f"SBOM scan for {test_sbom_path}",
    )
    assert scanner.raw_result == {"matches": []}


def test_scan_sbom_no_sbom(test_image):
    """Test scan_sbom fails without SBOM."""
    scanner = GrypeScanner(image=test_image)
    with pytest.raises(
        ValueError, match="You must set the SBOM path or retrieve from a container image"
    ):
        scanner.scan_sbom()


@patch.object(GrypeScanner, "_run_grype_command")
def test_scan_sbom_json_decode_error(mock_run_command, test_sbom_path):
    """Test scan_sbom handles JSON decode error."""
    scanner = GrypeScanner(sbom=test_sbom_path)
    mock_result = MagicMock()
    mock_result.stdout = "invalid json"
    mock_run_command.return_value = mock_result

    scanner.scan_sbom()

    assert "Error parsing Grype output" in scanner.error
    assert scanner.raw_result is None


@patch.object(GrypeScanner, "_run_grype_command")
def test_scan_sbom_command_failure(mock_run_command, test_sbom_path):
    """Test scan_sbom handles command failure."""
    scanner = GrypeScanner(sbom=test_sbom_path)
    mock_run_command.side_effect = subprocess.CalledProcessError(1, ["grype"])

    scanner.scan_sbom()

    assert scanner.raw_result is None


@patch.object(GrypeScanner, "_run_grype_command")
def test_scan_image_success(mock_run_command, test_image):
    """Test successful image scan."""
    scanner = GrypeScanner(image=test_image)
    mock_result = MagicMock()
    mock_result.stdout = json.dumps(
        {
            "matches": [
                {
                    "vulnerability": {"id": "CVE-2023-1234"},
                    "artifact": {"name": "package1", "version": "1.0.0"},
                }
            ]
        }
    )
    mock_run_command.return_value = mock_result

    scanner.scan_image()

    mock_run_command.assert_called_once_with(
        ["grype", test_image, "-o", "json"],
        f"Image scan for {test_image}",
    )
    assert scanner.raw_result is not None
    assert "matches" in scanner.raw_result
    assert len(scanner.raw_result["matches"]) == 1
    assert scanner.error == ""


def test_scan_image_no_image(test_sbom_path):
    """Test scan_image fails without image."""
    scanner = GrypeScanner(sbom=test_sbom_path)
    with pytest.raises(ValueError, match="You must set the image to scan"):
        scanner.scan_image()


@patch.object(GrypeScanner, "_run_grype_command")
def test_scan_image_json_decode_error(mock_run_command, test_image):
    """Test scan_image handles JSON decode error."""
    scanner = GrypeScanner(image=test_image)
    mock_result = MagicMock()
    mock_result.stdout = "invalid json"
    mock_run_command.return_value = mock_result

    scanner.scan_image()

    assert "Error parsing Grype output" in scanner.error
    assert scanner.raw_result is None


@patch.object(GrypeScanner, "_run_grype_command")
def test_scan_image_command_failure(mock_run_command, test_image):
    """Test scan_image handles command failure."""
    scanner = GrypeScanner(image=test_image)
    mock_run_command.side_effect = subprocess.CalledProcessError(1, ["grype"])

    scanner.scan_image()

    assert scanner.raw_result is None


def test_process_result_no_raw_result(test_image):
    """Test process_result fails without raw result."""
    scanner = GrypeScanner(image=test_image)
    with pytest.raises(ValueError, match="Run a scan before processing its output"):
        scanner.process_result()


def test_process_result_no_matches(test_image):
    """Test process_result with no matches in raw_result."""
    scanner = GrypeScanner(image=test_image)
    scanner.raw_result = {}

    scanner.process_result()

    assert scanner.processed_result == {}


def test_process_result_empty_matches(test_image):
    """Test process_result with empty matches array."""
    scanner = GrypeScanner(image=test_image)
    scanner.raw_result = {"matches": []}

    scanner.process_result()

    assert scanner.processed_result == {}


def test_process_result_with_vulnerabilities(test_image):
    """Test process_result with vulnerabilities."""
    scanner = GrypeScanner(image=test_image)
    scanner.raw_result = {
        "matches": [
            {
                "vulnerability": {"id": "CVE-2023-1234"},
                "artifact": {"name": "package1", "version": "1.0.0"},
            },
            {
                "vulnerability": {"id": "CVE-2023-5678"},
                "artifact": {"name": "package2", "version": "2.0.0"},
            },
            {
                "vulnerability": {"id": "CVE-2023-1234"},
                "artifact": {"name": "package3", "version": "1.5.0"},
            },
        ]
    }

    scanner.process_result()

    assert len(scanner.processed_result) == 2
    assert "CVE-2023-1234" in scanner.processed_result
    assert "CVE-2023-5678" in scanner.processed_result

    cve_1234_packages = scanner.processed_result["CVE-2023-1234"]
    assert len(cve_1234_packages) == 2
    assert Package(name="package1", version="1.0.0") in cve_1234_packages
    assert Package(name="package3", version="1.5.0") in cve_1234_packages

    cve_5678_packages = scanner.processed_result["CVE-2023-5678"]
    assert len(cve_5678_packages) == 1
    assert Package(name="package2", version="2.0.0") in cve_5678_packages


def test_process_result_all_vulnerabilities_skipped(test_image):
    """Test process_result when all matches lack vulnerability IDs."""
    scanner = GrypeScanner(image=test_image)
    scanner.raw_result = {
        "matches": [
            {
                "vulnerability": {},
                "artifact": {"name": "package1", "version": "1.0.0"},
            },
            {
                "vulnerability": {},
                "artifact": {"name": "package2", "version": "2.0.0"},
            },
        ]
    }

    scanner.process_result()

    assert scanner.processed_result == {}


def test_process_result_skip_vulnerabilities_without_id(test_image):
    """Test process_result skips vulnerabilities without ID."""
    scanner = GrypeScanner(image=test_image)
    scanner.raw_result = {
        "matches": [
            {
                "vulnerability": {"id": "CVE-2023-1234"},
                "artifact": {"name": "package1", "version": "1.0.0"},
            },
            {
                "vulnerability": {},
                "artifact": {"name": "package2", "version": "2.0.0"},
            },
        ]
    }

    scanner.process_result()

    assert len(scanner.processed_result) == 1
    assert "CVE-2023-1234" in scanner.processed_result


def test_process_result_clears_previous_results(test_image):
    """Test process_result clears previous results."""
    scanner = GrypeScanner(image=test_image)
    scanner.processed_result["CVE-2023-OLD"] = {Package(name="old", version="1.0.0")}
    scanner.raw_result = {"matches": []}

    scanner.process_result()

    assert scanner.processed_result == {}


@patch("diffused.scanners.grype.subprocess.run")
def test_get_version_success(mock_run):
    """Test successful get_version."""
    mock_result = MagicMock()
    mock_result.stdout = (
        "Application:         grype\n"
        "Version:             0.112.0\n"
        "BuildDate:           2026-05-01T18:57:12Z\n"
    )
    mock_result.returncode = 0
    mock_run.return_value = mock_result

    version = GrypeScanner.get_version()

    mock_run.assert_called_once_with(
        ["grype", "version"], capture_output=True, shell=False, text=True, timeout=10
    )
    assert version == "0.112.0"


@patch("diffused.scanners.grype.subprocess.run")
def test_get_version_called_process_error(mock_run):
    """Test get_version with CalledProcessError."""
    mock_run.side_effect = subprocess.CalledProcessError(1, ["grype"])

    version = GrypeScanner.get_version()

    assert version == "unknown"


@patch("diffused.scanners.grype.subprocess.run")
def test_get_version_timeout(mock_run):
    """Test get_version with timeout."""
    mock_run.side_effect = subprocess.TimeoutExpired(["grype"], 10)

    version = GrypeScanner.get_version()

    assert version == "unknown"


@patch("diffused.scanners.grype.subprocess.run")
def test_get_version_unexpected_error(mock_run):
    """Test get_version with unexpected error."""
    mock_run.side_effect = Exception("Unexpected error")

    version = GrypeScanner.get_version()

    assert version == "unknown"


@patch("diffused.scanners.grype.subprocess.run")
def test_get_version_malformed_output(mock_run):
    """Test get_version with malformed output."""
    mock_result = MagicMock()
    mock_result.stdout = "Invalid output format\n"
    mock_result.returncode = 0
    mock_run.return_value = mock_result

    version = GrypeScanner.get_version()

    assert version == "unknown"


def test_integration_workflow(test_image):
    """Test complete workflow integration."""
    scanner = GrypeScanner(image=test_image)

    with patch.object(scanner, "_run_grype_command") as mock_run:
        mock_result = MagicMock()
        mock_result.stdout = json.dumps(
            {
                "matches": [
                    {
                        "vulnerability": {"id": "CVE-2023-1234"},
                        "artifact": {"name": "package1", "version": "1.0.0"},
                    }
                ]
            }
        )
        mock_run.return_value = mock_result

        scanner.scan_image()
        assert scanner.raw_result is not None

        scanner.process_result()
        assert len(scanner.processed_result) == 1
        assert "CVE-2023-1234" in scanner.processed_result
