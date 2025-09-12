"""Unit tests for ACSScanner class."""

import json
import subprocess
from unittest.mock import MagicMock, patch

import pytest

from diffused.scanners.acs import ACSScanner
from diffused.scanners.models import Package

# Test constants
COMMAND_TIMEOUT = 120
VERSION_TIMEOUT = 10
SUCCESS_RETURN_CODE = 0
ERROR_RETURN_CODE = 1
UNKNOWN_VERSION = "unknown"

# Command constants
ROXCTL_VERSION_COMMAND = ["roxctl", "version"]
ROXCTL_BASE_ARGS = ["roxctl", "--no-color"]
ROXCTL_SBOM_ARGS = ROXCTL_BASE_ARGS + ["image", "sbom"]
ROXCTL_SCAN_ARGS = ROXCTL_BASE_ARGS + ["image", "scan", "--output", "json"]

# Error message patterns
MISSING_ENV_VARS_ERROR = "ROX_ENDPOINT and ROX_API_TOKEN must be set in the environment variables"
MISSING_IMAGE_ERROR = "You must set the image to retrieve the SBOM"
MISSING_OUTPUT_FILE_ERROR = "You must set the output_file with a valid path"
MISSING_IMAGE_SCAN_ERROR = "You must set the image to scan"
NO_RAW_RESULT_ERROR = "Run a scan before processing its output"


def create_mock_result(stdout="", returncode=SUCCESS_RETURN_CODE):
    """Helper to create a mock subprocess result."""
    mock_result = MagicMock()
    mock_result.stdout = stdout
    mock_result.returncode = returncode
    return mock_result


def create_scanner_with_image(test_image):
    """Helper to create ACSScanner with image."""
    return ACSScanner(image=test_image)


def create_scanner_with_sbom(test_sbom_path):
    """Helper to create ACSScanner with SBOM."""
    return ACSScanner(sbom=test_sbom_path)


def assert_default_scanner_state(scanner, expected_image=None, expected_sbom=None):
    """Helper to assert scanner is in default state."""
    assert scanner.image == expected_image
    assert scanner.sbom == expected_sbom
    assert scanner.raw_result is None
    assert scanner.processed_result == {}
    assert scanner.error == ""


def assert_cve_packages_match(processed_result, cve_id, expected_packages):
    """Helper to assert CVE packages match expected list."""
    assert cve_id in processed_result
    cve_packages = processed_result[cve_id]
    assert len(cve_packages) == len(expected_packages)
    for package in expected_packages:
        assert package in cve_packages


def assert_vulnerability_processing_results(processed_result, expected_cve_count, expected_cves):
    """Helper to assert vulnerability processing results."""
    assert len(processed_result) == expected_cve_count
    for cve_id in expected_cves:
        assert cve_id in processed_result


def test_initialization_succeeds_with_valid_image(rox_env, test_image):
    """Test ACSScanner initializes successfully when provided with a valid image."""
    scanner = create_scanner_with_image(test_image)
    assert_default_scanner_state(scanner, expected_image=test_image)


def test_initialization_succeeds_with_valid_sbom_path(rox_env, test_sbom_path):
    """Test ACSScanner initializes successfully when provided with a valid SBOM path."""
    scanner = create_scanner_with_sbom(test_sbom_path)
    assert_default_scanner_state(scanner, expected_sbom=test_sbom_path)


def test_initialization_succeeds_with_both_image_and_sbom(rox_env, test_image, test_sbom_path):
    """Test ACSScanner initializes successfully when provided with both image and SBOM path."""
    scanner = ACSScanner(image=test_image, sbom=test_sbom_path)
    assert scanner.image == test_image
    assert scanner.sbom == test_sbom_path


def test_initialization_fails_when_neither_image_nor_sbom_provided():
    """Test ACSScanner initialization raises ValueError when neither image nor SBOM is provided."""
    with pytest.raises(ValueError, match="You must set sbom or image"):
        ACSScanner()


@pytest.mark.parametrize(
    "env_vars",
    [
        {},  # Missing both variables
        {"ROX_API_TOKEN": "test-token"},  # Missing ROX_ENDPOINT
        {"ROX_ENDPOINT": "https://localhost:8443"},  # Missing ROX_API_TOKEN
    ],
)
def test_initialization_fails_with_missing_environment_variables(env_vars, test_image):
    """Test ACSScanner initialization fails when ROX environment variables are missing."""
    with patch.dict("os.environ", env_vars, clear=True):
        with pytest.raises(ValueError, match=MISSING_ENV_VARS_ERROR):
            ACSScanner(image=test_image)


@patch("diffused.scanners.acs.subprocess.run")
def test_acs_command_execution_succeeds_with_valid_subprocess_result(mock_run, rox_env, test_image):
    """Test _run_acs_command executes successfully when subprocess returns valid result."""
    scanner = create_scanner_with_image(test_image)
    mock_result = create_mock_result(returncode=SUCCESS_RETURN_CODE)
    mock_run.return_value = mock_result

    result = scanner._run_acs_command(ROXCTL_VERSION_COMMAND, "test operation")

    mock_run.assert_called_once_with(
        ROXCTL_VERSION_COMMAND, capture_output=True, shell=False, text=True, timeout=COMMAND_TIMEOUT
    )
    assert result == mock_result


@patch("diffused.scanners.acs.subprocess.run")
def test_acs_command_execution_handles_subprocess_called_process_error(
    mock_run, rox_env, test_image
):
    """Test _run_acs_command properly handles and re-raises CalledProcessError from subprocess."""
    scanner = create_scanner_with_image(test_image)
    mock_run.side_effect = subprocess.CalledProcessError(
        ERROR_RETURN_CODE, ROXCTL_VERSION_COMMAND, stderr="error output"
    )

    with pytest.raises(subprocess.CalledProcessError):
        scanner._run_acs_command(ROXCTL_VERSION_COMMAND, "test operation")

    assert "ACS test operation failed" in scanner.error
    assert "error output" in scanner.error


@patch("diffused.scanners.acs.subprocess.run")
def test_acs_command_execution_handles_subprocess_timeout_error(mock_run, rox_env, test_image):
    """Test _run_acs_command properly handles and re-raises TimeoutExpired from subprocess."""
    scanner = create_scanner_with_image(test_image)
    mock_run.side_effect = subprocess.TimeoutExpired(ROXCTL_VERSION_COMMAND, COMMAND_TIMEOUT)

    with pytest.raises(subprocess.TimeoutExpired):
        scanner._run_acs_command(ROXCTL_VERSION_COMMAND, "test operation")

    assert "ACS test operation timed out" in scanner.error


@patch("diffused.scanners.acs.subprocess.run")
def test_acs_command_execution_handles_unexpected_subprocess_error(mock_run, rox_env, test_image):
    """Test _run_acs_command properly handles and re-raises unexpected exceptions from subprocess."""
    scanner = create_scanner_with_image(test_image)
    mock_run.side_effect = Exception("Unexpected error")

    with pytest.raises(Exception):
        scanner._run_acs_command(ROXCTL_VERSION_COMMAND, "test operation")

    assert "Unexpected error during ACS test operation" in scanner.error


@patch.object(ACSScanner, "_run_acs_command")
def test_sbom_retrieval_succeeds_with_valid_image_and_output_path(
    mock_run_command, rox_env, test_image, test_output_path
):
    """Test SBOM retrieval completes successfully when provided with valid image and output path."""
    scanner = create_scanner_with_image(test_image)
    mock_result = create_mock_result(stdout='{"packages": []}')
    mock_run_command.return_value = mock_result

    with patch("builtins.open", MagicMock()) as mock_open:
        scanner.retrieve_sbom(test_output_path)

    mock_run_command.assert_called_once_with(
        ROXCTL_SBOM_ARGS + ["--image", test_image],
        f"SBOM generation for {test_image}",
    )
    assert scanner.sbom == test_output_path


def test_sbom_retrieval_fails_when_scanner_has_no_image(rox_env, test_sbom_path, test_output_path):
    """Test SBOM retrieval raises ValueError when scanner was initialized without an image."""
    scanner = create_scanner_with_sbom(test_sbom_path)
    with pytest.raises(ValueError, match=MISSING_IMAGE_ERROR):
        scanner.retrieve_sbom(test_output_path)


def test_sbom_retrieval_fails_when_no_output_path_provided(rox_env, test_image):
    """Test SBOM retrieval raises ValueError when no output file path is provided."""
    scanner = create_scanner_with_image(test_image)
    with pytest.raises(ValueError, match=MISSING_OUTPUT_FILE_ERROR):
        scanner.retrieve_sbom("")


@patch.object(ACSScanner, "_run_acs_command")
def test_sbom_retrieval_handles_command_execution_failure_gracefully(
    mock_run_command, rox_env, test_image, test_output_path
):
    """Test SBOM retrieval handles subprocess command failure without raising exception."""
    scanner = create_scanner_with_image(test_image)
    mock_run_command.side_effect = subprocess.CalledProcessError(1, ["roxctl"])

    scanner.retrieve_sbom(test_output_path)

    # Should not raise exception, error should be stored
    assert scanner.sbom is None  # Should not be set on failure


@patch.object(ACSScanner, "_run_acs_command")
def test_sbom_retrieval_handles_invalid_json_output_gracefully(
    mock_run_command, rox_env, test_image, test_output_path
):
    """Test SBOM retrieval handles invalid JSON output from command without raising exception."""
    scanner = create_scanner_with_image(test_image)
    mock_result = create_mock_result(stdout="invalid json output")
    mock_run_command.return_value = mock_result

    scanner.retrieve_sbom(test_output_path)

    # Should not raise exception, error should be stored
    assert scanner.sbom is None  # Should not be set on failure
    assert f"Error parsing SBOM output for {test_image}" in scanner.error


@patch.object(ACSScanner, "_run_acs_command")
def test_image_scanning_succeeds_with_valid_image_and_empty_response(
    mock_run_command, rox_env, test_image, empty_acs_response
):
    """Test image scanning completes successfully when provided with valid image and returns empty response."""
    scanner = create_scanner_with_image(test_image)
    mock_result = create_mock_result(stdout=json.dumps(empty_acs_response))
    mock_run_command.return_value = mock_result

    scanner.scan_sbom()

    mock_run_command.assert_called_once_with(
        ROXCTL_SCAN_ARGS + ["--image", test_image],
        f"Image scan for {test_image}",
    )
    assert scanner.raw_result == empty_acs_response


def test_image_scanning_fails_when_scanner_has_no_image(rox_env, test_sbom_path):
    """Test image scanning raises ValueError when scanner was initialized without an image."""
    scanner = create_scanner_with_sbom(test_sbom_path)
    with pytest.raises(ValueError, match=MISSING_IMAGE_SCAN_ERROR):
        scanner.scan_sbom()


@patch.object(ACSScanner, "_run_acs_command")
def test_image_scanning_handles_invalid_json_output_gracefully(
    mock_run_command, rox_env, test_image
):
    """Test image scanning handles invalid JSON output from command without raising exception."""
    scanner = create_scanner_with_image(test_image)
    mock_result = create_mock_result(stdout="invalid json")
    mock_run_command.return_value = mock_result

    scanner.scan_sbom()

    assert "Error parsing ACS output" in scanner.error
    assert scanner.raw_result is None


@patch.object(ACSScanner, "_run_acs_command")
def test_image_scanning_handles_command_execution_failure_gracefully(
    mock_run_command, rox_env, test_image
):
    """Test image scanning handles subprocess command failure without raising exception."""
    scanner = create_scanner_with_image(test_image)
    mock_run_command.side_effect = subprocess.CalledProcessError(1, ["roxctl"])

    scanner.scan_sbom()

    # Should not raise exception, error should be stored
    assert scanner.raw_result is None


def test_result_processing_fails_when_no_scan_data_available(rox_env, test_image):
    """Test result processing raises ValueError when no raw scan data is available."""
    scanner = create_scanner_with_image(test_image)
    with pytest.raises(ValueError, match=NO_RAW_RESULT_ERROR):
        scanner.process_result()


def test_result_processing_succeeds_with_empty_vulnerability_data(rox_env, test_image):
    """Test result processing completes successfully when raw result contains no vulnerability data."""
    scanner = create_scanner_with_image(test_image)
    scanner.raw_result = {"result": {}}

    scanner.process_result()

    assert scanner.processed_result == {}


def test_result_processing_succeeds_with_empty_vulnerability_array(
    rox_env, test_image, empty_acs_response
):
    """Test result processing completes successfully when vulnerability array is empty."""
    scanner = create_scanner_with_image(test_image)
    scanner.raw_result = empty_acs_response

    scanner.process_result()

    assert scanner.processed_result == {}


def test_result_processing_groups_vulnerabilities_by_cve_id_correctly(
    rox_env, test_image, sample_acs_response
):
    """Test result processing correctly groups vulnerabilities by CVE ID and handles duplicates."""
    scanner = create_scanner_with_image(test_image)
    scanner.raw_result = sample_acs_response

    scanner.process_result()

    assert_vulnerability_processing_results(
        scanner.processed_result,
        expected_cve_count=2,
        expected_cves=["CVE-2023-1234", "CVE-2023-5678"],
    )

    # Check that CVE-2023-1234 has both packages
    assert_cve_packages_match(
        scanner.processed_result,
        "CVE-2023-1234",
        [Package(name="package1", version="1.0.0"), Package(name="package3", version="1.5.0")],
    )

    # Check that CVE-2023-5678 has one package
    assert_cve_packages_match(
        scanner.processed_result, "CVE-2023-5678", [Package(name="package2", version="2.0.0")]
    )


def test_result_processing_skips_vulnerabilities_without_cve_id(
    rox_env, test_image, vulnerabilities_without_cve_id_response
):
    """Test result processing ignores vulnerabilities that are missing or have empty CVE IDs."""
    scanner = create_scanner_with_image(test_image)
    scanner.raw_result = vulnerabilities_without_cve_id_response

    scanner.process_result()

    assert_vulnerability_processing_results(
        scanner.processed_result, expected_cve_count=1, expected_cves=["CVE-2023-1234"]
    )


def test_result_processing_clears_previous_processed_data(rox_env, test_image, empty_acs_response):
    """Test result processing clears any previously processed vulnerability data before processing new results."""
    scanner = create_scanner_with_image(test_image)
    scanner.processed_result.clear()
    scanner.processed_result["CVE-2023-OLD"] = {Package(name="old", version="1.0.0")}
    scanner.raw_result = empty_acs_response

    scanner.process_result()

    assert scanner.processed_result == {}


@patch("diffused.scanners.acs.subprocess.run")
def test_version_retrieval_succeeds_with_valid_roxctl_output(mock_run, rox_env):
    """Test version retrieval returns correct version when roxctl command executes successfully."""
    mock_result = create_mock_result(
        stdout="roxctl version 4.0.0\n", returncode=SUCCESS_RETURN_CODE
    )
    mock_run.return_value = mock_result

    version = ACSScanner.get_version()

    mock_run.assert_called_once_with(
        ROXCTL_VERSION_COMMAND, capture_output=True, shell=False, text=True, timeout=VERSION_TIMEOUT
    )
    assert version == "roxctl version 4.0.0"


@patch("diffused.scanners.acs.subprocess.run")
def test_version_retrieval_returns_unknown_on_subprocess_error(mock_run, rox_env):
    """Test version retrieval returns 'unknown' when subprocess raises CalledProcessError."""
    mock_run.side_effect = subprocess.CalledProcessError(ERROR_RETURN_CODE, ROXCTL_VERSION_COMMAND)

    version = ACSScanner.get_version()

    assert version == UNKNOWN_VERSION


@patch("diffused.scanners.acs.subprocess.run")
def test_version_retrieval_returns_unknown_on_subprocess_timeout(mock_run, rox_env):
    """Test version retrieval returns 'unknown' when subprocess times out."""
    mock_run.side_effect = subprocess.TimeoutExpired(ROXCTL_VERSION_COMMAND, VERSION_TIMEOUT)

    version = ACSScanner.get_version()

    assert version == UNKNOWN_VERSION


@patch("diffused.scanners.acs.subprocess.run")
def test_version_retrieval_returns_unknown_on_unexpected_error(mock_run, rox_env):
    """Test version retrieval returns 'unknown' when subprocess raises unexpected exception."""
    mock_run.side_effect = Exception("Unexpected error")

    version = ACSScanner.get_version()

    assert version == UNKNOWN_VERSION


def test_complete_workflow_executes_all_operations_successfully(
    rox_env, test_image, test_sbom_path, integration_acs_response
):
    """Test complete workflow of SBOM retrieval, image scanning, and result processing executes successfully."""
    scanner = create_scanner_with_image(test_image)

    # Mock the entire workflow
    with patch.object(scanner, "_run_acs_command") as mock_run:
        # Test retrieve_sbom
        mock_result = create_mock_result(stdout='{"packages": []}')
        mock_run.return_value = mock_result

        with patch("builtins.open", MagicMock()):
            scanner.retrieve_sbom(test_sbom_path)
        assert scanner.sbom == test_sbom_path

        # Test scan_sbom
        mock_result = create_mock_result(stdout=json.dumps(integration_acs_response))
        mock_run.return_value = mock_result

        scanner.scan_sbom()
        assert scanner.raw_result is not None

        # Test process_result
        scanner.process_result()
        assert_vulnerability_processing_results(
            scanner.processed_result, expected_cve_count=1, expected_cves=["CVE-2023-1234"]
        )


def test_result_processing_handles_missing_vulnerabilities_key_gracefully(rox_env, test_image):
    """Test result processing handles missing 'vulnerabilities' key in raw result without errors."""
    scanner = create_scanner_with_image(test_image)
    scanner.raw_result = {"result": {}}  # Missing vulnerabilities key

    scanner.process_result()

    assert scanner.processed_result == {}


def test_result_processing_handles_missing_result_key_gracefully(rox_env, test_image):
    """Test result processing handles missing 'result' key in raw result without errors."""
    scanner = create_scanner_with_image(test_image)
    scanner.raw_result = {}  # Missing result key

    scanner.process_result()

    assert scanner.processed_result == {}


def test_result_processing_filters_mixed_vulnerability_data_correctly(
    rox_env, test_image, mixed_vulnerability_response
):
    """Test result processing correctly filters vulnerabilities with valid CVE IDs from mixed data set."""
    scanner = create_scanner_with_image(test_image)
    scanner.raw_result = mixed_vulnerability_response

    scanner.process_result()

    # Should only process vulnerabilities with valid CVE IDs
    assert_vulnerability_processing_results(
        scanner.processed_result,
        expected_cve_count=2,
        expected_cves=["CVE-2023-1234", "CVE-2023-5678"],
    )

    # Check package contents
    assert_cve_packages_match(
        scanner.processed_result, "CVE-2023-1234", [Package(name="package1", version="1.0.0")]
    )

    assert_cve_packages_match(
        scanner.processed_result, "CVE-2023-5678", [Package(name="package4", version="4.0.0")]
    )
