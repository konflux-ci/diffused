"""Unit tests for VulnerabilityDiffer class."""

import json
from collections import defaultdict
from unittest.mock import MagicMock, mock_open, patch

import pytest

from diffused.differ import VulnerabilityDiffer
from diffused.scanners.models import Package


def test_init_with_sbom_paths(test_previous_sbom_path, test_next_sbom_path):
    """Test VulnerabilityDiffer initialization with SBOM paths."""
    differ = VulnerabilityDiffer(
        previous_sbom=test_previous_sbom_path, next_sbom=test_next_sbom_path
    )

    assert differ.previous_release.sbom == test_previous_sbom_path
    assert differ.next_release.sbom == test_next_sbom_path
    assert differ.previous_release.image is None
    assert differ.next_release.image is None
    assert differ._vulnerabilities_diff == []
    assert differ._vulnerabilities_diff_all_info == {}
    assert differ.error == ""


def test_init_with_images(test_previous_image, test_next_image):
    """Test VulnerabilityDiffer initialization with container images."""
    differ = VulnerabilityDiffer(previous_image=test_previous_image, next_image=test_next_image)

    assert differ.previous_release.image == test_previous_image
    assert differ.next_release.image == test_next_image
    assert differ.previous_release.sbom is None
    assert differ.next_release.sbom is None


def test_init_with_mixed_parameters(test_previous_sbom_path, test_next_image):
    """Test VulnerabilityDiffer initialization with mixed parameters."""
    differ = VulnerabilityDiffer(previous_sbom=test_previous_sbom_path, next_image=test_next_image)

    assert differ.previous_release.sbom == test_previous_sbom_path
    assert differ.next_release.image == test_next_image
    assert differ.previous_release.image is None
    assert differ.next_release.sbom is None


@patch("diffused.differ.tempfile.TemporaryDirectory")
@patch("diffused.differ.os.path.join")
def test_retrieve_sboms_success(mock_join, mock_temp_dir):
    """Test successful SBOM retrieval."""
    # setup mocks
    mock_temp_dir.return_value = MagicMock()
    mock_temp_dir.return_value.name = "/tmp/diffused-test"
    mock_join.side_effect = [
        "/tmp/diffused-test/previous_image_latest.json",
        "/tmp/diffused-test/next_image_latest.json",
    ]

    differ = VulnerabilityDiffer(
        previous_image="previous/image:latest", next_image="next/image:latest"
    )

    # mock the retrieve_sbom methods
    differ.previous_release.retrieve_sbom = MagicMock()
    differ.next_release.retrieve_sbom = MagicMock()

    differ.retrieve_sboms()

    # verify calls
    differ.previous_release.retrieve_sbom.assert_called_once_with(
        "/tmp/diffused-test/previous_image_latest.json"
    )
    differ.next_release.retrieve_sbom.assert_called_once_with(
        "/tmp/diffused-test/next_image_latest.json"
    )


def test_retrieve_sboms_no_images(test_previous_sbom_path, test_next_sbom_path):
    """Test retrieve_sboms when no images are set."""
    differ = VulnerabilityDiffer(
        previous_sbom=test_previous_sbom_path, next_sbom=test_next_sbom_path
    )

    # mock the retrieve_sbom methods
    differ.previous_release.retrieve_sbom = MagicMock()
    differ.next_release.retrieve_sbom = MagicMock()

    differ.retrieve_sboms()

    # should not call retrieve_sbom when images are None
    differ.previous_release.retrieve_sbom.assert_not_called()
    differ.next_release.retrieve_sbom.assert_not_called()


@patch("diffused.differ.tempfile.TemporaryDirectory")
def test_retrieve_sboms_partial_sboms(mock_temp_dir, test_previous_image, test_next_image):
    """Test retrieve_sboms when one SBOM already exists."""
    mock_temp_dir.return_value = MagicMock()
    mock_temp_dir.return_value.name = "/tmp/diffused-test"

    differ = VulnerabilityDiffer(previous_image=test_previous_image, next_image=test_next_image)

    # set one SBOM as already existing
    differ.previous_release.sbom = "/existing/previous.json"

    # mock the retrieve_sbom methods
    differ.previous_release.retrieve_sbom = MagicMock()
    differ.next_release.retrieve_sbom = MagicMock()

    with patch("diffused.differ.os.path.join") as mock_join:
        mock_join.return_value = "/tmp/diffused-test/next_latest.json"
        differ.retrieve_sboms()

    # should only call retrieve_sbom for next release
    differ.previous_release.retrieve_sbom.assert_not_called()
    differ.next_release.retrieve_sbom.assert_called_once()


def test_scan_sboms_with_missing_sboms(test_previous_image, test_next_image):
    """Test scan_sboms when SBOMs are missing."""
    differ = VulnerabilityDiffer(previous_image=test_previous_image, next_image=test_next_image)

    # mock dependencies
    differ.retrieve_sboms = MagicMock()
    differ.previous_release.scan_sbom = MagicMock()
    differ.next_release.scan_sbom = MagicMock()

    differ.scan_sboms()

    # should call retrieve_sboms first
    differ.retrieve_sboms.assert_called_once()
    differ.previous_release.scan_sbom.assert_called_once()
    differ.next_release.scan_sbom.assert_called_once()


def test_scan_sboms_with_existing_results(test_previous_sbom_path, test_next_sbom_path):
    """Test scan_sboms when raw results already exist."""
    differ = VulnerabilityDiffer(
        previous_sbom=test_previous_sbom_path, next_sbom=test_next_sbom_path
    )

    # set raw results as already existing
    differ.previous_release.raw_result = {"Results": []}
    differ.next_release.raw_result = {"Results": []}

    # mock scan methods
    differ.previous_release.scan_sbom = MagicMock()
    differ.next_release.scan_sbom = MagicMock()

    differ.scan_sboms()

    # should not call scan_sbom when raw results exist
    differ.previous_release.scan_sbom.assert_not_called()
    differ.next_release.scan_sbom.assert_not_called()


def test_process_results_calls_scan_sboms(test_previous_sbom_path, test_next_sbom_path):
    """Test process_results calls scan_sboms when needed."""
    differ = VulnerabilityDiffer(
        previous_sbom=test_previous_sbom_path, next_sbom=test_next_sbom_path
    )

    # mock dependencies
    differ.scan_sboms = MagicMock()
    differ.previous_release.process_result = MagicMock()
    differ.next_release.process_result = MagicMock()

    differ.process_results()

    differ.scan_sboms.assert_called_once()
    differ.previous_release.process_result.assert_called_once()
    differ.next_release.process_result.assert_called_once()


def test_process_results_with_existing_processed_results(
    test_previous_sbom_path, test_next_sbom_path
):
    """Test process_results when processed results already exist."""
    differ = VulnerabilityDiffer(
        previous_sbom=test_previous_sbom_path, next_sbom=test_next_sbom_path
    )

    # set processed results as already existing
    differ.previous_release.processed_result = defaultdict(set)
    differ.previous_release.processed_result["CVE-2023-1234"] = set()
    differ.next_release.processed_result = defaultdict(set)
    differ.next_release.processed_result["CVE-2023-5678"] = set()
    differ.previous_release.raw_result = {"Results": []}
    differ.next_release.raw_result = {"Results": []}

    # mock process methods
    differ.previous_release.process_result = MagicMock()
    differ.next_release.process_result = MagicMock()

    differ.process_results()

    # should not call process_result when processed results exist
    differ.previous_release.process_result.assert_not_called()
    differ.next_release.process_result.assert_not_called()


def test_diff_vulnerabilities(test_previous_sbom_path, test_next_sbom_path):
    """Test diff_vulnerabilities method."""
    differ = VulnerabilityDiffer(
        previous_sbom=test_previous_sbom_path, next_sbom=test_next_sbom_path
    )

    # mock processed results
    differ.previous_release.processed_result = defaultdict(set)
    differ.previous_release.processed_result["CVE-2023-1234"] = {
        Package(name="pkg1", version="1.0")
    }
    differ.previous_release.processed_result["CVE-2023-5678"] = {
        Package(name="pkg2", version="2.0")
    }
    differ.previous_release.processed_result["CVE-2023-9999"] = {
        Package(name="pkg3", version="3.0")
    }

    differ.next_release.processed_result = defaultdict(set)
    differ.next_release.processed_result["CVE-2023-5678"] = {
        Package(name="pkg2", version="2.1")
    }  # still present
    differ.next_release.processed_result["CVE-2023-9999"] = {
        Package(name="pkg3", version="3.0")
    }  # still present

    # mock process_results
    differ.process_results = MagicMock()

    differ.diff_vulnerabilities()

    # should find CVE-2023-1234 as fixed (present in previous but not in next)
    assert "CVE-2023-1234" in differ._vulnerabilities_diff
    assert "CVE-2023-5678" not in differ._vulnerabilities_diff
    assert "CVE-2023-9999" not in differ._vulnerabilities_diff
    assert len(differ._vulnerabilities_diff) == 1


def test_load_sbom(test_sbom_path):
    """Test load_sbom static method."""
    test_sbom = {
        "packages": [
            {"name": "package1", "versionInfo": "1.0.0"},
            {"name": "package2", "versionInfo": "2.0.0"},
        ]
    }

    with patch("builtins.open", mock_open(read_data=json.dumps(test_sbom))):
        result = VulnerabilityDiffer.load_sbom(test_sbom_path)

    assert result == test_sbom


def test_generate_additional_info_no_vulnerabilities(test_previous_sbom_path, test_next_sbom_path):
    """Test generate_additional_info with no vulnerabilities."""
    differ = VulnerabilityDiffer(
        previous_sbom=test_previous_sbom_path, next_sbom=test_next_sbom_path
    )

    differ._vulnerabilities_diff = []
    differ.diff_vulnerabilities = MagicMock()

    differ.generate_additional_info()

    assert differ._vulnerabilities_diff_all_info == {}


def test_generate_additional_info_no_next_sbom(test_previous_sbom_path, test_next_image):
    """Test generate_additional_info when next SBOM is missing."""
    differ = VulnerabilityDiffer(
        previous_sbom=test_previous_sbom_path, next_image=test_next_image  # no next_sbom set
    )

    differ._vulnerabilities_diff = ["CVE-2023-1234"]
    differ.diff_vulnerabilities = MagicMock()

    differ.generate_additional_info()

    # should return early when no next SBOM
    assert differ._vulnerabilities_diff_all_info == {}


def test_generate_additional_info_with_vulnerabilities(
    test_previous_sbom_path, test_next_sbom_path
):
    """Test generate_additional_info with actual vulnerabilities."""
    differ = VulnerabilityDiffer(
        previous_sbom=test_previous_sbom_path, next_sbom=test_next_sbom_path
    )

    # setup test data
    differ._vulnerabilities_diff = ["CVE-2023-1234", "CVE-2023-5678"]
    differ.previous_release.processed_result = defaultdict(set)
    differ.previous_release.processed_result["CVE-2023-1234"] = {
        Package(name="package1", version="1.0.0"),
        Package(name="package2", version="2.0.0"),
    }
    differ.previous_release.processed_result["CVE-2023-5678"] = {
        Package(name="package3", version="3.0.0")
    }

    # mock SBOM data
    test_sbom = {
        "packages": [
            {"name": "package1", "versionInfo": "1.1.0"},  # updated
            {"name": "package2", "versionInfo": "2.0.0"},  # same version
            # package3 is missing (removed)
            {"name": "package4", "versionInfo": "4.0.0"},  # unrelated package
        ]
    }

    with patch.object(differ, "load_sbom", return_value=test_sbom):
        differ.generate_additional_info()

    # verify results
    assert len(differ._vulnerabilities_diff_all_info) == 2

    # check CVE-2023-1234
    cve_1234_info = differ._vulnerabilities_diff_all_info["CVE-2023-1234"]
    assert len(cve_1234_info) == 2

    # check package1 info
    package1_info = next(info for info in cve_1234_info if "package1" in info)
    assert package1_info["package1"]["previous_version"] == "1.0.0"
    assert package1_info["package1"]["new_version"] == "1.1.0"
    assert package1_info["package1"]["removed"] is False

    # check package2 info
    package2_info = next(info for info in cve_1234_info if "package2" in info)
    assert package2_info["package2"]["previous_version"] == "2.0.0"
    assert package2_info["package2"]["new_version"] == "2.0.0"
    assert package2_info["package2"]["removed"] is False

    # check CVE-2023-5678
    cve_5678_info = differ._vulnerabilities_diff_all_info["CVE-2023-5678"]
    assert len(cve_5678_info) == 1

    # check package3 info (removed)
    package3_info = cve_5678_info[0]
    assert package3_info["package3"]["previous_version"] == "3.0.0"
    assert package3_info["package3"]["new_version"] == ""
    assert package3_info["package3"]["removed"] is True


def test_vulnerabilities_diff_property(test_previous_sbom_path, test_next_sbom_path):
    """Test vulnerabilities_diff property."""
    differ = VulnerabilityDiffer(
        previous_sbom=test_previous_sbom_path, next_sbom=test_next_sbom_path
    )

    # mock diff_vulnerabilities method
    differ.diff_vulnerabilities = MagicMock()
    differ._vulnerabilities_diff = ["CVE-2023-1234"]

    result = differ.vulnerabilities_diff

    # should not call diff_vulnerabilities if already populated
    differ.diff_vulnerabilities.assert_not_called()
    assert result == ["CVE-2023-1234"]


def test_vulnerabilities_diff_property_calls_diff(test_previous_sbom_path, test_next_sbom_path):
    """Test vulnerabilities_diff property calls diff when empty."""
    differ = VulnerabilityDiffer(
        previous_sbom=test_previous_sbom_path, next_sbom=test_next_sbom_path
    )

    # mock diff_vulnerabilities method
    differ.diff_vulnerabilities = MagicMock()
    differ._vulnerabilities_diff = []

    # mock the method to set some data
    def mock_diff():
        differ._vulnerabilities_diff = ["CVE-2023-1234"]

    differ.diff_vulnerabilities.side_effect = mock_diff

    result = differ.vulnerabilities_diff

    # should call diff_vulnerabilities when empty
    differ.diff_vulnerabilities.assert_called_once()
    assert result == ["CVE-2023-1234"]


def test_vulnerabilities_diff_all_info_property(test_previous_sbom_path, test_next_sbom_path):
    """Test vulnerabilities_diff_all_info property."""
    differ = VulnerabilityDiffer(
        previous_sbom=test_previous_sbom_path, next_sbom=test_next_sbom_path
    )

    # mock generate_additional_info method
    differ.generate_additional_info = MagicMock()
    differ._vulnerabilities_diff_all_info = {"CVE-2023-1234": []}

    result = differ.vulnerabilities_diff_all_info

    # should not call generate_additional_info if already populated
    differ.generate_additional_info.assert_not_called()
    assert result == {"CVE-2023-1234": []}


def test_vulnerabilities_diff_all_info_property_calls_generate(
    test_previous_sbom_path, test_next_sbom_path
):
    """Test vulnerabilities_diff_all_info property calls generate when empty."""
    differ = VulnerabilityDiffer(
        previous_sbom=test_previous_sbom_path, next_sbom=test_next_sbom_path
    )

    # mock generate_additional_info method
    differ.generate_additional_info = MagicMock()
    differ._vulnerabilities_diff_all_info = {}

    # mock the method to set some data
    def mock_generate():
        differ._vulnerabilities_diff_all_info = {"CVE-2023-1234": []}

    differ.generate_additional_info.side_effect = mock_generate

    result = differ.vulnerabilities_diff_all_info

    # should call generate_additional_info when empty
    differ.generate_additional_info.assert_called_once()
    assert result == {"CVE-2023-1234": []}


def test_integration_workflow(test_previous_sbom_path, test_next_sbom_path):
    """Test complete workflow integration."""
    differ = VulnerabilityDiffer(
        previous_sbom=test_previous_sbom_path, next_sbom=test_next_sbom_path
    )

    # mock processed results directly
    differ.previous_release.processed_result = defaultdict(set)
    differ.previous_release.processed_result["CVE-2023-1234"] = {
        Package(name="package1", version="1.0.0")
    }
    differ.next_release.processed_result = defaultdict(set)

    # mock the SBOM data
    test_sbom = {"packages": [{"name": "package1", "versionInfo": "1.1.0"}]}

    # mock only the methods that would cause file I/O
    with (
        patch.object(differ, "load_sbom", return_value=test_sbom),
        patch.object(differ, "process_results"),
        patch.object(differ, "diff_vulnerabilities", wraps=differ.diff_vulnerabilities),
    ):

        # test the workflow
        diff_result = differ.vulnerabilities_diff
        info_result = differ.vulnerabilities_diff_all_info

    # verify results
    assert diff_result == ["CVE-2023-1234"]
    assert len(info_result) == 1
    assert "CVE-2023-1234" in info_result

    package_info = info_result["CVE-2023-1234"][0]
    assert package_info["package1"]["previous_version"] == "1.0.0"
    assert package_info["package1"]["new_version"] == "1.1.0"
    assert package_info["package1"]["removed"] is False


def test_init_with_invalid_scanner(test_previous_sbom_path, test_next_sbom_path):
    """Test VulnerabilityDiffer initialization with invalid scanner."""
    with pytest.raises(
        ValueError, match="Unsupported scanner: invalid. Supported scanners: \\['acs', 'trivy'\\]"
    ):
        VulnerabilityDiffer(
            previous_sbom=test_previous_sbom_path,
            next_sbom=test_next_sbom_path,
            scanner="invalid",
        )


def test_init_with_valid_scanners(rox_env, test_previous_sbom_path, test_next_sbom_path):
    """Test VulnerabilityDiffer initialization with valid scanners."""
    # Test with trivy scanner (default)
    differ_trivy = VulnerabilityDiffer(
        previous_sbom=test_previous_sbom_path, next_sbom=test_next_sbom_path, scanner="trivy"
    )
    assert differ_trivy.previous_release.sbom == test_previous_sbom_path
    assert differ_trivy.next_release.sbom == test_next_sbom_path

    # Test with acs scanner
    differ_acs = VulnerabilityDiffer(
        previous_sbom=test_previous_sbom_path, next_sbom=test_next_sbom_path, scanner="acs"
    )
    assert differ_acs.previous_release.sbom == test_previous_sbom_path
    assert differ_acs.next_release.sbom == test_next_sbom_path
