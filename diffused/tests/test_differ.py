"""Unit tests for VulnerabilityDiffer class."""

import json
from collections import defaultdict
from unittest.mock import MagicMock, mock_open, patch

import pytest

from diffused.differ import VulnerabilityDiffer
from diffused.scanners.models import Package


def _seed(report, processed=None):
    """Seed a ScanReport's underlying scanner so the lazy properties return canned data.

    A truthy ``raw_result`` makes ``ScanReport.scan()`` a no-op (no real scan), and a
    pre-populated ``processed_result`` is returned directly by the property.
    """
    report.scanner.raw_result = {"Results": []}
    pr = defaultdict(set)
    if processed:
        pr.update(processed)
    report.scanner.processed_result = pr
    report._processed = True


def test_init_with_sbom_paths(test_previous_sbom_path, test_next_sbom_path):
    """Test VulnerabilityDiffer initialization with SBOM paths."""
    differ = VulnerabilityDiffer(
        previous_sbom=test_previous_sbom_path, next_sbom=test_next_sbom_path
    )

    assert differ.previous_release.sbom == test_previous_sbom_path
    assert differ.next_release.sbom == test_next_sbom_path
    assert differ.previous_release.image is None
    assert differ.next_release.image is None
    # scan_type omitted -> both reports infer "sbom" from their targets
    assert differ.previous_release.scan_type == "sbom"
    assert differ.next_release.scan_type == "sbom"
    assert differ._vulnerabilities_diff is None
    assert differ._vulnerabilities_diff_all_info is None
    assert differ._new_vulnerabilities is None
    assert differ._new_vulnerabilities_all_info is None


def test_init_with_images(test_previous_image, test_next_image):
    """Test VulnerabilityDiffer initialization with container images."""
    differ = VulnerabilityDiffer(previous_image=test_previous_image, next_image=test_next_image)

    assert differ.previous_release.image == test_previous_image
    assert differ.next_release.image == test_next_image
    assert differ.previous_release.sbom is None
    assert differ.next_release.sbom is None
    # scan_type omitted -> both reports infer "image" from their targets
    assert differ.previous_release.scan_type == "image"
    assert differ.next_release.scan_type == "image"


def test_init_with_mixed_parameters(test_previous_sbom_path, test_next_image):
    """Test VulnerabilityDiffer initialization with mixed parameters."""
    differ = VulnerabilityDiffer(previous_sbom=test_previous_sbom_path, next_image=test_next_image)

    assert differ.previous_release.sbom == test_previous_sbom_path
    assert differ.next_release.image == test_next_image
    assert differ.previous_release.image is None
    assert differ.next_release.sbom is None
    # scan_type omitted -> each report infers independently from its own target
    assert differ.previous_release.scan_type == "sbom"
    assert differ.next_release.scan_type == "image"


def test_init_with_scan_type(test_previous_sbom_path, test_next_sbom_path):
    """Test VulnerabilityDiffer keeps the scan_type parameter."""
    differ = VulnerabilityDiffer(
        previous_sbom=test_previous_sbom_path,
        next_sbom=test_next_sbom_path,
        scan_type="sbom",
    )
    assert differ.scan_type == "sbom"


def test_scan_type_setter_propagates_to_both_reports(test_previous_image, test_next_image):
    """Setting scan_type on the differ updates both reports (effective before scanning)."""
    differ = VulnerabilityDiffer(previous_image=test_previous_image, next_image=test_next_image)
    assert differ.scan_type == "image"  # getter reads from the reports

    differ.scan_type = "sbom"

    assert differ.previous_release.scan_type == "sbom"
    assert differ.next_release.scan_type == "sbom"
    assert differ.scan_type == "sbom"


def test_init_with_invalid_scanner(test_previous_sbom_path, test_next_sbom_path):
    """Test VulnerabilityDiffer initialization with invalid scanner."""
    with pytest.raises(
        ValueError,
        match="Unsupported scanner: invalid. Supported scanners: \\['acs', 'grype', 'trivy'\\]",
    ):
        VulnerabilityDiffer(
            previous_sbom=test_previous_sbom_path,
            next_sbom=test_next_sbom_path,
            scanner="invalid",
        )


def test_init_with_valid_scanners(rox_env, test_previous_sbom_path, test_next_sbom_path):
    """Test VulnerabilityDiffer initialization with valid scanners."""
    differ_trivy = VulnerabilityDiffer(
        previous_sbom=test_previous_sbom_path, next_sbom=test_next_sbom_path, scanner="trivy"
    )
    assert differ_trivy.previous_release.sbom == test_previous_sbom_path
    assert differ_trivy.next_release.sbom == test_next_sbom_path

    differ_acs = VulnerabilityDiffer(
        previous_sbom=test_previous_sbom_path, next_sbom=test_next_sbom_path, scanner="acs"
    )
    assert differ_acs.previous_release.sbom == test_previous_sbom_path
    assert differ_acs.next_release.sbom == test_next_sbom_path


def test_scan_type_forwarded_to_both_reports(test_previous_image, test_next_image):
    """Test scan_type is forwarded onto both reports, overriding what they would infer."""
    # both image and sbom are set on each side, so inference alone would pick "sbom";
    # an explicit scan_type="image" winning proves it is actually forwarded.
    differ = VulnerabilityDiffer(
        previous_image=test_previous_image,
        previous_sbom="previous.sbom.json",
        next_image=test_next_image,
        next_sbom="next.sbom.json",
        scan_type="image",
    )
    assert differ.previous_release.scan_type == "image"
    assert differ.next_release.scan_type == "image"


def _wire_scanner(report, cves):
    """Make a report's real scanner populate raw_result/processed_result on demand."""
    report.scanner.scan_image = MagicMock(
        side_effect=lambda: setattr(report.scanner, "raw_result", {"result": {}})
    )

    def _process():
        for cve in cves:
            report.scanner.processed_result[cve] = {Package(name="pkg", version="1.0")}

    report.scanner.process_result = MagicMock(side_effect=_process)


def test_vulnerabilities_diff_scans_lazily_without_seed(test_previous_image, test_next_image):
    """vulnerabilities_diff drives real scan()/process_result() through the reports."""
    differ = VulnerabilityDiffer(previous_image=test_previous_image, next_image=test_next_image)

    _wire_scanner(differ.previous_release, ["CVE-2023-1111", "CVE-2023-2222"])
    _wire_scanner(differ.next_release, ["CVE-2023-2222"])  # next drops CVE-2023-1111 (fixed)

    assert differ.vulnerabilities_diff == ["CVE-2023-1111"]
    differ.previous_release.scanner.scan_image.assert_called_once()
    differ.next_release.scanner.scan_image.assert_called_once()


def test_vulnerabilities_diff_propagates_scan_failure(test_previous_image, test_next_image):
    """A failed scan (raw_result left None) surfaces as RuntimeError via the lazy diff.

    Exercises ScanReport.scan()'s real fail-closed path (not a stubbed scan).
    """
    differ = VulnerabilityDiffer(previous_image=test_previous_image, next_image=test_next_image)

    # scan_image "runs" but leaves raw_result None and records an error -> fail-closed
    differ.previous_release.scanner.scan_image = MagicMock()
    differ.previous_release.scanner.error = "ACS unreachable"

    with pytest.raises(RuntimeError, match="Failed to scan image .*ACS unreachable"):
        _ = differ.vulnerabilities_diff


def test_diff_vulnerabilities(test_previous_sbom_path, test_next_sbom_path):
    """Test diff_vulnerabilities method."""
    differ = VulnerabilityDiffer(
        previous_sbom=test_previous_sbom_path, next_sbom=test_next_sbom_path
    )

    _seed(
        differ.previous_release,
        {
            "CVE-2023-1234": {Package(name="pkg1", version="1.0")},
            "CVE-2023-5678": {Package(name="pkg2", version="2.0")},
            "CVE-2023-9999": {Package(name="pkg3", version="3.0")},
        },
    )
    _seed(
        differ.next_release,
        {
            "CVE-2023-5678": {Package(name="pkg2", version="2.1")},  # still present
            "CVE-2023-9999": {Package(name="pkg3", version="3.0")},  # still present
        },
    )

    differ.diff_vulnerabilities()

    # should find CVE-2023-1234 as fixed (present in previous but not in next)
    assert differ._vulnerabilities_diff == ["CVE-2023-1234"]


def test_diff_new_vulnerabilities(test_previous_sbom_path, test_next_sbom_path):
    """Test diff_new_vulnerabilities method."""
    differ = VulnerabilityDiffer(
        previous_sbom=test_previous_sbom_path, next_sbom=test_next_sbom_path
    )

    _seed(
        differ.previous_release,
        {
            "CVE-2023-5678": {Package(name="pkg2", version="2.0")},
            "CVE-2023-9999": {Package(name="pkg3", version="3.0")},
        },
    )
    _seed(
        differ.next_release,
        {
            "CVE-2023-5678": {Package(name="pkg2", version="2.1")},  # still present
            "CVE-2023-9999": {Package(name="pkg3", version="3.0")},  # still present
            "CVE-2023-1234": {Package(name="pkg1", version="1.0")},  # newly introduced
        },
    )

    differ.diff_new_vulnerabilities()

    # should find CVE-2023-1234 as new (present in next but not in previous)
    assert differ._new_vulnerabilities == ["CVE-2023-1234"]


def test_diff_new_vulnerabilities_identical_sets(test_previous_sbom_path, test_next_sbom_path):
    """Test diff_new_vulnerabilities returns empty when both releases share the same CVEs."""
    differ = VulnerabilityDiffer(
        previous_sbom=test_previous_sbom_path, next_sbom=test_next_sbom_path
    )

    _seed(differ.previous_release, {"CVE-2023-5678": {Package(name="pkg2", version="2.0")}})
    _seed(differ.next_release, {"CVE-2023-5678": {Package(name="pkg2", version="2.1")}})

    differ.diff_new_vulnerabilities()

    assert differ._new_vulnerabilities == []


def test_diff_new_vulnerabilities_all_new(test_previous_sbom_path, test_next_sbom_path):
    """Test diff_new_vulnerabilities returns every CVE when previous has none."""
    differ = VulnerabilityDiffer(
        previous_sbom=test_previous_sbom_path, next_sbom=test_next_sbom_path
    )

    _seed(differ.previous_release)
    _seed(
        differ.next_release,
        {
            "CVE-2023-1234": {Package(name="pkg1", version="1.0")},
            "CVE-2023-5678": {Package(name="pkg2", version="2.0")},
        },
    )

    differ.diff_new_vulnerabilities()

    # order must be deterministic (sorted), not just set-equal
    assert differ._new_vulnerabilities == ["CVE-2023-1234", "CVE-2023-5678"]


def test_diff_both_directions_same_instance(test_previous_sbom_path, test_next_sbom_path):
    """Test computing fixed and new diffs on one instance keeps the two caches independent."""
    differ = VulnerabilityDiffer(
        previous_sbom=test_previous_sbom_path, next_sbom=test_next_sbom_path
    )

    _seed(
        differ.previous_release,
        {
            "CVE-2023-5678": {Package(name="pkg2", version="2.0")},  # shared
            "CVE-2023-FIXED": {Package(name="pkg9", version="9.0")},  # only in previous
        },
    )
    _seed(
        differ.next_release,
        {
            "CVE-2023-5678": {Package(name="pkg2", version="2.1")},  # shared
            "CVE-2023-NEW": {Package(name="pkg1", version="1.0")},  # only in next
        },
    )

    differ.diff_vulnerabilities()
    differ.diff_new_vulnerabilities()

    # fixed = previous - next; new = next - previous; the two caches must not clobber each other
    assert differ._vulnerabilities_diff == ["CVE-2023-FIXED"]
    assert differ._new_vulnerabilities == ["CVE-2023-NEW"]


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

    def mock_diff():
        differ._vulnerabilities_diff = []

    differ.diff_vulnerabilities = MagicMock(side_effect=mock_diff)

    differ.generate_additional_info()

    differ.diff_vulnerabilities.assert_called_once()
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

    # affected packages come from the previous release
    differ._vulnerabilities_diff = ["CVE-2023-1234", "CVE-2023-5678"]
    _seed(
        differ.previous_release,
        {
            "CVE-2023-1234": {
                Package(name="package1", version="1.0.0"),
                Package(name="package2", version="2.0.0"),
            },
            "CVE-2023-5678": {Package(name="package3", version="3.0.0")},
        },
    )

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

    package1_info = next(info for info in cve_1234_info if "package1" in info)
    assert package1_info["package1"]["previous_version"] == "1.0.0"
    assert package1_info["package1"]["new_version"] == "1.1.0"
    assert package1_info["package1"]["removed"] is False

    package2_info = next(info for info in cve_1234_info if "package2" in info)
    assert package2_info["package2"]["previous_version"] == "2.0.0"
    assert package2_info["package2"]["new_version"] == "2.0.0"
    assert package2_info["package2"]["removed"] is False

    # check CVE-2023-5678 (package3 removed)
    cve_5678_info = differ._vulnerabilities_diff_all_info["CVE-2023-5678"]
    assert len(cve_5678_info) == 1
    package3_info = cve_5678_info[0]
    assert package3_info["package3"]["previous_version"] == "3.0.0"
    assert package3_info["package3"]["new_version"] == ""
    assert package3_info["package3"]["removed"] is True


def test_vulnerabilities_diff_property(test_previous_sbom_path, test_next_sbom_path):
    """Test vulnerabilities_diff property."""
    differ = VulnerabilityDiffer(
        previous_sbom=test_previous_sbom_path, next_sbom=test_next_sbom_path
    )

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

    differ.diff_vulnerabilities = MagicMock()
    differ._vulnerabilities_diff = None

    def mock_diff():
        differ._vulnerabilities_diff = ["CVE-2023-1234"]

    differ.diff_vulnerabilities.side_effect = mock_diff

    result = differ.vulnerabilities_diff

    differ.diff_vulnerabilities.assert_called_once()
    assert result == ["CVE-2023-1234"]


def test_vulnerabilities_diff_all_info_property(test_previous_sbom_path, test_next_sbom_path):
    """Test vulnerabilities_diff_all_info property."""
    differ = VulnerabilityDiffer(
        previous_sbom=test_previous_sbom_path, next_sbom=test_next_sbom_path
    )

    differ.generate_additional_info = MagicMock()
    differ._vulnerabilities_diff_all_info = {"CVE-2023-1234": []}

    result = differ.vulnerabilities_diff_all_info

    differ.generate_additional_info.assert_not_called()
    assert result == {"CVE-2023-1234": []}


def test_vulnerabilities_diff_all_info_property_calls_generate(
    test_previous_sbom_path, test_next_sbom_path
):
    """Test vulnerabilities_diff_all_info property calls generate when empty."""
    differ = VulnerabilityDiffer(
        previous_sbom=test_previous_sbom_path, next_sbom=test_next_sbom_path
    )

    differ.generate_additional_info = MagicMock()
    differ._vulnerabilities_diff_all_info = None

    def mock_generate():
        differ._vulnerabilities_diff_all_info = {"CVE-2023-1234": []}

    differ.generate_additional_info.side_effect = mock_generate

    result = differ.vulnerabilities_diff_all_info

    differ.generate_additional_info.assert_called_once()
    assert result == {"CVE-2023-1234": []}


def test_integration_workflow(test_previous_sbom_path, test_next_sbom_path):
    """Test complete workflow integration driven through the lazy properties."""
    differ = VulnerabilityDiffer(
        previous_sbom=test_previous_sbom_path, next_sbom=test_next_sbom_path
    )

    _seed(differ.previous_release, {"CVE-2023-1234": {Package(name="package1", version="1.0.0")}})
    _seed(differ.next_release)

    test_sbom = {"packages": [{"name": "package1", "versionInfo": "1.1.0"}]}

    with patch.object(differ, "load_sbom", return_value=test_sbom):
        diff_result = differ.vulnerabilities_diff
        info_result = differ.vulnerabilities_diff_all_info

    assert diff_result == ["CVE-2023-1234"]
    assert len(info_result) == 1
    assert "CVE-2023-1234" in info_result

    package_info = info_result["CVE-2023-1234"][0]
    assert package_info["package1"]["previous_version"] == "1.0.0"
    assert package_info["package1"]["new_version"] == "1.1.0"
    assert package_info["package1"]["removed"] is False


def test_build_additional_info():
    """Test _build_additional_info builds the version diff from an already-loaded SBOM."""
    source_release = MagicMock()
    source_release.processed_result = {
        "CVE-2023-1234": {
            Package(name="package1", version="1.1.0"),
            Package(name="package2", version="2.0.0"),
        },
        "CVE-2023-5678": {Package(name="package3", version="3.0.0")},
    }

    target_release_sbom = {
        "packages": [
            {"name": "package1", "versionInfo": "1.0.0"},  # present in target
            {"name": "package2", "versionInfo": "2.0.0"},  # same version
            # package3 is missing (added)
            {"name": "package4", "versionInfo": "4.0.0"},  # unrelated package
        ]
    }

    result = VulnerabilityDiffer._build_additional_info(
        vulnerabilities=["CVE-2023-1234", "CVE-2023-5678"],
        source_release=source_release,
        target_release_sbom=target_release_sbom,
        source_version_key="new_version",
        target_version_key="previous_version",
        change_key="added",
    )

    assert len(result) == 2

    cve_1234_info = result["CVE-2023-1234"]
    package1_info = next(info for info in cve_1234_info if "package1" in info)
    assert package1_info["package1"]["new_version"] == "1.1.0"
    assert package1_info["package1"]["previous_version"] == "1.0.0"
    assert package1_info["package1"]["added"] is False

    # package3 is not in the target SBOM, so it is flagged as added
    package3_info = result["CVE-2023-5678"][0]
    assert package3_info["package3"]["new_version"] == "3.0.0"
    assert package3_info["package3"]["previous_version"] == ""
    assert package3_info["package3"]["added"] is True


def test_generate_new_additional_info_no_vulnerabilities(
    test_previous_sbom_path, test_next_sbom_path
):
    """Test generate_new_additional_info with no vulnerabilities."""
    differ = VulnerabilityDiffer(
        previous_sbom=test_previous_sbom_path, next_sbom=test_next_sbom_path
    )

    differ._new_vulnerabilities = []

    differ.generate_new_additional_info()

    assert differ._new_vulnerabilities_all_info == {}


def test_generate_new_additional_info_no_previous_sbom(test_previous_image, test_next_sbom_path):
    """Test generate_new_additional_info when previous SBOM is missing."""
    differ = VulnerabilityDiffer(
        previous_image=test_previous_image, next_sbom=test_next_sbom_path  # no previous_sbom set
    )

    differ._new_vulnerabilities = ["CVE-2023-1234"]
    differ.diff_new_vulnerabilities = MagicMock()

    differ.generate_new_additional_info()

    # should return early when no previous SBOM
    assert differ._new_vulnerabilities_all_info == {}


def test_generate_new_additional_info_with_vulnerabilities(
    test_previous_sbom_path, test_next_sbom_path
):
    """Test generate_new_additional_info with actual vulnerabilities."""
    differ = VulnerabilityDiffer(
        previous_sbom=test_previous_sbom_path, next_sbom=test_next_sbom_path
    )

    # affected packages come from the next release
    differ._new_vulnerabilities = ["CVE-2023-1234", "CVE-2023-5678"]
    _seed(
        differ.next_release,
        {
            "CVE-2023-1234": {
                Package(name="package1", version="1.1.0"),
                Package(name="package2", version="2.0.0"),
            },
            "CVE-2023-5678": {Package(name="package3", version="3.0.0")},
        },
    )

    # mock previous SBOM data
    test_sbom = {
        "packages": [
            {"name": "package1", "versionInfo": "1.0.0"},  # updated into a vulnerable version
            {"name": "package2", "versionInfo": "2.0.0"},  # same version
            # package3 is missing (added)
            {"name": "package4", "versionInfo": "4.0.0"},  # unrelated package
        ]
    }

    with patch.object(differ, "load_sbom", return_value=test_sbom) as mock_load_sbom:
        differ.generate_new_additional_info()

    # the lookup must load the previous release SBOM, not the next one
    mock_load_sbom.assert_called_once_with(test_previous_sbom_path)

    assert len(differ._new_vulnerabilities_all_info) == 2

    cve_1234_info = differ._new_vulnerabilities_all_info["CVE-2023-1234"]
    assert len(cve_1234_info) == 2

    package1_info = next(info for info in cve_1234_info if "package1" in info)
    assert package1_info["package1"]["previous_version"] == "1.0.0"
    assert package1_info["package1"]["new_version"] == "1.1.0"
    assert package1_info["package1"]["added"] is False

    package2_info = next(info for info in cve_1234_info if "package2" in info)
    assert package2_info["package2"]["previous_version"] == "2.0.0"
    assert package2_info["package2"]["new_version"] == "2.0.0"
    assert package2_info["package2"]["added"] is False

    cve_5678_info = differ._new_vulnerabilities_all_info["CVE-2023-5678"]
    assert len(cve_5678_info) == 1
    package3_info = cve_5678_info[0]
    assert package3_info["package3"]["previous_version"] == ""
    assert package3_info["package3"]["new_version"] == "3.0.0"
    assert package3_info["package3"]["added"] is True


def test_generate_new_additional_info_calls_diff_when_empty(
    test_previous_sbom_path, test_next_sbom_path
):
    """Test generate_new_additional_info triggers diff_new_vulnerabilities when unresolved."""
    differ = VulnerabilityDiffer(
        previous_sbom=test_previous_sbom_path, next_sbom=test_next_sbom_path
    )

    differ._new_vulnerabilities = None
    _seed(differ.next_release, {"CVE-2023-1234": {Package(name="package1", version="1.1.0")}})

    def mock_diff():
        differ._new_vulnerabilities = ["CVE-2023-1234"]

    differ.diff_new_vulnerabilities = MagicMock(side_effect=mock_diff)

    test_sbom = {"packages": [{"name": "package1", "versionInfo": "1.0.0"}]}

    with patch.object(differ, "load_sbom", return_value=test_sbom):
        differ.generate_new_additional_info()

    differ.diff_new_vulnerabilities.assert_called_once()
    assert "CVE-2023-1234" in differ._new_vulnerabilities_all_info


def test_new_vulnerabilities_property(test_previous_sbom_path, test_next_sbom_path):
    """Test new_vulnerabilities property."""
    differ = VulnerabilityDiffer(
        previous_sbom=test_previous_sbom_path, next_sbom=test_next_sbom_path
    )

    differ.diff_new_vulnerabilities = MagicMock()
    differ._new_vulnerabilities = ["CVE-2023-1234"]

    result = differ.new_vulnerabilities

    differ.diff_new_vulnerabilities.assert_not_called()
    assert result == ["CVE-2023-1234"]


def test_new_vulnerabilities_property_calls_diff(test_previous_sbom_path, test_next_sbom_path):
    """Test new_vulnerabilities property calls diff when empty."""
    differ = VulnerabilityDiffer(
        previous_sbom=test_previous_sbom_path, next_sbom=test_next_sbom_path
    )

    differ.diff_new_vulnerabilities = MagicMock()
    differ._new_vulnerabilities = None

    def mock_diff():
        differ._new_vulnerabilities = ["CVE-2023-1234"]

    differ.diff_new_vulnerabilities.side_effect = mock_diff

    result = differ.new_vulnerabilities

    differ.diff_new_vulnerabilities.assert_called_once()
    assert result == ["CVE-2023-1234"]


def test_new_vulnerabilities_all_info_property(test_previous_sbom_path, test_next_sbom_path):
    """Test new_vulnerabilities_all_info property."""
    differ = VulnerabilityDiffer(
        previous_sbom=test_previous_sbom_path, next_sbom=test_next_sbom_path
    )

    differ.generate_new_additional_info = MagicMock()
    differ._new_vulnerabilities_all_info = {"CVE-2023-1234": []}

    result = differ.new_vulnerabilities_all_info

    differ.generate_new_additional_info.assert_not_called()
    assert result == {"CVE-2023-1234": []}


def test_new_vulnerabilities_all_info_property_calls_generate(
    test_previous_sbom_path, test_next_sbom_path
):
    """Test new_vulnerabilities_all_info property calls generate when empty."""
    differ = VulnerabilityDiffer(
        previous_sbom=test_previous_sbom_path, next_sbom=test_next_sbom_path
    )

    differ.generate_new_additional_info = MagicMock()
    differ._new_vulnerabilities_all_info = None

    def mock_generate():
        differ._new_vulnerabilities_all_info = {"CVE-2023-1234": []}

    differ.generate_new_additional_info.side_effect = mock_generate

    result = differ.new_vulnerabilities_all_info

    differ.generate_new_additional_info.assert_called_once()
    assert result == {"CVE-2023-1234": []}
