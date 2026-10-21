"""Unit tests for the ScanReport class."""

from collections import defaultdict
from unittest.mock import MagicMock, patch

import pytest

from diffused.report import ScanReport
from diffused.scanners.models import Package


def _report_with_mock_scanner(scan_type=None, image="image:latest", sbom=None):
    """Build a ScanReport backed by a mock scanner, returning (report, scanner)."""
    scanner = MagicMock()
    scanner.image = image
    scanner.sbom = sbom
    scanner.raw_result = None
    scanner.error = ""
    scanner.processed_result = defaultdict(set)
    with patch("diffused.report.get_scanner_class", return_value=MagicMock(return_value=scanner)):
        report = ScanReport(image=image, sbom=sbom, scanner="acs", scan_type=scan_type)
    return report, scanner


# --- construction / inference -------------------------------------------------


def test_infers_image_scan_type(test_image):
    report = ScanReport(image=test_image)
    assert report.scan_type == "image"
    assert report.image == test_image
    assert report.sbom is None


def test_infers_sbom_scan_type(test_sbom_path):
    report = ScanReport(sbom=test_sbom_path)
    assert report.scan_type == "sbom"
    assert report.sbom == test_sbom_path
    assert report.image is None


def test_explicit_scan_type_is_kept(test_image):
    report = ScanReport(image=test_image, scan_type="image")
    assert report.scan_type == "image"


def test_infers_sbom_when_both_targets_set(test_image, test_sbom_path):
    # inference prefers sbom whenever an sbom is provided, even if an image is too
    report = ScanReport(image=test_image, sbom=test_sbom_path)
    assert report.scan_type == "sbom"


def test_explicit_scan_type_overrides_inference(test_sbom_path):
    # an explicit scan_type wins over what inference would pick from the target
    report = ScanReport(sbom=test_sbom_path, scan_type="image")
    assert report.scan_type == "image"


def test_unsupported_scanner(test_image):
    with pytest.raises(ValueError, match="Unsupported scanner"):
        ScanReport(image=test_image, scanner="nope")


# --- scan() -------------------------------------------------------------------


def test_scan_runs_image_scan():
    report, scanner = _report_with_mock_scanner(scan_type="image")
    scanner.scan_image.side_effect = lambda: setattr(scanner, "raw_result", {"result": {}})

    report.scan()

    scanner.scan_image.assert_called_once()
    scanner.scan_sbom.assert_not_called()


def test_scan_runs_sbom_scan():
    report, scanner = _report_with_mock_scanner(scan_type="sbom", image=None, sbom="s.json")
    scanner.scan_sbom.side_effect = lambda: setattr(scanner, "raw_result", {"Results": []})

    report.scan()

    scanner.scan_sbom.assert_called_once()
    scanner.scan_image.assert_not_called()


def test_scan_is_idempotent_when_already_scanned():
    report, scanner = _report_with_mock_scanner(scan_type="image")
    scanner.raw_result = {"result": {}}

    report.scan()

    scanner.scan_image.assert_not_called()


def test_scan_fails_closed_for_image():
    report, scanner = _report_with_mock_scanner(scan_type="image", image="img:1")
    scanner.error = "ACS unreachable"

    with pytest.raises(RuntimeError, match="Failed to scan image img:1. ACS unreachable"):
        report.scan()


def test_scan_fails_closed_for_sbom():
    report, scanner = _report_with_mock_scanner(scan_type="sbom", image=None, sbom="s.json")
    scanner.error = "bad sbom"

    with pytest.raises(RuntimeError, match="Failed to scan sbom s.json. bad sbom"):
        report.scan()


def test_scan_unsupported_scan_type():
    report, _ = _report_with_mock_scanner(scan_type="bogus")

    with pytest.raises(ValueError, match="Unsupported scan_type: bogus"):
        report.scan()


def test_scan_accepts_empty_success_result():
    """A successful but empty ({}) report is a valid scan, not a failure, and is cached."""
    report, scanner = _report_with_mock_scanner(scan_type="image")
    scanner.scan_image.side_effect = lambda: setattr(scanner, "raw_result", {})

    report.scan()  # must not raise even though {} is falsy
    report.scan()  # idempotent: already scanned, not re-invoked

    scanner.scan_image.assert_called_once()
    assert report.raw_result == {}


def test_scan_type_target_mismatch_propagates_scanner_error():
    # scan_type says image but only an sbom was provided: the scanner's own
    # ValueError surfaces (ScanReport does not mask a caller/target mismatch)
    report, scanner = _report_with_mock_scanner(scan_type="image", image=None, sbom="s.json")
    scanner.scan_image.side_effect = ValueError("You must set the image to scan.")

    with pytest.raises(ValueError, match="You must set the image to scan."):
        report.scan()


# --- result properties --------------------------------------------------------


def test_raw_result_returns_full_report():
    report, scanner = _report_with_mock_scanner(scan_type="image")
    full = {"result": {"vulnerabilities": [{"cveId": "CVE-2023-1234"}]}}
    scanner.scan_image.side_effect = lambda: setattr(scanner, "raw_result", full)

    assert report.raw_result == full


def test_processed_result_processes_lazily():
    report, scanner = _report_with_mock_scanner(scan_type="image")
    scanner.raw_result = {"result": {}}
    scanner.process_result.side_effect = lambda: scanner.processed_result.__setitem__(
        "CVE-2023-1234", {Package(name="pkg", version="1.0")}
    )

    result = report.processed_result

    scanner.process_result.assert_called_once()
    assert "CVE-2023-1234" in result


def test_processed_result_skips_when_already_processed():
    report, scanner = _report_with_mock_scanner(scan_type="image")
    scanner.raw_result = {"result": {}}
    scanner.processed_result = defaultdict(
        set, {"CVE-2023-1234": {Package(name="pkg", version="1.0")}}
    )
    report._processed = True

    report.processed_result

    scanner.process_result.assert_not_called()


def test_processed_result_scans_then_processes_when_unscanned():
    """processed_result must scan() (populating raw_result) before process_result()."""
    report, scanner = _report_with_mock_scanner(scan_type="image")
    # raw_result starts None; scan_image() populates it, then process_result() runs
    scanner.scan_image.side_effect = lambda: setattr(scanner, "raw_result", {"result": {}})

    def _process():
        # enforce order: process_result must not run before scan() populated raw_result
        assert scanner.raw_result is not None, "process_result ran before scan()"
        scanner.processed_result["CVE-2023-1234"] = {Package(name="pkg", version="1.0")}

    scanner.process_result.side_effect = _process

    result = report.processed_result

    scanner.scan_image.assert_called_once()
    scanner.process_result.assert_called_once()
    assert "CVE-2023-1234" in result


def test_processed_result_does_not_reprocess_empty_success():
    """A successful zero-vulnerability scan must not reprocess on subsequent access."""
    report, scanner = _report_with_mock_scanner(scan_type="image")
    scanner.raw_result = {"result": {}}
    # process_result leaves processed_result empty (clean image)

    report.processed_result
    report.processed_result

    scanner.process_result.assert_called_once()


def test_vulnerabilities_are_sorted():
    report, scanner = _report_with_mock_scanner(scan_type="image")
    scanner.raw_result = {"result": {}}
    scanner.processed_result = defaultdict(set, {"CVE-2023-5678": set(), "CVE-2023-1234": set()})

    assert report.vulnerabilities == ["CVE-2023-1234", "CVE-2023-5678"]
