"""Differ module responsible for diffing the vulnerabilities between two container images."""

import json
import logging
from typing import Dict, List, Optional, Union

from diffused.report import ScanReport

logger = logging.getLogger(__name__)


class VulnerabilityDiffer:
    """Vulnerability differ class"""

    def __init__(
        self,
        previous_sbom: Optional[str] = None,
        next_sbom: Optional[str] = None,
        previous_image: Optional[str] = None,
        next_image: Optional[str] = None,
        scanner: str = "trivy",
        scan_type: Optional[str] = None,
    ):
        # the differ is simply two single-target reports plus the diff logic
        self.previous_release = ScanReport(
            image=previous_image, sbom=previous_sbom, scanner=scanner, scan_type=scan_type
        )
        self.next_release = ScanReport(
            image=next_image, sbom=next_sbom, scanner=scanner, scan_type=scan_type
        )
        self._vulnerabilities_diff: Optional[List[str]] = None
        self._vulnerabilities_diff_all_info: Optional[
            Dict[str, List[Dict[str, Dict[str, Union[str, bool]]]]]
        ] = None
        self._new_vulnerabilities: Optional[List[str]] = None
        self._new_vulnerabilities_all_info: Optional[
            Dict[str, List[Dict[str, Dict[str, Union[str, bool]]]]]
        ] = None

    @property
    def scan_type(self) -> str:
        """Scan type (image or sbom) used by the reports."""
        return self.previous_release.scan_type

    @scan_type.setter
    def scan_type(self, value: str) -> None:
        """Propagate a scan type change to both reports (effective before scanning)."""
        self.previous_release.scan_type = value
        self.next_release.scan_type = value

    def _diff_keys(self, minuend_release: ScanReport, subtrahend_release: ScanReport) -> List[str]:
        """Return the vulnerability keys present in minuend_release but not subtrahend_release.

        Accessing ``processed_result`` scans and processes each release lazily as needed.
        """
        # sort for deterministic ordering (set-difference order is hash-seed dependent)
        return sorted(
            set(minuend_release.processed_result.keys())
            - set(subtrahend_release.processed_result.keys())
        )

    def diff_vulnerabilities(self) -> None:
        """Creates a diff between the vulnerabilities of the previous and the next scan results."""
        self._vulnerabilities_diff = self._diff_keys(self.previous_release, self.next_release)

    def diff_new_vulnerabilities(self) -> None:
        """Creates a diff of vulnerabilities present in the next but not the previous scan."""
        self._new_vulnerabilities = self._diff_keys(self.next_release, self.previous_release)

    @staticmethod
    def load_sbom(sbom_path: str) -> dict:
        """Load the SBOM from a file path."""
        with open(sbom_path, "r") as sbom_file:
            return json.load(sbom_file)

    def _generate_additional_info(
        self,
        vulnerabilities: List[str],
        source_release: ScanReport,
        target_release: ScanReport,
        source_version_key: str,
        target_version_key: str,
        change_key: str,
        target_name: str,
    ) -> Dict[str, List[Dict[str, Dict[str, Union[str, bool]]]]]:
        """Builds per-package version information for a set of vulnerabilities.

        The affected packages are taken from ``source_release`` and looked up in the
        ``target_release`` SBOM to determine the counterpart version and whether the
        package was added/removed between the two releases.

        Note: This requires the target release SBOM to be available. If it is not
        available, this returns an empty dictionary.
        """
        # early return if no vulnerabilities to process
        if not vulnerabilities:
            return {}

        # early return if the target SBOM is not available (cannot generate additional info)
        if not target_release.sbom:
            logger.warning(
                f"SBOM not available for {target_name} release."
                " Cannot generate additional vulnerability info."
            )
            return {}

        # load the target release SBOM, then build the version diff from the loaded data
        target_release_sbom = self.load_sbom(target_release.sbom)
        return self._build_additional_info(
            vulnerabilities=vulnerabilities,
            source_release=source_release,
            target_release_sbom=target_release_sbom,
            source_version_key=source_version_key,
            target_version_key=target_version_key,
            change_key=change_key,
        )

    @staticmethod
    def _build_additional_info(
        vulnerabilities: List[str],
        source_release: ScanReport,
        target_release_sbom: dict,
        source_version_key: str,
        target_version_key: str,
        change_key: str,
    ) -> Dict[str, List[Dict[str, Dict[str, Union[str, bool]]]]]:
        """Builds per-package version information from an already-loaded target SBOM.

        The target SBOM is passed in already loaded, so this method does not load any
        SBOM file itself. The affected packages come from ``source_release`` (expected
        to be an already-scanned report; accessing ``processed_result`` would otherwise
        scan lazily) and are looked up in ``target_release_sbom`` to determine the
        counterpart version and whether the package was added/removed.
        """
        # resolve the processed result once (accessing it may scan/process lazily)
        source_processed_result = source_release.processed_result

        # collect all affected package names from vulnerabilities
        affected_package_names = set()
        for vulnerability in vulnerabilities:
            for package in source_processed_result[vulnerability]:
                affected_package_names.add(package.name)

        # only load affected packages into memory
        target_packages = {
            package["name"]: package["versionInfo"]
            for package in target_release_sbom.get("packages", [])
            if package["name"] in affected_package_names
        }

        all_info: Dict[str, List[Dict[str, Dict[str, Union[str, bool]]]]] = {}
        for vulnerability in vulnerabilities:
            affected_packages = source_processed_result[vulnerability]

            # create list of package dictionaries for this vulnerability
            package_list = [
                {
                    package.name: {
                        source_version_key: package.version,
                        target_version_key: target_packages.get(package.name, ""),
                        change_key: package.name not in target_packages,
                    }
                }
                for package in affected_packages
            ]

            all_info[vulnerability] = package_list

        return all_info

    def generate_additional_info(self) -> None:
        """Generates all additional information related to the fixed vulnerabilities.

        Note: This requires the next release SBOM to be available. If it is not available,
        this will return an empty dictionary.
        """
        if self._vulnerabilities_diff is None:
            self.diff_vulnerabilities()
        assert self._vulnerabilities_diff is not None

        self._vulnerabilities_diff_all_info = self._generate_additional_info(
            vulnerabilities=self._vulnerabilities_diff,
            source_release=self.previous_release,
            target_release=self.next_release,
            source_version_key="previous_version",
            target_version_key="new_version",
            change_key="removed",
            target_name="next",
        )

    def generate_new_additional_info(self) -> None:
        """Generates all additional information related to the new vulnerabilities.

        Note: This requires the previous release SBOM to be available. If it is not
        available, this will return an empty dictionary.
        """
        if self._new_vulnerabilities is None:
            self.diff_new_vulnerabilities()
        assert self._new_vulnerabilities is not None

        self._new_vulnerabilities_all_info = self._generate_additional_info(
            vulnerabilities=self._new_vulnerabilities,
            source_release=self.next_release,
            target_release=self.previous_release,
            source_version_key="new_version",
            target_version_key="previous_version",
            change_key="added",
            target_name="previous",
        )

    @property
    def vulnerabilities_diff(self):
        """Process the SBOM, if needed, and return the vulnerabilities diff."""
        if self._vulnerabilities_diff is None:
            self.diff_vulnerabilities()
        return self._vulnerabilities_diff

    @property
    def vulnerabilities_diff_all_info(self):
        """Process the SBOM, if needed, and return the vulnerabilities diff with additional info."""
        if self._vulnerabilities_diff_all_info is None:
            self.generate_additional_info()
        return self._vulnerabilities_diff_all_info

    @property
    def new_vulnerabilities(self):
        """Process the SBOM, if needed, and return the new vulnerabilities."""
        if self._new_vulnerabilities is None:
            self.diff_new_vulnerabilities()
        return self._new_vulnerabilities

    @property
    def new_vulnerabilities_all_info(self):
        """Process the SBOM, if needed, and return the new vulnerabilities with additional info."""
        if self._new_vulnerabilities_all_info is None:
            self.generate_new_additional_info()
        return self._new_vulnerabilities_all_info
