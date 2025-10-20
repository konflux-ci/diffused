"""Differ module responsible for diffing the vulnerabilities between two container images."""

import json
import logging
from typing import Dict, List, Optional, Union

from diffused.scanners.acs import ACSScanner
from diffused.scanners.trivy import TrivyScanner

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
        # Create scanner instances based on the scanner parameter
        scanner_class = self._get_scanner_class(scanner)
        self.previous_release = scanner_class(sbom=previous_sbom, image=previous_image)
        self.next_release = scanner_class(sbom=next_sbom, image=next_image)
        self.scan_type = scan_type
        self._vulnerabilities_diff: List[str] = []
        self._vulnerabilities_diff_all_info: Dict[
            str, List[Dict[str, Dict[str, Union[str, bool]]]]
        ] = {}
        self.error: str = ""

    @staticmethod
    def _get_scanner_class(scanner: str):
        """Get the scanner class based on the scanner name."""
        scanner_map = {
            "acs": ACSScanner,
            "trivy": TrivyScanner,
        }

        if scanner not in scanner_map:
            raise ValueError(
                f"Unsupported scanner: {scanner}. Supported scanners: {list(scanner_map.keys())}"
            )

        return scanner_map[scanner]

    def scan_images(self) -> None:
        """Scans the previous and next images directly."""
        if not self.previous_release.raw_result:
            self.previous_release.scan_image()
        if not self.next_release.raw_result:
            self.next_release.scan_image()

    def scan_sboms(self) -> None:
        """Scans the previous and the next SBOMs."""
        if not self.previous_release.raw_result:
            self.previous_release.scan_sbom()
        if not self.next_release.raw_result:
            self.next_release.scan_sbom()

    def process_results(self) -> None:
        """Processes the results for the previous and the next releases, if not present.

        If raw results are not available and scan_type is set, performs the appropriate
        scan before processing.
        """
        # Check if we need to perform scans first
        if not self.previous_release.raw_result or not self.next_release.raw_result:
            if self.scan_type:
                if self.scan_type == "sbom":
                    self.scan_sboms()
                elif self.scan_type == "image":
                    self.scan_images()
                else:
                    raise ValueError(
                        f"Unsupported scan_type: {self.scan_type}."
                        " Supported types: ['sbom', 'image']"
                    )

                # Check if scans were successful before processing
                if not self.previous_release.raw_result:
                    error_msg = f"Failed to scan previous release. {self.previous_release.error}"
                    logger.error(error_msg)
                    self.error = error_msg
                    raise RuntimeError(error_msg)
                if not self.next_release.raw_result:
                    error_msg = f"Failed to scan next release. {self.next_release.error}"
                    logger.error(error_msg)
                    self.error = error_msg
                    raise RuntimeError(error_msg)

        # Process results if not already processed
        if not self.previous_release.processed_result:
            self.previous_release.process_result()
        if not self.next_release.processed_result:
            self.next_release.process_result()

    def diff_vulnerabilities(self) -> None:
        """Creates a diff between the vulnerabilities of the previous and the next scan results."""
        if not self.previous_release.processed_result or not self.next_release.processed_result:
            self.process_results()

        previous_vulnerabilities = set(self.previous_release.processed_result.keys())
        next_vulnerabilities = set(self.next_release.processed_result.keys())
        self._vulnerabilities_diff = list(previous_vulnerabilities - next_vulnerabilities)

    @staticmethod
    def load_sbom(sbom_path: str) -> dict:
        """Load the SBOM from a file path."""
        with open(sbom_path, "r") as sbom_file:
            return json.load(sbom_file)

    def generate_additional_info(self) -> None:
        """Generates all additional information related to the vulnerabilities.

        Note: This requires the next release SBOM to be available. If it is not available,
        this will return an empty dictionary.
        """
        if not self._vulnerabilities_diff:
            self.diff_vulnerabilities()

        # early return if no vulnerabilities to process
        if not self._vulnerabilities_diff:
            self._vulnerabilities_diff_all_info = {}
            return

        # early return if SBOMs are not available (cannot generate additional info)
        if not self.next_release.sbom:
            logger.warning(
                "SBOM not available for next release."
                " Cannot generate additional vulnerability info."
            )
            self._vulnerabilities_diff_all_info = {}
            return

        # collect all affected package names from vulnerabilities
        affected_package_names = set()
        for vulnerability in self._vulnerabilities_diff:
            affected_packages = self.previous_release.processed_result[vulnerability]
            for package in affected_packages:
                affected_package_names.add(package.name)

        # load the next release SBOM
        next_release_sbom = self.load_sbom(self.next_release.sbom)

        # only load affected packages into memory
        next_packages = {
            package["name"]: package["versionInfo"]
            for package in next_release_sbom.get("packages", [])
            if package["name"] in affected_package_names
        }

        for vulnerability in self._vulnerabilities_diff:
            affected_packages = self.previous_release.processed_result[vulnerability]

            # create list of package dictionaries for this vulnerability
            package_list = [
                {
                    package.name: {
                        "previous_version": package.version,
                        "new_version": next_packages.get(package.name, ""),
                        "removed": package.name not in next_packages,
                    }
                }
                for package in affected_packages
            ]

            self._vulnerabilities_diff_all_info[vulnerability] = package_list

    @property
    def vulnerabilities_diff(self):
        """Process the SBOM, if needed, and return the vulnerabilities diff."""
        if not self._vulnerabilities_diff:
            self.diff_vulnerabilities()
        return self._vulnerabilities_diff

    @property
    def vulnerabilities_diff_all_info(self):
        """Process the SBOM, if needed, and return the vulnerabilities diff with additional info."""
        if not self._vulnerabilities_diff_all_info:
            self.generate_additional_info()
        return self._vulnerabilities_diff_all_info
