"""Trivy scanner implementation."""

import json
import logging
import subprocess

from diffused.scanners.base import BaseScanner
from diffused.scanners.models import Package

logger = logging.getLogger(__name__)


class TrivyScanner(BaseScanner):
    """Trivy scanner class."""

    def _run_trivy_command(self, cmd: list[str], operation: str) -> subprocess.CompletedProcess:
        """Helper method to run Trivy commands."""
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                shell=False,
                text=True,
                timeout=120,  # 2 minutes timeout
            )
            result.check_returncode()
            return result
        except subprocess.CalledProcessError as e:
            error_message = f"Trivy {operation} failed. Return code: {e.returncode}."
            if e.stderr:
                error_message += f" Error output: {e.stderr}"
            logger.error(error_message)
            self.error = error_message
            raise
        except subprocess.TimeoutExpired:
            error_message = f"Trivy {operation} timed out."
            logger.error(error_message)
            self.error = error_message
            raise
        except Exception as e:
            error_message = f"Unexpected error during Trivy {operation}: {e}."
            logger.error(error_message)
            self.error = error_message
            raise

    def retrieve_sbom(self, output_file: str) -> None:
        """Retrieves the SBOM from a container image."""
        if not self.image:
            raise ValueError("You must set the image to retrieve the SBOM.")
        if not output_file:
            raise ValueError("You must set the output_file with a valid path to retrieve the SBOM.")

        # command to generate the sbom
        cmd = [
            "trivy",
            "image",
            "--format",
            "spdx-json",
            "--output",
            output_file,
            self.image,
        ]

        try:
            self._run_trivy_command(cmd, f"SBOM generation for {self.image}")
            # Set the sbom path after successful generation
            self.sbom = output_file
            logger.info(f"Successfully generated SBOM for {self.image} at {output_file}.")
        except Exception:
            # Error already logged and stored in self.error by _run_trivy_command
            pass

    def scan_sbom(self) -> None:
        """Performs a scan on a given SBOM."""
        if not self.sbom:
            raise ValueError(
                "You must set the SBOM path or retrieve from a container image before scanning it."
            )

        cmd = [
            "trivy",
            "sbom",
            "--format",
            "json",
            self.sbom,
        ]

        try:
            result = self._run_trivy_command(cmd, f"SBOM scan for {self.sbom}")
            self.raw_result = json.loads(result.stdout)
            logger.info(f"Successfully scanned SBOM {self.sbom}")
        except json.JSONDecodeError as e:
            error_message = f"Error parsing Trivy output for {self.sbom}: {e}."
            logger.error(error_message)
            self.error = error_message
        except Exception:
            # Error already logged and stored in self.error by _run_trivy_command
            pass

    def process_result(self) -> None:
        """Processes the desired data from the given scan result."""
        if self.raw_result is None:
            raise ValueError("Run a scan before processing its output.")

        # Clear previous results
        self.processed_result.clear()

        # If the image does not have vulnerabilities tracked, keep the list empty
        if not self.raw_result.get("Results"):
            logger.info("No vulnerabilities found in scan results.")
            return

        # Use defaultdict for automatic set creation and better performance
        vulnerability_count = 0
        skipped_count = 0

        # Process vulnerabilities directly without creating intermediate collections
        for result_content in self.raw_result["Results"]:
            vulnerabilities = result_content.get("Vulnerabilities")
            if not vulnerabilities:
                continue

            for vuln in vulnerabilities:
                vulnerability_id = vuln.get("VulnerabilityID")
                if not vulnerability_id:
                    skipped_count += 1
                    continue

                pkg_info = Package(
                    name=vuln.get("PkgName", ""), version=vuln.get("InstalledVersion", "")
                )

                if vulnerability_id not in self.processed_result:
                    self.processed_result[vulnerability_id] = set()
                self.processed_result[vulnerability_id].add(pkg_info)
                vulnerability_count += 1

        # Log processing results
        unique_vulnerabilities = len(self.processed_result)
        if unique_vulnerabilities == 0:
            logger.info("No vulnerabilities found in any result content.")
        else:
            logger.info(
                f"Processed {vulnerability_count} vulnerabilities into {unique_vulnerabilities}"
                f" unique vulnerability IDs."
            )
            if skipped_count > 0:
                logger.warning(f"Skipped {skipped_count} vulnerabilities without IDs.")

    @staticmethod
    def get_version() -> str:
        """Returns Trivy scanner version."""
        try:
            result = subprocess.run(
                ["trivy", "--version"], capture_output=True, shell=False, text=True, timeout=10
            )
            result.check_returncode()
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
            error_message = f"Failed to get Trivy version: {str(e)}"
            logger.error(error_message)
            return "unknown"
        except Exception as e:
            error_message = f"Unexpected error during Trivy version check: {e}."
            logger.error(error_message)
            return "unknown"

        version_output = result.stdout.strip().split("\n")[0]
        return version_output.split("Version: ")[1].strip()
