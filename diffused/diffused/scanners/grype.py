"""Grype scanner implementation."""

import json
import logging
import subprocess

from diffused.scanners.base import BaseScanner
from diffused.scanners.models import Package

logger = logging.getLogger(__name__)


class GrypeScanner(BaseScanner):
    """Grype scanner class."""

    def _run_grype_command(self, cmd: list[str], operation: str) -> subprocess.CompletedProcess:
        """Helper method to run Grype commands."""
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                shell=False,
                text=True,
                timeout=120,
            )
            result.check_returncode()
            return result
        except subprocess.CalledProcessError as e:
            error_message = f"Grype {operation} failed. Return code: {e.returncode}."
            if e.stderr:
                error_message += f" Error output: {e.stderr}"
            logger.error(error_message)
            self.error = error_message
            raise
        except subprocess.TimeoutExpired:
            error_message = f"Grype {operation} timed out."
            logger.error(error_message)
            self.error = error_message
            raise
        except Exception as e:
            error_message = f"Unexpected error during Grype {operation}: {e}."
            logger.error(error_message)
            self.error = error_message
            raise

    def scan_sbom(self) -> None:
        """Performs a scan on a given SBOM."""
        if not self.sbom:
            raise ValueError(
                "You must set the SBOM path or retrieve from a container image before scanning it."
            )

        cmd = [
            "grype",
            f"sbom:{self.sbom}",
            "-o",
            "json",
        ]

        try:
            result = self._run_grype_command(cmd, f"SBOM scan for {self.sbom}")
            self.raw_result = json.loads(result.stdout)
            logger.info("Successfully scanned SBOM %s", self.sbom)
        except json.JSONDecodeError as e:
            error_message = f"Error parsing Grype output for {self.sbom}: {e}."
            logger.error(error_message)
            self.error = error_message
        except Exception:
            pass

    def scan_image(self) -> None:
        """Performs a scan on a given image."""
        if not self.image:
            raise ValueError("You must set the image to scan.")

        cmd = [
            "grype",
            self.image,
            "-o",
            "json",
        ]

        try:
            result = self._run_grype_command(cmd, f"Image scan for {self.image}")
            self.raw_result = json.loads(result.stdout)
            logger.info("Successfully scanned image %s", self.image)
        except json.JSONDecodeError as e:
            error_message = f"Error parsing Grype output for {self.image}: {e}."
            logger.error(error_message)
            self.error = error_message
        except Exception:
            pass

    def process_result(self) -> None:
        """Processes the desired data from the given scan result."""
        if self.raw_result is None:
            raise ValueError("Run a scan before processing its output.")

        self.processed_result.clear()

        matches = self.raw_result.get("matches")
        if not matches:
            logger.info("No vulnerabilities found in scan results.")
            return

        vulnerability_count = 0
        skipped_count = 0

        for match in matches:
            vulnerability = match.get("vulnerability", {})
            vulnerability_id = vulnerability.get("id")
            if not vulnerability_id:
                skipped_count += 1
                continue

            artifact = match.get("artifact", {})
            pkg_info = Package(name=artifact.get("name", ""), version=artifact.get("version", ""))

            if vulnerability_id not in self.processed_result:
                self.processed_result[vulnerability_id] = set()
            self.processed_result[vulnerability_id].add(pkg_info)
            vulnerability_count += 1

        unique_vulnerabilities = len(self.processed_result)
        if unique_vulnerabilities == 0:
            logger.info("No vulnerabilities found in any match.")
        else:
            logger.info(
                "Processed %d vulnerabilities into %d unique vulnerability IDs.",
                vulnerability_count,
                unique_vulnerabilities,
            )
            if skipped_count > 0:
                logger.warning("Skipped %d vulnerabilities without IDs.", skipped_count)

    @staticmethod
    def get_version() -> str:
        """Returns Grype scanner version."""
        try:
            result = subprocess.run(
                ["grype", "version"], capture_output=True, shell=False, text=True, timeout=10
            )
            result.check_returncode()
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
            error_message = f"Failed to get Grype version: {str(e)}"
            logger.error(error_message)
            return "unknown"
        except Exception as e:
            error_message = f"Unexpected error during Grype version check: {e}."
            logger.error(error_message)
            return "unknown"

        for line in result.stdout.strip().split("\n"):
            if line.startswith("Version:"):
                return line.split("Version:")[1].strip()

        return "unknown"
