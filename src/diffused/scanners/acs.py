"""ACS scanner implementation."""

import json
import logging
import os
import subprocess

from diffused.scanners.base import BaseScanner
from diffused.scanners.models import Package

logger = logging.getLogger(__name__)


class ACSScanner(BaseScanner):
    """ACS scanner class."""

    def __init__(self, sbom: str | None = None, image: str | None = None):
        super().__init__(sbom, image)
        self._validate_environment()

    def _validate_environment(self) -> None:
        """Validates required environment variables are set."""
        if not os.getenv("ROX_ENDPOINT") or not os.getenv("ROX_API_TOKEN"):
            error_message = (
                "ROX_ENDPOINT and ROX_API_TOKEN must be set in the environment variables."
            )
            logger.error(error_message)
            self.error = error_message
            raise ValueError(error_message)

    def _run_acs_command(self, cmd: list[str], operation: str) -> subprocess.CompletedProcess:
        """Helper method to run ACS commands."""

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
            error_message = f"ACS {operation} failed. Return code: {e.returncode}."
            if e.stderr:
                error_message += f" Error output: {e.stderr}"
            logger.error(error_message)
            self.error = error_message
            raise
        except subprocess.TimeoutExpired:
            error_message = f"ACS {operation} timed out."
            logger.error(error_message)
            self.error = error_message
            raise
        except Exception as e:
            error_message = f"Unexpected error during ACS {operation}: {e}."
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
            "roxctl",
            "--no-color",
            "image",
            "sbom",
            "--image",
            self.image,
        ]

        try:
            result = self._run_acs_command(cmd, f"SBOM generation for {self.image}")
            parsed_output = json.loads(result.stdout)

            with open(output_file, "w") as f:
                json.dump(parsed_output, f, indent=2)

            # Set the sbom path after successful generation
            self.sbom = output_file
            logger.info(f"Successfully generated SBOM for {self.image} at {output_file}.")
        except json.JSONDecodeError as e:
            error_message = f"Error parsing SBOM output for {self.image}: {e}."
            logger.error(error_message)
            self.error = error_message
        except Exception:
            # Error already logged and stored in self.error by _run_acs_command
            pass

    def scan_sbom(self) -> None:
        """Performs a scan on a given SBOM."""
        # The ACS scanner does not support SBOM scanning yet.
        logger.warning(
            "Image %s: SBOM scanning is not supported by ACS yet. Falling back to image scanning.",
            self.image,
        )

        if not self.image:
            raise ValueError("You must set the image to scan.")

        cmd = [
            "roxctl",
            "--no-color",
            "image",
            "scan",
            "--output",
            "json",
            "--image",
            self.image,
        ]

        try:
            result = self._run_acs_command(cmd, f"Image scan for {self.image}")
            self.raw_result = json.loads(result.stdout)
            logger.info(f"Successfully scanned image {self.image}")
        except json.JSONDecodeError as e:
            error_message = f"Error parsing ACS output for {self.image}: {e}."
            logger.error(error_message)
            self.error = error_message
        except Exception:
            # Error already logged and stored in self.error by _run_acs_command
            pass

    def process_result(self) -> None:
        """Processes the desired data from the given scan result."""
        if self.raw_result is None:
            raise ValueError("Run a scan before processing its output.")

        # Clear previous results
        self.processed_result.clear()

        # If the image does not have vulnerabilities tracked, keep the list empty
        if "result" not in self.raw_result or "vulnerabilities" not in self.raw_result["result"]:
            logger.info("No vulnerabilities found in scan results.")
            return

        # Use defaultdict for automatic set creation and better performance
        vulnerability_count = 0
        skipped_count = 0

        # Process vulnerabilities directly without creating intermediate collections
        vulnerabilities = self.raw_result["result"]["vulnerabilities"]
        for vulnerability in vulnerabilities:
            vulnerability_id = vulnerability.get("cveId")
            if not vulnerability_id:
                skipped_count += 1
                continue

            pkg_info = Package(
                name=vulnerability.get("componentName", ""),
                version=vulnerability.get("componentVersion", ""),
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
                "Processed %d vulnerabilities into %d unique vulnerability IDs.",
                vulnerability_count,
                unique_vulnerabilities,
            )
            if skipped_count > 0:
                logger.warning("Skipped %d vulnerabilities without IDs.", skipped_count)

    @staticmethod
    def get_version() -> str:
        """Returns ACS scanner version."""
        try:
            result = subprocess.run(
                ["roxctl", "version"], capture_output=True, shell=False, text=True, timeout=10
            )
            result.check_returncode()
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
            error_message = f"Failed to get ACS version: {str(e)}"
            logger.error(error_message)
            return "unknown"
        except Exception as e:
            error_message = f"Unexpected error during ACS version check: {e}."
            logger.error(error_message)
            return "unknown"

        return result.stdout.strip()
