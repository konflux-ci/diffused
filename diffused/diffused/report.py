"""Single-target vulnerability scan report.

Scans a single image or SBOM and lazily exposes the scanner's results. The full,
raw scanner report is returned as-is; interpreting it (severities, advisories,
fixes, ...) is left to the caller, keeping this module scanner-agnostic.
"""

import logging
from collections import defaultdict
from typing import Optional

from diffused.scanners.base import BaseScanner
from diffused.scanners.models import Package
from diffused.scanners.registry import get_scanner_class

logger = logging.getLogger(__name__)


class ScanReport:
    """Scans a single image or SBOM and lazily exposes the scanner's results."""

    def __init__(
        self,
        image: Optional[str] = None,
        sbom: Optional[str] = None,
        scanner: str = "trivy",
        scan_type: Optional[str] = None,
    ):
        self.scanner: BaseScanner = get_scanner_class(scanner)(image=image, sbom=sbom)
        # infer the scan type from the provided target when not set explicitly
        self.scan_type: str = scan_type or ("sbom" if sbom else "image")
        self._processed: bool = False

    @property
    def image(self) -> Optional[str]:
        """Image reference being scanned, if any."""
        return self.scanner.image

    @property
    def sbom(self) -> Optional[str]:
        """SBOM path being scanned, if any."""
        return self.scanner.sbom

    def scan(self) -> None:
        """Scan the target once (no-op if already scanned); fail closed on no result.

        The already-scanned check gates on identity, not truthiness: a successful but
        empty report ({}) is a scanned result, and scanners signal "not scanned"/"failed"
        with None.
        """
        if self.scanner.raw_result is not None:
            return

        if self.scan_type == "image":
            self.scanner.scan_image()
            target = f"image {self.scanner.image}"
        elif self.scan_type == "sbom":
            self.scanner.scan_sbom()
            target = f"sbom {self.scanner.sbom}"
        else:
            raise ValueError(
                f"Unsupported scan_type: {self.scan_type}. Supported types: ['sbom', 'image']"
            )

        if self.scanner.raw_result is None:
            error_message = f"Failed to scan {target}. {self.scanner.error}"
            logger.error(error_message)
            raise RuntimeError(error_message)

    @property
    def raw_result(self) -> dict:
        """Full, raw scanner report (scans lazily on first access)."""
        self.scan()
        assert self.scanner.raw_result is not None
        return self.scanner.raw_result

    @property
    def processed_result(self) -> defaultdict[str, set[Package]]:
        """Mapping of vulnerability id to affected packages (scans/processes lazily).

        Processing gates on an explicit flag, not container truthiness, so a successful
        zero-vulnerability scan is not reprocessed on every access.
        """
        self.scan()
        if not self._processed:
            self.scanner.process_result()
            self._processed = True
        return self.scanner.processed_result

    @property
    def vulnerabilities(self) -> list[str]:
        """Sorted list of vulnerability ids found in the target."""
        return sorted(self.processed_result.keys())
