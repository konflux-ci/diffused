"""Registry mapping scanner names to their implementations."""

from diffused.scanners.acs import ACSScanner
from diffused.scanners.base import BaseScanner
from diffused.scanners.grype import GrypeScanner
from diffused.scanners.trivy import TrivyScanner

SCANNERS: dict[str, type[BaseScanner]] = {
    "acs": ACSScanner,
    "grype": GrypeScanner,
    "trivy": TrivyScanner,
}


def get_scanner_class(scanner: str) -> type[BaseScanner]:
    """Return the scanner class registered under the given name."""
    if scanner not in SCANNERS:
        raise ValueError(
            f"Unsupported scanner: {scanner}. Supported scanners: {list(SCANNERS.keys())}"
        )
    return SCANNERS[scanner]
