"""Scanners' base class definition."""

from abc import ABC, abstractmethod
from collections import defaultdict

from diffused.scanners.models import Package


class BaseScanner(ABC):
    """Base scanner class from which different scanner classes will be inheriting."""

    def __init__(self, sbom: str | None = None, image: str | None = None):
        if not sbom and not image:
            raise ValueError("You must set sbom or image.")

        self.sbom: str | None = sbom
        self.image: str | None = image
        self.raw_result: dict | None = None
        # processed_result is a mapping of vulnerability ids to a set of packages:
        # {"CVE-2025-1234":
        #   {Package(name="foo", version="1.2.3"), Package(name="bar", version="4.5.6")}
        # }
        self.processed_result: defaultdict[str, set[Package]] = defaultdict(set)
        self.error: str = ""

    @abstractmethod
    def retrieve_sbom(self, output_file: str) -> None:
        """Retrieves the SBOM from a given target image."""
        raise NotImplementedError()

    @abstractmethod
    def scan_sbom(self) -> None:
        """Performs a scan on a given target SBOM."""
        raise NotImplementedError()

    @abstractmethod
    def process_result(self) -> None:
        """Processes the desired data from the given scan result."""
        raise NotImplementedError()

    @staticmethod
    @abstractmethod
    def get_version() -> str:
        """Returns the version of the scanner."""
        raise NotImplementedError()
