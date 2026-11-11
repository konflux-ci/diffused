"""Scanners' base class definition."""

import os
from abc import ABC, abstractmethod
from collections import defaultdict
from typing import Optional

from diffused.scanners.models import Package

# default scan subprocess timeout in seconds. Chosen to tolerate a cold (uncached)
# scan. Overridable per scanner via the ``timeout`` argument or the
# ``DIFFUSED_SCAN_TIMEOUT`` env var.
DEFAULT_SCAN_TIMEOUT = 600

# upper bound for the scan timeout (seconds). Generous for any real scan while
# staying well clear of the overflow subprocess.run hits when ``time() + timeout``
# no longer fits a C timestamp.
MAX_SCAN_TIMEOUT = 86400

# environment variable holding the default scan timeout (seconds).
SCAN_TIMEOUT_ENV_VAR = "DIFFUSED_SCAN_TIMEOUT"


def resolve_scan_timeout(timeout: Optional[int] = None) -> int:
    """Resolve and validate the scan timeout: explicit argument, env var, then default.

    An explicit ``timeout`` always wins. Otherwise ``SCAN_TIMEOUT_ENV_VAR`` value is
    used when set, falling back to ``DEFAULT_SCAN_TIMEOUT``. The resolved value must
    be a positive integer no greater than ``MAX_SCAN_TIMEOUT``; anything else (a
    non-integer env var, zero, a negative, or an overflow-sized value) raises
    ``ValueError`` so a bad timeout fails closed with a clear message instead of a
    misleading scan timeout or an opaque ``OverflowError``.
    """
    if timeout is None:
        env_value = os.getenv(SCAN_TIMEOUT_ENV_VAR)
        if env_value is not None:
            try:
                timeout = int(env_value)
            except ValueError:
                raise ValueError(
                    f"Invalid {SCAN_TIMEOUT_ENV_VAR} value: {env_value!r}. Must be an integer."
                )
        else:
            timeout = DEFAULT_SCAN_TIMEOUT

    # bool is an int subclass, so reject it explicitly; check the type before the
    # range so a non-numeric value raises ValueError rather than a TypeError from
    # the comparison.
    if (
        isinstance(timeout, bool)
        or not isinstance(timeout, int)
        or not 0 < timeout <= MAX_SCAN_TIMEOUT
    ):
        raise ValueError(
            f"Scan timeout must be a positive integer no greater than "
            f"{MAX_SCAN_TIMEOUT} seconds, got {timeout!r}."
        )

    return timeout


class BaseScanner(ABC):
    """Base scanner class from which different scanner classes will be inheriting."""

    def __init__(
        self,
        sbom: Optional[str] = None,
        image: Optional[str] = None,
        timeout: Optional[int] = None,
    ):
        """Initialize the scanner with a target and an optional scan timeout.

        The ``timeout`` (seconds) is resolved via ``resolve_scan_timeout``: the
        explicit argument if given, else ``DIFFUSED_SCAN_TIMEOUT``, else the default.
        It must be an ``int``; a ``bool`` is rejected despite being an ``int`` subclass.

        Raises:
            ValueError: if neither ``sbom`` nor ``image`` is set, or if the resolved
                timeout is not a positive integer no greater than ``MAX_SCAN_TIMEOUT``.
        """
        if not sbom and not image:
            raise ValueError("You must set sbom or image.")

        self.sbom: Optional[str] = sbom
        self.image: Optional[str] = image
        # scan subprocess timeout (seconds); single source of truth for all scanners.
        self.timeout: int = resolve_scan_timeout(timeout)
        self.raw_result: Optional[dict] = None
        # processed_result is a mapping of vulnerability ids to a set of packages:
        # {"CVE-2025-1234":
        #   {Package(name="foo", version="1.2.3"), Package(name="bar", version="4.5.6")}
        # }
        self.processed_result: defaultdict[str, set[Package]] = defaultdict(set)
        self.error: str = ""

    @abstractmethod
    def scan_sbom(self) -> None:
        """Performs a scan on a given target SBOM."""
        raise NotImplementedError()

    @abstractmethod
    def scan_image(self) -> None:
        """Performs a scan on a given target image."""
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
