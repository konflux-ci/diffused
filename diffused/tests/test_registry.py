"""Unit tests for the scanner registry."""

import pytest

from diffused.scanners.acs import ACSScanner
from diffused.scanners.grype import GrypeScanner
from diffused.scanners.registry import get_scanner_class
from diffused.scanners.trivy import TrivyScanner


@pytest.mark.parametrize(
    "name, expected",
    [
        ("acs", ACSScanner),
        ("grype", GrypeScanner),
        ("trivy", TrivyScanner),
    ],
)
def test_get_scanner_class_returns_registered_class(name, expected):
    """Each registered name resolves to its scanner class."""
    assert get_scanner_class(name) is expected


def test_get_scanner_class_unsupported():
    """An unknown scanner name raises a descriptive ValueError."""
    with pytest.raises(ValueError, match="Unsupported scanner: nope"):
        get_scanner_class("nope")
