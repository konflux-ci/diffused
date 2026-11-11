"""Simple unit tests for BaseScanner abstract class."""

from collections import defaultdict
from unittest.mock import patch

import pytest

from diffused.scanners.base import (
    DEFAULT_SCAN_TIMEOUT,
    MAX_SCAN_TIMEOUT,
    SCAN_TIMEOUT_ENV_VAR,
    BaseScanner,
    resolve_scan_timeout,
)
from diffused.scanners.models import Package


class ScannerClassTest(BaseScanner):
    """Test implementation of BaseScanner."""

    def scan_sbom(self) -> None:
        """Test implementation."""
        pass

    def scan_image(self) -> None:
        """Test implementation."""
        pass

    def process_result(self) -> None:
        """Test implementation."""
        pass

    @staticmethod
    def get_version() -> str:
        """Test implementation."""
        return "1.0.0"


class SuperCallScanner(BaseScanner):
    """Test implementation that calls super methods to trigger NotImplementedError."""

    def scan_sbom(self) -> None:
        """Implementation that calls super to trigger NotImplementedError."""
        super().scan_sbom()

    def scan_image(self) -> None:
        """Implementation that calls super to trigger NotImplementedError."""
        super().scan_image()

    def process_result(self) -> None:
        """Implementation that calls super to trigger NotImplementedError."""
        super().process_result()

    @staticmethod
    def get_version() -> str:
        """Implementation that calls super to trigger NotImplementedError."""
        return BaseScanner.get_version()


def test_init_with_sbom(test_sbom_path):
    """Test initialization with SBOM."""
    scanner = ScannerClassTest(sbom=test_sbom_path)
    assert scanner.sbom == test_sbom_path
    assert scanner.image is None


def test_init_with_image(test_image):
    """Test initialization with image."""
    scanner = ScannerClassTest(image=test_image)
    assert scanner.image == test_image
    assert scanner.sbom is None


def test_init_with_both(test_sbom_path, test_image):
    """Test initialization with both sbom and image."""
    scanner = ScannerClassTest(sbom=test_sbom_path, image=test_image)
    assert scanner.sbom == test_sbom_path
    assert scanner.image == test_image


def test_init_without_parameters_raises_error():
    """Test initialization fails without parameters."""
    with pytest.raises(ValueError, match="You must set sbom or image"):
        ScannerClassTest()


def test_init_with_empty_strings_raises_error():
    """Test initialization fails with empty strings."""
    with pytest.raises(ValueError, match="You must set sbom or image"):
        ScannerClassTest(sbom="", image="")


def test_default_attributes(test_sbom_path):
    """Test default attribute values."""
    scanner = ScannerClassTest(sbom=test_sbom_path)
    assert scanner.raw_result is None
    assert isinstance(scanner.processed_result, defaultdict)
    assert scanner.error == ""


def test_default_timeout(test_sbom_path):
    """Test the scanner defaults to DEFAULT_SCAN_TIMEOUT when no timeout is set.

    The autouse clear_scan_timeout_env fixture guarantees DIFFUSED_SCAN_TIMEOUT is unset.
    """
    scanner = ScannerClassTest(sbom=test_sbom_path)
    assert scanner.timeout == DEFAULT_SCAN_TIMEOUT
    assert DEFAULT_SCAN_TIMEOUT > 120


def test_explicit_timeout_override(test_sbom_path):
    """Test an explicit timeout argument is used verbatim."""
    scanner = ScannerClassTest(sbom=test_sbom_path, timeout=42)
    assert scanner.timeout == 42


def test_timeout_from_env_var(test_sbom_path):
    """Test the timeout falls back to DIFFUSED_SCAN_TIMEOUT when set."""
    with patch.dict("os.environ", {SCAN_TIMEOUT_ENV_VAR: "300"}):
        scanner = ScannerClassTest(sbom=test_sbom_path)
    assert scanner.timeout == 300


def test_explicit_timeout_overrides_env_var(test_sbom_path):
    """Test an explicit timeout argument wins over the env var."""
    with patch.dict("os.environ", {SCAN_TIMEOUT_ENV_VAR: "300"}):
        scanner = ScannerClassTest(sbom=test_sbom_path, timeout=42)
    assert scanner.timeout == 42


def test_invalid_env_var_raises(test_sbom_path):
    """Test a non-integer env var fails closed with a clear error."""
    with patch.dict("os.environ", {SCAN_TIMEOUT_ENV_VAR: "not-a-number"}):
        with pytest.raises(ValueError, match=SCAN_TIMEOUT_ENV_VAR):
            ScannerClassTest(sbom=test_sbom_path)


def test_resolve_scan_timeout_precedence():
    """Test resolve_scan_timeout honors argument > env var > default precedence."""
    with patch.dict("os.environ", {SCAN_TIMEOUT_ENV_VAR: "300"}):
        assert resolve_scan_timeout(42) == 42
        assert resolve_scan_timeout() == 300
    # the autouse fixture guarantees the env var is unset outside the patched block
    assert resolve_scan_timeout() == DEFAULT_SCAN_TIMEOUT


@pytest.mark.parametrize("bad_timeout", [0, -1, MAX_SCAN_TIMEOUT + 1])
def test_explicit_timeout_out_of_range_raises(test_sbom_path, bad_timeout):
    """Test a non-positive or overflow-sized explicit timeout fails closed."""
    with pytest.raises(ValueError, match="positive integer"):
        ScannerClassTest(sbom=test_sbom_path, timeout=bad_timeout)


@pytest.mark.parametrize("bad_value", ["0", "-5", str(MAX_SCAN_TIMEOUT + 1)])
def test_env_var_out_of_range_raises(test_sbom_path, bad_value):
    """Test a non-positive or overflow-sized env var timeout fails closed."""
    with patch.dict("os.environ", {SCAN_TIMEOUT_ENV_VAR: bad_value}):
        with pytest.raises(ValueError, match="positive integer"):
            ScannerClassTest(sbom=test_sbom_path)


def test_max_timeout_is_accepted(test_sbom_path):
    """Test the upper bound itself is a valid timeout."""
    scanner = ScannerClassTest(sbom=test_sbom_path, timeout=MAX_SCAN_TIMEOUT)
    assert scanner.timeout == MAX_SCAN_TIMEOUT


@pytest.mark.parametrize("bad_timeout", [1.5, True, "600"])
def test_non_integer_timeout_raises(test_sbom_path, bad_timeout):
    """Test a non-integer explicit timeout (float, bool, str) fails closed with ValueError.

    bool is an int subclass and str would raise a TypeError on the range comparison, so
    both must be rejected with the documented ValueError like any other invalid value.
    """
    with pytest.raises(ValueError, match="positive integer"):
        ScannerClassTest(sbom=test_sbom_path, timeout=bad_timeout)


def test_processed_result_defaultdict_behavior(test_sbom_path):
    """Test processed_result creates sets automatically."""
    scanner = ScannerClassTest(sbom=test_sbom_path)

    # Accessing non-existent key creates empty set
    test_set = scanner.processed_result["CVE-2023-1234"]
    assert isinstance(test_set, set)
    assert len(test_set) == 0


def test_processed_result_stores_packages(test_sbom_path):
    """Test processed_result can store Package objects."""
    scanner = ScannerClassTest(sbom=test_sbom_path)

    pkg = Package(name="test-package", version="1.0.0")
    scanner.processed_result["CVE-2023-1234"].add(pkg)

    assert len(scanner.processed_result["CVE-2023-1234"]) == 1
    assert pkg in scanner.processed_result["CVE-2023-1234"]


def test_cannot_instantiate_abstract_class(test_sbom_path):
    """Test BaseScanner cannot be instantiated directly."""
    with pytest.raises(TypeError):
        BaseScanner(sbom=test_sbom_path)


def test_all_abstract_methods_implemented(test_sbom_path):
    """Test all abstract methods are implemented."""
    scanner = ScannerClassTest(sbom=test_sbom_path)

    # Should not raise NotImplementedError
    scanner.scan_sbom()
    scanner.scan_image()
    scanner.process_result()
    version = scanner.get_version()

    assert version == "1.0.0"


def test_abstract_methods_required(test_sbom_path):
    """Test that all abstract methods must be implemented."""

    class IncompleteScanner(BaseScanner):
        def scan_sbom(self) -> None:
            pass

        # Missing other abstract methods

    with pytest.raises(TypeError):
        IncompleteScanner(sbom=test_sbom_path)


def test_scan_sbom_not_implemented_error(test_sbom_path):
    """Test scan_sbom raises NotImplementedError when calling super."""
    scanner = SuperCallScanner(sbom=test_sbom_path)
    with pytest.raises(NotImplementedError):
        scanner.scan_sbom()


def test_scan_image_not_implemented_error(test_image):
    """Test scan_image raises NotImplementedError when calling super."""
    scanner = SuperCallScanner(image=test_image)
    with pytest.raises(NotImplementedError):
        scanner.scan_image()


def test_process_result_not_implemented_error(test_sbom_path):
    """Test process_result raises NotImplementedError when calling super."""
    scanner = SuperCallScanner(sbom=test_sbom_path)
    with pytest.raises(NotImplementedError):
        scanner.process_result()


def test_get_version_not_implemented_error():
    """Test get_version raises NotImplementedError when calling super."""
    with pytest.raises(NotImplementedError):
        SuperCallScanner.get_version()


def test_error_attribute_assignment(test_sbom_path):
    """Test error attribute can be set and retrieved."""
    scanner = ScannerClassTest(sbom=test_sbom_path)

    error_message = "Test error"
    scanner.error = error_message

    assert scanner.error == error_message


def test_raw_result_assignment(test_sbom_path):
    """Test raw_result can be assigned."""
    scanner = ScannerClassTest(sbom=test_sbom_path)

    test_data = {"Results": []}
    scanner.raw_result = test_data

    assert scanner.raw_result == test_data
