"""Simple unit tests for BaseScanner abstract class."""

from collections import defaultdict

import pytest

from diffused.scanners.base import BaseScanner
from diffused.scanners.models import Package


class ScannerClassTest(BaseScanner):
    """Test implementation of BaseScanner."""

    def retrieve_sbom(self, output_file: str) -> None:
        """Test implementation."""
        pass

    def scan_sbom(self) -> None:
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

    def retrieve_sbom(self, output_file: str) -> None:
        """Implementation that calls super to trigger NotImplementedError."""
        super().retrieve_sbom(output_file)

    def scan_sbom(self) -> None:
        """Implementation that calls super to trigger NotImplementedError."""
        super().scan_sbom()

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


def test_all_abstract_methods_implemented(test_sbom_path, test_output_path):
    """Test all abstract methods are implemented."""
    scanner = ScannerClassTest(sbom=test_sbom_path)

    # Should not raise NotImplementedError
    scanner.retrieve_sbom(test_output_path)
    scanner.scan_sbom()
    scanner.process_result()
    version = scanner.get_version()

    assert version == "1.0.0"


def test_abstract_methods_required(test_sbom_path):
    """Test that all abstract methods must be implemented."""

    class IncompleteScanner(BaseScanner):
        def retrieve_sbom(self, output_file: str) -> None:
            pass

        # Missing other abstract methods

    with pytest.raises(TypeError):
        IncompleteScanner(sbom=test_sbom_path)


def test_retrieve_sbom_not_implemented_error(test_sbom_path, test_output_path):
    """Test retrieve_sbom raises NotImplementedError when calling super."""
    scanner = SuperCallScanner(sbom=test_sbom_path)
    with pytest.raises(NotImplementedError):
        scanner.retrieve_sbom(test_output_path)


def test_scan_sbom_not_implemented_error(test_sbom_path):
    """Test scan_sbom raises NotImplementedError when calling super."""
    scanner = SuperCallScanner(sbom=test_sbom_path)
    with pytest.raises(NotImplementedError):
        scanner.scan_sbom()


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
