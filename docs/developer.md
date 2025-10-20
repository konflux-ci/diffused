# Development

We welcome contributions! Check below on how to get started.

## Development Workflow

1. **Fork the repository** and clone your fork
2. **Create a feature branch**: `git checkout -b your-feature-name`
3. **Make your changes** following our coding standards
4. **Add tests** for any new functionality
5. **Run the test suite**: `tox`
6. **Submit a pull request** with a clear description

## Coding Standards

- **Python Style**: Follow PEP 8 guidelines
- **Type Hints**: Use type annotations for all functions
- **Testing**: Maintain 100% test coverage
- **Comments**: Use lowercase first letters for inline comments
- **Tests**: Write function-based tests (not class-based)

## Structure

Diffused is built with a modular structure.

### Library Structure

```
diffused/diffused/
├── scanners/          # Scanner implementations
│   ├── base.py        # Abstract scanner interface
│   ├── acs.py         # RHACS scanner implementation
│   ├── trivy.py       # Trivy scanner implementation
│   └── models.py      # Data models (Package, etc.)
└── differ.py          # Core diffing logic
```

### CLI Structure

```
diffusedcli/diffusedcli/
└── cli.py             # CLI implementation
```

### Key Components

- **BaseScanner**: Abstract base class defining the scanner interface
- **ACSScanner**: Concrete implementation using RHACS for vulnerability scanning
- **TrivyScanner**: Concrete implementation using Trivy for vulnerability scanning
- **VulnerabilityDiffer**: Core engine for comparing vulnerability reports
- **CLI Module**: User-friendly command-line interface with rich output

## Development Setup

```bash
# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install development dependencies
pip install -e ./diffused/.[dev]
pip install -e ./diffusedcli/.[dev]
```

### Running Tests

```bash
# Run all tests
tox

# Run black only
tox -e py39-black

# Automatically fix black errors
tox -e black-format
```

## Adding New Scanners

To add support for a new vulnerability scanner:

1. Create a new scanner class inheriting from `BaseScanner`
2. Implement the required abstract methods
3. Add comprehensive unit tests
4. Update the CLI to support the new scanner
5. Add the scanner to the scanner map in `VulnerabilityDiffer._get_scanner_class()`

Example:
```python
class NewScanner(BaseScanner):
    def scan_sbom(self) -> None:
        # Scan SBOM and populate self.raw_result
        pass

    def scan_image(self) -> None:
        # Scan container image and populate self.raw_result
        pass

    def process_result(self) -> None:
        # Process self.raw_result and populate self.processed_result
        pass
```
