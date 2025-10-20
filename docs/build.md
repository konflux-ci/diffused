# Build Process

This document describes how to build the Diffused Library and CLI packages.

## Package Overview

Diffused is distributed as two separate PyPI packages:

- **`diffused`** - Core library providing vulnerability scanning and diffing functionality
- **`diffusedcli`** - Command-line interface that depends on the diffused library

## Prerequisites

Install the required build tools:

```bash
pip install build hatchling
```

## Building the Packages

### Building Both Packages

Build both packages from the root directory:

```bash
# Build the library first
cd diffused
python -m build
cd ..

# Build the CLI
cd diffusedcli
python -m build
cd ..
```

### Building Individual Packages

#### Library Package

```bash
cd diffused
python -m build
```

This creates distribution files in `diffused/dist/`:
- `diffused_lib-0.1.0.tar.gz` (source distribution)
- `diffused_lib-0.1.0-py3-none-any.whl` (wheel distribution)

#### CLI Package

```bash
cd diffusedcli
python -m build
```

This creates distribution files in `diffusedcli/dist/`:
- `diffusedcli-0.1.0.tar.gz` (source distribution)
- `diffusedcli-0.1.0-py3-none-any.whl` (wheel distribution)

## Clean Builds

Before building new versions, clean previous builds:

```bash
# Clean library build artifacts
rm -rf diffused/dist/ diffused/build/

# Clean CLI build artifacts
rm -rf diffusedcli/dist/ diffusedcli/build/

# Clean all at once
rm -rf */dist/ */build/
```

## Package Contents

### Library Package (`diffused`)

The library package includes:
- Core vulnerability scanning functionality
- SBOM and image diffing capabilities
- Support for multiple scanners (Trivy, RHACS)
- Python API for programmatic access

### CLI Package (`diffusedcli`)

The CLI package includes:
- Command-line interface (`diffused` command)
- Rich terminal output formatting
- JSON and text output formats
- Dependency on the `diffused` library

## Development Installation

For development, install both packages in editable mode:

```bash
# Install library in development mode
pip install -e ./diffused

# Install CLI in development mode (includes library dependency)
pip install -e ./diffusedcli
```

## Important Notes

- **Python Version**: Both packages require Python >=3.9
- **License**: Apache-2.0
- **Build Backend**: Both packages use hatchling for building
- **Dependencies**: CLI package automatically installs the library package
- **Source Locations**:
  - Library: `diffused/diffused/`
  - CLI: `diffusedcli/diffusedcli/`
