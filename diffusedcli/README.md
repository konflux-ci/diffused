# Diffused CLI

Command-line interface for the Diffused vulnerability scanning and diffing library. This tool provides an easy-to-use interface for comparing container images and SBOMs (Software Bill of Materials) to track security improvements and regressions.

## Features

- 🔍 **Container Image Comparison**: Compare vulnerabilities between different container image versions
- 📊 **SBOM Diffing**: Direct comparison of SPDX-JSON formatted SBOMs (Trivy only)
- 📄 **Multiple Output Formats**: Support for both rich text and JSON output
- 🎨 **Rich Terminal Output**: Beautiful, colored output for better readability

## Installation

### Prerequisites

1. **Install the scanner**:
    1. **Trivy**: Follow the [official Trivy installation guide](https://aquasecurity.github.io/trivy/latest/getting-started/installation/)
    2. **RHACS**: Follow the [official roxctl installation guide](https://docs.redhat.com/en/documentation/red_hat_advanced_cluster_security_for_kubernetes/4.8/html/roxctl_cli/index) 
2. **Python Environment**: Ensure Python 3.12+ is installed

### From Source

```bash
# Install the library
pip install -e ./diffused

# Install the CLI
pip install -e ./diffusedcli
```

### From PyPI

```bash
pip install diffusedcli
```

## Usage

### Compare Container Images

```bash
# Basic vulnerability diff between two container images
diffused image-diff -p ubuntu:20.04 -n ubuntu:22.04

# Use ACS scanner
diffused --scanner acs image-diff -p nginx:1.20 -n nginx:1.21

# Get detailed information about each vulnerability
diffused image-diff -p nginx:1.20 -n nginx:1.21 --all-info

# Save output to JSON file
diffused image-diff -p app:v1.0 -n app:v2.0 --output json --file report.json
```

### Compare SBOMs

```bash
# Compare two SBOM files
diffused sbom-diff -p previous.json -n current.json

# Get detailed vulnerability information
diffused sbom-diff -p old-sbom.json -n new-sbom.json --all-info

# Export to file with rich formatting
diffused sbom-diff -p v1-sbom.json -n v2-sbom.json --file vulnerability-report.txt
```

## CLI Commands and Options

For more information on commands and options, use the `--help` option.

### Commands

| Command | Description |
|--------|-------|
| `image-diff` | Show the vulnerability diff between two container images |
| `sbom-diff` | Show the vulnerability diff between two SBOMs |

### Global Options

| Option | Short | Description | Default |
|--------|-------|-------------|---------|
| `--scanner` | `-s` | Scanner to use (`acs`, `trivy`) | `trivy` |
| `--all-info` | `-a` | Show detailed vulnerability information | `False` |
| `--output` | `-o` | Output format (`rich`, `json`) | `rich` |
| `--file` | `-f` | Output file (use `-` for stdout) | `-` |
| `--help` | `-h` | Show help message | - |

### image-diff Options

| Option | Short | Description | Required |
|--------|-------|-------------|----------|
| `--previous-image` | `-p` | Previous container image URL | Yes |
| `--next-image` | `-n` | Next container image URL | Yes |

### sbom-diff Options

| Option | Short | Description | Required |
|--------|-------|-------------|----------|
| `--previous-sbom` | `-p` | Previous SBOM file path | Yes |
| `--next-sbom` | `-n` | Next SBOM file path | Yes |
