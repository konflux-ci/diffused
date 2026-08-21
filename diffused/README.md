# Diffused Library

The core Python library providing vulnerability scanning and diffing functionality for container images and SBOMs (Software Bill of Materials). This library enables programmatic access to vulnerability analysis capabilities.

## Features

- 🔍 **Vulnerability Scanning**: Automated scanning of SBOMs using [Trivy](https://trivy.dev/) or scanning of container images using [RHACS](https://www.redhat.com/pt-br/technologies/cloud-computing/openshift/advanced-cluster-security-kubernetes)
- 🔀 **Fixed & New Vulnerability Detection**: Reports both vulnerabilities fixed and vulnerabilities newly introduced between two versions
- 📊 **SBOM Diffing**: Direct comparison of SPDX-JSON formatted SBOMs (Trivy only)
- 📄 **Flexible Output**: Programmatic access to vulnerability data
- 🐍 **Python API**: Clean, intuitive Python interface

## Installation

### Prerequisites

1. **Install the scanner**:
    1. **Trivy**: Follow the [official Trivy installation guide](https://aquasecurity.github.io/trivy/latest/getting-started/installation/)
    2. **RHACS**: Follow the [official roxctl installation guide](https://docs.redhat.com/en/documentation/red_hat_advanced_cluster_security_for_kubernetes/4.8/html/roxctl_cli/index)
2. **Python Environment**: Ensure Python 3.9+ is installed

### From Source

```bash
cd diffused
pip install -e .
```

### From PyPI

```bash
pip install diffused-lib
```

## Usage

### Basic Library Usage

#### Comparing Container Images

```python
from diffused.differ import VulnerabilityDiffer

# Create a differ instance for container images
vuln_differ = VulnerabilityDiffer(
    previous_image="ubuntu:20.04",
    next_image="ubuntu:22.04",
    scan_type="image"  # Automatically scans images
)

# Retrieve the vulnerabilities diff (list of fixed CVEs)
fixed_vulnerabilities = vuln_differ.vulnerabilities_diff
print(f"Fixed vulnerabilities: {fixed_vulnerabilities}")

# Get detailed information about each fixed vulnerability
detailed_info = vuln_differ.vulnerabilities_diff_all_info

# Retrieve the vulnerabilities introduced in the next image (list of new CVEs)
new_vulnerabilities = vuln_differ.new_vulnerabilities
print(f"New vulnerabilities: {new_vulnerabilities}")

# Get detailed information about each new vulnerability
new_detailed_info = vuln_differ.new_vulnerabilities_all_info
```

#### Comparing SBOMs

```python
from diffused.differ import VulnerabilityDiffer

# Create a differ instance for SBOMs
vuln_differ = VulnerabilityDiffer(
    previous_sbom="previous.sbom.json",
    next_sbom="current.sbom.json",
    scan_type="sbom"  # Automatically scans SBOMs
)

# Retrieve the vulnerabilities diff
fixed_vulnerabilities = vuln_differ.vulnerabilities_diff
```

#### Using Different Scanners

```python
from diffused.differ import VulnerabilityDiffer

# Use Trivy scanner (default)
trivy_differ = VulnerabilityDiffer(
    previous_image="nginx:1.20",
    next_image="nginx:1.21",
    scanner="trivy",
    scan_type="image"
)

# Use ACS scanner (requires ROX_ENDPOINT and either ROX_API_TOKEN or ROX_CONFIG_DIR)
acs_differ = VulnerabilityDiffer(
    previous_image="nginx:1.20",
    next_image="nginx:1.21",
    scanner="acs",
    scan_type="image"
)
```
