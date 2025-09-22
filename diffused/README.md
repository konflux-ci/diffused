# Diffused Library

The core Python library providing vulnerability scanning and diffing functionality for container images and SBOMs (Software Bill of Materials). This library enables programmatic access to vulnerability analysis capabilities.

## Features

- 🔍 **Vulnerability Scanning**: Automated scanning of SBOMs using [Trivy](https://trivy.dev/) or scanning of container images using [RHACS](https://www.redhat.com/pt-br/technologies/cloud-computing/openshift/advanced-cluster-security-kubernetes)
- 📊 **SBOM Diffing**: Direct comparison of SPDX-JSON formatted SBOMs (Trivy only)
- 📄 **Flexible Output**: Programmatic access to vulnerability data
- 🐍 **Python API**: Clean, intuitive Python interface

## Installation

### Prerequisites

1. **Install the scanner**:
    1. **Trivy**: Follow the [official Trivy installation guide](https://aquasecurity.github.io/trivy/latest/getting-started/installation/)
    2. **RHACS**: Follow the [official roxctl installation guide](https://docs.redhat.com/en/documentation/red_hat_advanced_cluster_security_for_kubernetes/4.8/html/roxctl_cli/index) 
2. **Python Environment**: Ensure Python 3.12+ is installed

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

```python
from diffused.differ import VulnerabilityDiffer

# Create a differ instance
vuln_differ = VulnerabilityDiffer(previous_image="ubuntu:20.04", next_image="ubuntu:22.04")

# Retrieve the vulnerabilities diff
vuln_differ.vulnerabilities_diff
```
