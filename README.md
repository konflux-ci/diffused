# Diffused

A vulnerability scan diffing tool for container images and SBOMs (Software Bill of Materials). Diffused helps track security improvements and regressions between different versions of container images by comparing vulnerability scan results from SBOMs.

Its name comes from the pun `diff + used`, which means it performs the diffing of both results.

## Project Structure

This project is split into two main components:

- **[diffused/](./diffused/)** - Core library providing vulnerability scanning and diffing functionality
- **[diffusedcli/](./diffusedcli/)** - Command-line interface for the diffused library

## Features

- 🔍 **Vulnerability Scanning**: Automated scanning of SBOMs using [Trivy](https://trivy.dev/) (default) or scanning of container images using [RHACS](https://www.redhat.com/pt-br/technologies/cloud-computing/openshift/advanced-cluster-security-kubernetes)
- 📊 **SBOM Diffing**: Direct comparison of SPDX-JSON formatted SBOMs (Trivy only)
- 📄 **Multiple Output Formats**: Support for both rich text and JSON output

## Quick Start

### Prerequisites

1. **Install the scanner**:
    1. **Trivy**: Follow the [official Trivy installation guide](https://aquasecurity.github.io/trivy/latest/getting-started/installation/)
    2. **RHACS**: Follow the [official roxctl installation guide](https://docs.redhat.com/en/documentation/red_hat_advanced_cluster_security_for_kubernetes/4.8/html/roxctl_cli/index) 
2. **Python Environment**: Ensure Python 3.12+ is installed

### Installation

#### Library

```bash
# Install the library
pip install ./diffused

# Use in Python code
from diffused.differ import VulnerabilityDiffer
```

#### CLI Tool

```bash
# Install the CLI tool
pip install ./diffusedcli

# Basic usage
diffused image-diff -p ubuntu:20.04 -n ubuntu:22.04
```

## Components

### Library ([diffused/](./diffused/))

The core library provides programmatic access to vulnerability scanning and diffing functionality. See [diffused/README.md](./diffused/README.md) for detailed library documentation.

### CLI ([diffusedcli/](./diffusedcli/))

The command-line interface provides an easy-to-use tool for comparing container images and SBOMs. See [diffusedcli/README.md](./diffusedcli/README.md) for detailed CLI documentation and usage examples.

## Contributing

We welcome contributions! Refer to the [developer](./docs/developer.md) guide for instructions on getting started.

## Documentation

The documentation for the Diffused project is available in the [docs](/docs/) folder.

## License

Copyright 2025.

Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions and limitations under the License.
