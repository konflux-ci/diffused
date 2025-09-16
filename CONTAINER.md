# Container Usage Guide

This document provides comprehensive instructions for building and using Diffused as a container image.

## Quick Start

### Build the Container

The build script automatically detects your container manager (podman or docker) and uses it for building:

```bash
# Build with Trivy scanner (default) - auto-detects container manager
./build-container.sh

# Build with Trivy scanner
./build-container.sh --scanner trivy

# Build with all scanners
./build-container.sh --scanner all

# Force specific container manager
./build-container.sh --container-manager docker
./build-container.sh --container-manager podman
```

### Run Container Examples

Replace `podman` with `docker` if you're using Docker:

```bash
# Compare two container images using ACS scanner (requires credentials)
podman run --rm \
  -e ROX_ENDPOINT=$ROX_ENDPOINT \
  -e ROX_API_TOKEN=$ROX_API_TOKEN \
  diffused:latest image-diff -p ubuntu:20.04 -n ubuntu:22.04

# Compare SBOM files (mount local directory)
podman run --rm \
  -v $(pwd):/data \
  diffused:latest sbom-diff -p /data/old.json -n /data/new.json
```

## Build Options

### Scanner Selection

The container can be built with different scanner configurations:

| Scanner | Description | Binary Source |
|---------|-------------|---------------|
| `acs` | ACS REST API scanner | https://mirror.openshift.com/pub/rhacs/assets/latest/bin/Linux/ |
| `trivy` | Trivy vulnerability scanner (default) | https://github.com/aquasecurity/trivy/releases |
| `all` | All available scanners included | All sources |

### Build Arguments

| Argument | Default | Description |
|----------|---------|-------------|
| `SCANNER` | `trivy` | Scanner type: `acs`, `trivy`, or `all` |
| `ACS_VERSION` | `latest` | ACS version to download |
| `TRIVY_VERSION` | `latest` | Trivy version to download |

### Build Examples

```bash
# Build with specific ACS version
./build-container.sh --scanner acs --acs-version 4.4.0

# Build with specific Trivy version
./build-container.sh --scanner trivy --trivy-version 0.48.0

# Build with all scanners and custom tag
./build-container.sh --scanner all --tag myregistry/diffused:v1.0

# Build with Docker specifically
./build-container.sh --container-manager docker --scanner all

# Manual build with auto-detected container manager
$(command -v podman docker | head -n1) build \
  --build-arg SCANNER=all \
  --build-arg ACS_VERSION=4.4.0 \
  --build-arg TRIVY_VERSION=0.48.0 \
  -t diffused:custom \
  -f Containerfile .
```

### Container Manager Detection

The build script automatically detects and uses the available container manager in this order:

1. **Podman** (preferred)
2. **Docker** (fallback)

You can override the detection by using the `--container-manager` option. The script will validate that your specified container manager is installed and available in your PATH.

## Runtime Configuration

### Environment Variables

#### ACS Scanner Requirements
When using the ACS scanner, these environment variables are required:

- `ROX_ENDPOINT`: ACS Central endpoint URL
- `ROX_API_TOKEN`: ACS API authentication token

To create the `ROX_API_TOKEN`, follow the instructions [here](https://docs.redhat.com/en/documentation/red_hat_advanced_cluster_security_for_kubernetes/4.8/html/roxctl_cli/using-the-roxctl-cli-1#create-api-token_using-roxctl-cli).

#### Optional Variables
- `SCANNER_TYPE`: Override default scanner type at runtime
- `PYTHONUNBUFFERED=1`: Already set in container for better logging

### Volume Mounts

Mount local directories to work with local SBOM files:

```bash
# Mount current directory
podman run --rm -v $(pwd):/data diffused:latest sbom-diff -p /data/file1.json -n /data/file2.json

# Mount specific directory
podman run --rm -v /path/to/sboms:/sboms diffused:latest sbom-diff -p /sboms/old.json -n /sboms/new.json

# Mount output directory for saving results
podman run --rm -v $(pwd)/output:/app/output diffused:latest image-diff -p app:v1 -n app:v2 -f /app/output/report.json
```

## Usage Examples

### Image Vulnerability Comparison

```bash
# Basic image diff with rich output
podman run --rm \
  -e ROX_ENDPOINT=$ROX_ENDPOINT \
  -e ROX_API_TOKEN=$ROX_API_TOKEN \
  diffused:latest image-diff -p nginx:1.20 -n nginx:1.21

# Detailed vulnerability information
podman run --rm \
  -e ROX_ENDPOINT=$ROX_ENDPOINT \
  -e ROX_API_TOKEN=$ROX_API_TOKEN \
  diffused:latest image-diff -p app:v1.0 -n app:v2.0 --all-info

# Save results to JSON file
podman run --rm \
  -v $(pwd)/output:/app/output \
  -e ROX_ENDPOINT=$ROX_ENDPOINT \
  -e ROX_API_TOKEN=$ROX_API_TOKEN \
  diffused:latest image-diff -p app:v1 -n app:v2 --output json -f /app/output/report.json
```

### SBOM Comparison

```bash
# Compare local SBOM files
podman run --rm \
  -v $(pwd):/data \
  diffused:latest sbom-diff -p /data/previous.json -n /data/current.json

# Detailed SBOM diff with JSON output
podman run --rm \
  -v $(pwd):/data \
  -v $(pwd)/output:/app/output \
  diffused:latest sbom-diff -p /data/old.json -n /data/new.json --all-info --output json -f /app/output/diff.json
```

### Scanner Selection at Runtime

```bash
# Use Trivy scanner (if included in build)
podman run --rm diffused:latest image-diff -p ubuntu:20.04 -n ubuntu:22.04 --scanner trivy

# Use ACS scanner explicitly
podman run --rm \
  -e ROX_ENDPOINT=$ROX_ENDPOINT \
  -e ROX_API_TOKEN=$ROX_API_TOKEN \
  diffused:latest image-diff -p ubuntu:20.04 -n ubuntu:22.04 --scanner acs
```

## SELinux Systems

On SELinux systems (Fedora, RHEL, CentOS), add `:z` to volume mounts:

```bash
podman run --rm -v $(pwd):/data:z diffused:latest sbom-diff -p /data/file1.json -n /data/file2.json
```

## Troubleshooting

### Common Issues

1. **ACS Authentication Errors**
   ```
   Error: ROX_ENDPOINT and ROX_API_TOKEN must be set
   ```
   Solution: Ensure both environment variables are set when using ACS scanner.

2. **Container Manager Not Found**
   ```
   Error: No supported container manager found. Please install podman or docker.
   ```
   Solution: Install either Podman or Docker on your system.

3. **Scanner Not Found**
   ```
   Error: Command 'roxctl' not found
   ```
   Solution: Rebuild container with the required scanner using `--scanner` build argument.

4. **Permission Errors with Volume Mounts**
   ```
   Error: Permission denied writing to /app/output
   ```
   Solution: Ensure mounted directories have proper permissions or use `--user` flag:
   ```bash
   podman run --rm --user $(id -u):$(id -g) -v $(pwd):/data diffused:latest ...
   ```

### Manual Health Check

You can manually verify the container is working correctly:

```bash
# Check container health
podman run --rm diffused:latest python3.12 -c "import diffused; print('OK')"
```

### Interactive Debugging

```bash
# Run container interactively for debugging
podman run --rm -it --entrypoint /bin/bash diffused:latest

# Check installed scanners
which roxctl trivy

# Test scanner versions
roxctl version
trivy --version
```

## Security Considerations

- The container runs as a non-root user (`diffused`) for enhanced security
- Use secrets management for ACS credentials instead of environment variables in production
- Consider using read-only root filesystem when possible
- Scan the built container images for vulnerabilities before deployment

## Integration Examples

### CI/CD Pipeline (GitLab CI)

```yaml
vulnerability-diff:
  stage: security
  image: docker:latest
  services:
    - docker:dind
  script:
    - docker run --rm
        -e ROX_ENDPOINT=$ROX_ENDPOINT
        -e ROX_API_TOKEN=$ROX_API_TOKEN
        diffused:latest image-diff
        -p $CI_REGISTRY_IMAGE:$CI_COMMIT_BEFORE_SHA
        -n $CI_REGISTRY_IMAGE:$CI_COMMIT_SHA
        --output json --file /dev/stdout > vulnerability-diff.json
  artifacts:
    reports:
      junit: vulnerability-diff.json
```

### Kubernetes Job

```yaml
apiVersion: batch/v1
kind: Job
metadata:
  name: diffused-scan
spec:
  template:
    spec:
      containers:
      - name: diffused
        image: diffused:latest
        env:
        - name: ROX_ENDPOINT
          valueFrom:
            secretKeyRef:
              name: acs-credentials
              key: endpoint
        - name: ROX_API_TOKEN
          valueFrom:
            secretKeyRef:
              name: acs-credentials
              key: token
        args: ["image-diff", "-p", "app:v1.0", "-n", "app:v2.0"]
      restartPolicy: Never
```
