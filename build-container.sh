#!/bin/bash
# Build script for Diffused container images

set -e

# Default values
SCANNER="trivy"
TAG="diffused:latest"
ACS_VERSION="latest"
TRIVY_VERSION="latest"
CONTAINER_MANAGER=""

# Help function
show_help() {
    cat << EOF
Build script for Diffused container image

Usage: $0 [OPTIONS]

Options:
    -s, --scanner SCANNER    Scanner to include: acs, trivy, or all (default: trivy)
    -t, --tag TAG            Container image tag (default: diffused:latest)
    -c, --container-manager  Container manager to use: podman, docker (auto-detected if not specified)
    --acs-version VERSION    ACS version to download (default: latest)
    --trivy-version VERSION  Trivy version to download (default: latest)
    -h, --help               Show this help message

Examples:
    # Build with Trivy scanner only (default)
    $0

    # Build with specific ACS version
    $0 --acs-version 4.4.0

    # Build with Trivy scanner only
    $0 --scanner trivy

    # Build with all scanners
    $0 --scanner all

    # Build with custom tag
    $0 --tag myregistry/diffused:v1.0

    # Use specific container manager
    $0 --container-manager docker
EOF
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -s|--scanner)
            SCANNER="$2"
            shift 2
            ;;
        -t|--tag)
            TAG="$2"
            shift 2
            ;;
        -c|--container-manager)
            CONTAINER_MANAGER="$2"
            shift 2
            ;;
        --acs-version)
            ACS_VERSION="$2"
            shift 2
            ;;
        --trivy-version)
            TRIVY_VERSION="$2"
            shift 2
            ;;
        -h|--help)
            show_help
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            show_help
            exit 1
            ;;
    esac
done

# Function to detect available container managers
detect_container_manager() {
    local managers=("podman" "docker")

    for manager in "${managers[@]}"; do
        if command -v "$manager" &> /dev/null; then
            echo "$manager"
            return 0
        fi
    done

    echo "Error: No supported container manager found. Please install podman or docker." >&2
    exit 1
}

# Validate and set container manager
if [[ -n "$CONTAINER_MANAGER" ]]; then
    # User specified a container manager, validate it
    if [[ ! "$CONTAINER_MANAGER" =~ ^(podman|docker)$ ]]; then
        echo "Error: Container manager must be 'podman' or 'docker'"
        exit 1
    fi

    # Check if the specified manager is available
    if ! command -v "$CONTAINER_MANAGER" &> /dev/null; then
        echo "Error: $CONTAINER_MANAGER is not installed or not in PATH"
        exit 1
    fi
else
    # Auto-detect container manager
    CONTAINER_MANAGER=$(detect_container_manager)
fi

# Validate scanner option
if [[ ! "$SCANNER" =~ ^(acs|trivy|all)$ ]]; then
    echo "Error: Scanner must be 'acs', 'trivy', or 'all'"
    exit 1
fi

echo "Building Diffused container image..."
echo "Container Manager: $CONTAINER_MANAGER"
echo "Scanner: $SCANNER"
echo "Tag: $TAG"
echo "ACS Version: $ACS_VERSION"
echo "Trivy Version: $TRIVY_VERSION"
echo

# Build the container image
$CONTAINER_MANAGER build \
    --build-arg SCANNER="$SCANNER" \
    --build-arg ACS_VERSION="$ACS_VERSION" \
    --build-arg TRIVY_VERSION="$TRIVY_VERSION" \
    -t "$TAG" \
    -f Containerfile \
    .

echo
echo "Container image built successfully: $TAG"
echo

# Show usage examples
echo "Usage examples:"
echo
case $SCANNER in
    acs)
        echo "# Set ACS credentials and run image diff:"
        echo "$CONTAINER_MANAGER run --rm -e ROX_ENDPOINT=\$ROX_ENDPOINT -e ROX_API_TOKEN=\$ROX_API_TOKEN $TAG image-diff -p ubuntu:20.04 -n ubuntu:22.04"
        ;;
    trivy)
        echo "# Run image diff with Trivy:"
        echo "$CONTAINER_MANAGER run --rm $TAG image-diff -p ubuntu:20.04 -n ubuntu:22.04 --scanner trivy"
        ;;
    all)
        echo "# Run with ACS (requires credentials):"
        echo "$CONTAINER_MANAGER run --rm -e ROX_ENDPOINT=\$ROX_ENDPOINT -e ROX_API_TOKEN=\$ROX_API_TOKEN $TAG image-diff -p ubuntu:20.04 -n ubuntu:22.04 --scanner acs"
        echo
        echo "# Run with Trivy:"
        echo "$CONTAINER_MANAGER run --rm $TAG image-diff -p ubuntu:20.04 -n ubuntu:22.04 --scanner trivy"
        ;;
esac
echo
echo "# Run SBOM diff:"
echo "$CONTAINER_MANAGER run --rm -v \$(pwd):/data:z $TAG sbom-diff -p /data/old.json -n /data/new.json"
