# Containerfile for Diffused - A vulnerability scan diffing tool
FROM registry.access.redhat.com/ubi9/ubi:latest

# Build arguments for scanner selection
ARG SCANNER=trivy
ARG ACS_VERSION=latest
ARG TRIVY_VERSION=latest

# Set environment variables
ENV PYTHONUNBUFFERED=1
ENV PATH="/usr/local/bin:$PATH"
ENV SCANNER_TYPE=${SCANNER}

# Install system dependencies
RUN dnf update -y && \
    dnf install -y \
        python3.12 \
        python3.12-pip \
        wget \
        tar \
        gzip \
        unzip && \
    dnf clean all

# Create application directory
WORKDIR /app

# Copy application source code
COPY diffused/ /app/diffused/
COPY diffusedcli/ /app/diffusedcli/
COPY README.md /app/
COPY LICENSE /app/

# Install Python dependencies and the application
RUN python3.12 -m pip install --no-cache-dir --upgrade pip && \
    python3.12 -m pip install --no-cache-dir -e ./diffused && \
    python3.12 -m pip install --no-cache-dir -e ./diffusedcli

# Download and install scanners based on build argument
RUN if [ "$SCANNER" = "acs" ] || [ "$SCANNER" = "all" ]; then \
        echo "Installing ACS (roxctl) scanner..." && \
        if [ "$ACS_VERSION" = "latest" ]; then \
            DOWNLOAD_URL="https://mirror.openshift.com/pub/rhacs/assets/latest/bin/Linux/roxctl"; \
        else \
            DOWNLOAD_URL="https://mirror.openshift.com/pub/rhacs/assets/${ACS_VERSION}/bin/Linux/roxctl"; \
        fi && \
        curl -L "$DOWNLOAD_URL" -o /usr/local/bin/roxctl && \
        chmod +x /usr/local/bin/roxctl; \
    fi

RUN if [ "$SCANNER" = "trivy" ] || [ "$SCANNER" = "all" ]; then \
        echo "Installing Trivy scanner..." && \
        if [ "$TRIVY_VERSION" = "latest" ]; then \
            DOWNLOAD_URL=$(curl -s https://api.github.com/repos/aquasecurity/trivy/releases/latest | grep "browser_download_url.*Linux-64bit\.tar\.gz\"" | grep -v "\.pem" | grep -v "\.sig" | cut -d '"' -f 4 | head -n1); \
        else \
            DOWNLOAD_URL="https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_Linux-64bit.tar.gz"; \
        fi && \
        curl -L "$DOWNLOAD_URL" -o /tmp/trivy.tar.gz && \
        tar -xzf /tmp/trivy.tar.gz -C /tmp && \
        mv /tmp/trivy /usr/local/bin/ && \
        chmod +x /usr/local/bin/trivy && \
        rm -f /tmp/trivy.tar.gz; \
    fi

# Create non-root user for security
RUN groupadd -r diffused && useradd -r -g diffused -s /bin/bash diffused

# Create directories for output, temporary files, and user home directory
RUN mkdir -p /app/output /app/temp /home/diffused && \
    chown -R diffused:diffused /app /home/diffused

# Switch to non-root user
USER diffused

# Set working directory
WORKDIR /home/diffused


# Default scanner environment variable (can be overridden at runtime)
ENV DEFAULT_SCANNER=${SCANNER}

# Entrypoint script to invoke Diffused
ENTRYPOINT ["diffused"]

# Default command shows help
CMD ["--help"]
