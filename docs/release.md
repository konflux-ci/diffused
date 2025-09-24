# Release Process

This document describes how to release and publish the Diffused package to PyPI using automated GitHub Actions workflows.

## Automated Releases

The project uses GitHub Actions to automatically build and publish packages to PyPI:

### Test Releases (Test PyPI)
- **Trigger**: Every push to the `main` branch
- **Workflow**: `.github/workflows/test-release.yml`
- **Packages**: Both library (`diffused-lib`) and CLI (`diffused-cli`)
- **Versioning**: Automatically appends `-dev{COMMIT_HASH}` to the current version
- **Repository**: Test PyPI (https://test.pypi.org/)

### Production Releases (PyPI)
- **Trigger**: Git tags matching `v*` pattern (e.g., `v1.0.0`) or manual dispatch
- **Workflow**: `.github/workflows/release.yml`
- **Packages**: Both library (`diffused-lib`) and CLI (`diffused-cli`)
- **Versioning**: Uses the exact version from `pyproject.toml` files
- **Repository**: Production PyPI (https://pypi.org/)

## Creating a Release

### For Production Release:

1. **Update versions** in both `pyproject.toml` files:
   - `diffused/pyproject.toml`
   - `diffusedcli/pyproject.toml`

2. **Create and push a git tag:**
   ```bash
   git tag v1.0.0
   git push origin v1.0.0
   ```

3. **GitHub Actions will automatically:**
   - Build both packages
   - Test installations
   - Publish to PyPI

### Manual Workflow Dispatch
You can also trigger releases manually from the GitHub Actions UI.

## Version Management

Before creating a new release:

1. **Update the version** in both `pyproject.toml` files:
   ```toml
   # diffused/pyproject.toml
   version = "0.1.1"  # Increment appropriately

   # diffusedcli/pyproject.toml
   version = "0.1.1"  # Keep in sync with library
   ```

2. **Follow semantic versioning:**
   - **MAJOR**: Incompatible API changes
   - **MINOR**: Backward-compatible functionality additions
   - **PATCH**: Backward-compatible bug fixes

## Manual Release (Fallback)

If you need to publish manually (when automated workflows are not available):

### Prerequisites

Install the required tools:

```bash
pip install build twine
```

## Publishing to PyPI

### Test PyPI (Recommended)

Before publishing to production PyPI, test your package on Test PyPI:

1. **Upload to Test PyPI:**
   ```bash
   cd diffused
   twine upload --repository testpypi dist/*
   cd ..

   cd diffusedcli
   twine upload --repository testpypi dist/*
   cd ..
   ```

2. **Test installation:**
   ```bash
   pip install --index-url https://test.pypi.org/simple/ --extra-index-url https://pypi.org/simple/ diffused-cli
   ```

3. **Verify the CLI works:**
   ```bash
   diffused --help
   ```

### Production PyPI

Once tested, publish to production PyPI:

```bash
cd diffused
twine upload dist/*
cd ..

cd diffusedcli
twine upload dist/*
cd ..
```

## PyPI Credentials

Configure your PyPI credentials using one of these methods:

### Option 1: API Tokens (Recommended)
Create API tokens at https://pypi.org/manage/account/token/ and use:

```bash
# For production PyPI
twine upload --username __token__ --password <your-token> dist/*

# For Test PyPI
twine upload --repository testpypi --username __token__ --password <your-token> dist/*
```

### Option 2: Configuration File
Create `~/.pypirc`:

```ini
[distutils]
index-servers =
    pypi
    testpypi

[pypi]
username = __token__
password = <your-production-token>

[testpypi]
repository = https://test.pypi.org/legacy/
username = __token__
password = <your-test-token>
```

## Release Checklist

### For Automated Releases:
- [ ] Update versions in both `diffused/pyproject.toml` and `diffusedcli/pyproject.toml`
- [ ] Commit and push changes to main
- [ ] Create and push git tag (e.g., `git tag v1.0.0 && git push origin v1.0.0`)
- [ ] Monitor GitHub Actions workflow completion
- [ ] Verify packages are published to PyPI
- [ ] Test installation: `pip install diffused-cli`

### For Manual Releases (Fallback):
- [ ] Update versions in both `pyproject.toml` files
- [ ] Clean previous builds (`rm -rf */dist/ */build/`)
- [ ] Build packages (`python -m build diffused/` and `python -m build diffusedcli/`)
- [ ] Test on Test PyPI
- [ ] Verify installation and functionality
- [ ] Publish to production PyPI
- [ ] Create Git tag for the release
- [ ] Update documentation if needed

## Installation for End Users

After publishing, users can install the package with:

```bash
pip install diffused-cli
```

## Important Notes

- **Testing**: Always test on Test PyPI before publishing to production
- **Credentials**: Use API tokens for secure authentication
- **Version Control**: Tag releases in Git for tracking
- **Dependencies**: The package includes both library and CLI dependencies
