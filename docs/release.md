# Release Process

This document describes how to release and publish the Diffused package to PyPI.

## Prerequisites

Install the required tools:

```bash
pip install twine
```

## Version Management

Before creating a new release:

1. **Update the version** in `pyproject.toml`:
   ```toml
   version = "0.1.1"  # Increment appropriately
   ```

2. **Follow semantic versioning:**
   - **MAJOR**: Incompatible API changes
   - **MINOR**: Backward-compatible functionality additions
   - **PATCH**: Backward-compatible bug fixes

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

- [ ] Update version in `pyproject.toml`
- [ ] Clean previous builds (`rm -rf dist/ build/`)
- [ ] Build package (`python -m build`)
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
