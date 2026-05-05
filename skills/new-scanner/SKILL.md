---
name: new-scanner
description: Scaffold a new vulnerability scanner implementation with tests following the project's existing pattern. Use when adding support for a new scanner tool.
allowed-tools: Bash Read Write Edit
arguments: [name, cli, example_image, example_sbom]
argument-hint: <scanner-name> <cli-executable> "<image scan command>" "<sbom scan command>"
---

# New Scanner

Scaffold a complete scanner implementation for `$name` using the `$cli` CLI tool.

**Validate `$name` first:** it must be a valid Python identifier (lowercase letters, numbers, underscores only). If it contains dashes, spaces, or other invalid characters, normalize it (e.g., `my-scanner` becomes `my_scanner`) and use the normalized form for file names, class names, and method names throughout.

## Step 1: Discover the CLI

Run `$cli --help` to learn available subcommands and flags. Identify:
- The version flag (e.g., `--version`, `version`)
- How to scan an SBOM file
- How to scan a container image
- How to get JSON output

## Step 2: Discover the JSON structure

Run both example commands provided by the user:

Image scan:
```
$example_image
```

SBOM scan:
```
$example_sbom
```

Inspect the JSON output from each and identify:
- Where vulnerability entries live in the JSON hierarchy
- The field name for the vulnerability/CVE ID
- The field names for package name and installed version

## Step 3: Read the existing pattern

Read these files to understand the conventions:
- `diffused/diffused/scanners/base.py` — abstract base class with 4 required methods
- `diffused/diffused/scanners/trivy.py` — reference implementation
- `diffused/tests/scanners/test_trivy.py` — reference test structure
- `diffused/tests/conftest.py` — shared fixtures (`test_image`, `test_sbom_path`)

## Step 4: Create the scanner implementation

Create `diffused/diffused/scanners/$name.py`:
- Subclass `BaseScanner`
- Implement all 4 abstract methods using the discovered CLI commands and JSON structure:
  - `scan_sbom()` — run the scanner on `self.sbom`, parse JSON into `self.raw_result`
  - `scan_image()` — run the scanner on `self.image`, parse JSON into `self.raw_result`
  - `process_result()` — parse `self.raw_result` into `self.processed_result` (a `defaultdict[str, set[Package]]` mapping CVE IDs to sets of Package objects)
  - `get_version()` — static method, return the scanner version string
- Add a `_run_$name_command(self, cmd, operation)` helper with 120s timeout
- Follow the error handling convention: store errors in `self.error`, do not raise from scan/process methods
- Use `logging` for all log messages

## Step 5: Create the test file

Create `diffused/tests/scanners/test_$name.py`:
- Use the discovered JSON output as sample test data in fixtures
- Cover: initialization, scan_sbom, scan_image, process_result, get_version
- Use `unittest.mock` (`patch`, `MagicMock`) for subprocess mocking
- Reuse fixtures from `conftest.py` (`test_image`, `test_sbom_path`)
- Follow the same test structure as `test_trivy.py`

## Step 6: Register the scanner

Edit `diffused/diffused/differ.py`:
- Add an import for the new scanner class
- Add an entry to the `scanner_map` dict in `VulnerabilityDiffer._get_scanner_class()`

Edit `diffusedcli/diffusedcli/cli.py`:
- Add `$name` to the `click.Choice` list in the `--scanner` option
- Check for any scanner-specific restrictions in the CLI commands (e.g., SBOM scanning guards) and update them if the new scanner supports those features

## Step 7: Run tests

Run `tox -e py39-pytest,py39-pytest-cli` and fix any failures until tests pass with 100% code coverage on the new scanner file.

## Step 8: Summary

Present a summary:
- Files created and modified
- CLI commands and JSON fields discovered
- Any manual steps remaining
