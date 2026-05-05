---
name: lint-and-test
description: Run the project's tox linting and test suite and present a concise pass/fail summary. Use when asked to lint, test, check, or validate the project.
allowed-tools: Bash
argument-hint: "[environment]"
---

# Lint and Test

Run the tox suite and summarize results.

## Arguments

`$ARGUMENTS` is an optional comma-separated list of tox environment names (e.g., `py39-pytest`, `py39-flake8,py39-black`). Use exact names as defined in `tox.ini`.

## Steps

1. **Run tox** from the project root:
   - If `$ARGUMENTS` is provided, run: `tox -e $ARGUMENTS`
   - If no arguments, run: `tox`
2. **Parse the output.** Tox prints a summary at the end with each environment listed as `PASSED` or `FAILED`.
3. **Present results** as a short table: environment name and status. For failures, include the key error lines — not the full log.
4. If everything passes, confirm with a single sentence.
