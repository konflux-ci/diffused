---
name: release-prep
description: Check version consistency, git tag status, and test results before cutting a release. Use when asked to prepare, validate, or check readiness for a release.
allowed-tools: Bash
---

# Release Prep

Run pre-release checks and present a summary checklist.

## Steps

1. **Read versions** from all 3 `pyproject.toml` files:
   - `pyproject.toml` (root)
   - `diffused/pyproject.toml`
   - `diffusedcli/pyproject.toml`
   Extract the `version` field from each.

2. **Check version consistency.** All 3 must match. Report any mismatches.

3. **Check git tag.** Run `git tag --list "v{version}"` to see if the tag already exists. If it does, warn that this version was already released.

4. **Check working tree.** Run `git status --porcelain`. Warn if there are uncommitted changes.

5. **Run tox.** Execute the full tox suite. Summarize each environment as pass or fail. For failures, include the key error lines — not the full log.

6. **Present a summary checklist:**
   - Version consistency: pass/fail
   - Git tag `v{version}` available: yes/no
   - Working tree clean: yes/no
   - Tests/linting: pass/fail per environment
   - Final verdict: ready to release, or list the blockers
