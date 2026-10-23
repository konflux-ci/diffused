from pathlib import Path

MAX_LINES = 60


def test_agents_md_line_count() -> None:
    """Verify AGENTS.md stays within the maximum line count."""
    agents_md = Path(__file__).resolve().parent.parent / "AGENTS.md"
    line_count = len(agents_md.read_text(encoding="utf-8").splitlines())
    assert line_count <= MAX_LINES, f"AGENTS.md has {line_count} lines, max is {MAX_LINES}"


def test_agents_md_documents_ci_workflows() -> None:
    """Verify AGENTS.md contains CI workflow documentation."""
    agents_md = Path(__file__).resolve().parent.parent / "AGENTS.md"
    content = agents_md.read_text(encoding="utf-8")
    assert "CI Workflows" in content, "AGENTS.md should contain a CI Workflows section"
    for workflow in ["tests.yml", "test-release.yml", "release.yml"]:
        assert workflow in content, f"AGENTS.md should document {workflow}"
