from pathlib import Path

MAX_LINES = 60


def test_agents_md_line_count():
    agents_md = Path(__file__).resolve().parent.parent / "AGENTS.md"
    line_count = len(agents_md.read_text(encoding="utf-8").splitlines())
    assert line_count <= MAX_LINES, f"AGENTS.md has {line_count} lines, max is {MAX_LINES}"
