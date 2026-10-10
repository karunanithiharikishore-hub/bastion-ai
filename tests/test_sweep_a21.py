from bluecell.agents.analyst import _extract_json


def test_trailing_brace_text_does_not_discard_object():
    text = '```json\n{"verdict":"needs-review"}\n```\n(see {appendix})'
    assert _extract_json(text) == {"verdict": "needs-review"}


def test_brace_text_before_object_is_skipped():
    assert _extract_json('see {appendix} then {"verdict":"likely-benign"}') == {"verdict": "likely-benign"}


def test_no_object_returns_none():
    assert _extract_json("only {braces} here") is None
