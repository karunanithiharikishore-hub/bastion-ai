"""BUG-FEAT-5: unlisted model versions must get no price (cost unknown)."""
import pytest

from bluecell import tracing


@pytest.mark.parametrize("model", [
    "claude-opus-4-1",  # 4-5 models are priced now (sweep F23)
    "claude-3-5-sonnet-20241022", "claude-3-opus-20240229",
    "claude-opus-5-1", "totally-unknown-model", "gpt-x",
])
def test_unlisted_versions_have_no_price(model):
    assert tracing.price_for(model) is None


def test_unlisted_version_usage_is_unknown_not_estimated(tmp_path, monkeypatch):
    monkeypatch.setenv("BLUECELL_RUNS_DIR", str(tmp_path))
    rec = tracing.Tracer(persist=False).record_usage(
        {"input_tokens": 1000, "output_tokens": 1000}, model="claude-opus-4-1")
    assert rec["cost_usd"] is None and rec["cost_basis"] == "unknown"


@pytest.mark.parametrize("model,key", [
    ("claude-opus-5-5", "claude-opus-5-5"),
    ("claude-opus-5-5-20260101", "claude-opus-5-5"),
    ("claude-sonnet-4-6-20250101", "claude-sonnet-4-6"),
    ("anthropic.claude-haiku-5-5-20251001-v1:0", "claude-haiku-5-5"),
    ("claude-fable-5-1", "claude-fable-5-1"),
])
def test_listed_versions_match_exactly(model, key):
    assert tracing.price_for(model) == tracing.PRICES[key]


def test_version_less_alias_uses_newest_family_price():
    assert tracing.price_for("claude-haiku") == tracing.PRICES["claude-haiku-5-5"]
