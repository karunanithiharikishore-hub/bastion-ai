"""ITEM-23: listed model ids (and their dated forms) must get a list price."""
import pytest

from bluecell import tracing


@pytest.mark.parametrize("model, price", [
    ("claude-opus-4-5", (5.00, 25.00)),
    ("claude-opus-4-5-20251101", (5.00, 25.00)),
    ("claude-sonnet-4-5", (3.00, 15.00)),
    ("claude-sonnet-4-5-20250929", (3.00, 15.00)),
    ("claude-haiku-4-5-20251001", (1.00, 5.00)),
])
def test_listed_and_dated_ids_have_price(model, price):
    assert tracing.price_for(model) == price


@pytest.mark.parametrize("model,price", [
    ("claude-opus-4-1-20250805", (15.00, 75.00)),
    ("claude-opus-4-20250514", (15.00, 75.00)),
    ("claude-sonnet-4-20250514", (3.00, 15.00)),
    ("claude-3-5-haiku-20241022", (0.80, 4.00)),
    ("claude-opus-4-5-20251101", (5.00, 25.00)),
])
def test_verified_prices(model, price):
    from bluecell import tracing
    assert tracing.price_for(model) == price


def test_haiku_5_5_long_prompt_tier():
    from bluecell import tracing
    short = tracing.estimate_cost({"input_tokens": 100_000, "output_tokens": 1_000_000}, "claude-haiku-5-5")
    assert short == round((100_000 * 0.10 + 1_000_000 * 0.50) / 1e6, 6)
    # over 100k prompt tokens (cache reads count): the whole call bills at $0.50/$2.50
    long = tracing.estimate_cost({"input_tokens": 60_000, "cache_read_input_tokens": 50_000,
                                  "output_tokens": 1_000}, "claude-haiku-5-5")
    assert long == round((60_000 * 0.50 + 50_000 * 0.50 * 0.10 + 1_000 * 2.50) / 1e6, 6)
    # other models are unaffected by prompt size
    assert tracing.estimate_cost({"input_tokens": 200_000}, "claude-sonnet-5-5") == 0.4
