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
