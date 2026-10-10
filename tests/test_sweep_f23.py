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
