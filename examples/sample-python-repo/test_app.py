"""Property tests for the sample app.

These express properties that should ALWAYS hold, regardless of input.
"""
from hypothesis import given, strategies as st
import sys
import os

sys.path.insert(0, os.path.dirname(__file__))
from app import calculate_discount, get_user_data


@given(st.floats(min_value=0, max_value=10000), st.floats(min_value=0, max_value=100))
def test_calculate_discount_never_negative(price, discount_percent):
    """Property: discounted price should never go negative for valid inputs."""
    result = calculate_discount(price, discount_percent)
    assert result >= 0


@given(st.integers(min_value=1, max_value=1000000))
def test_get_user_data_returns_dict(user_id):
    """Property: get_user_data should always return a dict for valid IDs."""
    result = get_user_data(user_id)
    assert isinstance(result, dict)
