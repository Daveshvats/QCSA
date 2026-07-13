"""Tests for the function-level result cache."""
import pytest
from pathlib import Path
from loomscan.cache import ResultCache


@pytest.fixture
def cache(tmp_path):
    return ResultCache(tmp_path)


def test_cache_miss_returns_none(cache):
    result = cache.get("L0", "def foo(): pass")
    assert result is None


def test_cache_put_then_get(cache):
    findings = [{"rule_id": "test", "message": "test msg"}]
    cache.put("L0", "def foo(): pass", findings)
    result = cache.get("L0", "def foo(): pass")
    assert result == findings


def test_cache_keyed_on_function_body(cache):
    """Different function bodies should have separate cache entries."""
    cache.put("L0", "def foo(): pass", [{"rule_id": "foo"}])
    cache.put("L0", "def bar(): pass", [{"rule_id": "bar"}])
    assert cache.get("L0", "def foo(): pass") == [{"rule_id": "foo"}]
    assert cache.get("L0", "def bar(): pass") == [{"rule_id": "bar"}]


def test_cache_keyed_on_layer(cache):
    """Different layers should have separate cache entries for the same function."""
    cache.put("L0", "def foo(): pass", [{"rule_id": "L0 finding"}])
    cache.put("L1", "def foo(): pass", [{"rule_id": "L1 finding"}])
    assert cache.get("L0", "def foo(): pass") == [{"rule_id": "L0 finding"}]
    assert cache.get("L1", "def foo(): pass") == [{"rule_id": "L1 finding"}]


def test_cache_invalidate_all(cache):
    cache.put("L0", "def foo(): pass", [{"rule_id": "test"}])
    cache.invalidate()
    assert cache.get("L0", "def foo(): pass") is None


def test_cache_invalidate_layer(cache):
    cache.put("L0", "def foo(): pass", [{"rule_id": "L0"}])
    cache.put("L1", "def foo(): pass", [{"rule_id": "L1"}])
    cache.invalidate(layer="L0")
    assert cache.get("L0", "def foo(): pass") is None
    assert cache.get("L1", "def foo(): pass") == [{"rule_id": "L1"}]


def test_cache_stats(cache):
    cache.put("L0", "def foo(): pass", [{"rule_id": "test"}])
    stats = cache.stats()
    assert stats["total_entries"] == 1
    assert stats["ttl_days"] == 7
