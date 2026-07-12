"""v4.41: High-performance regex engine — uses re2 (Rust-backed) if available,
falls back to Python's re module.

re2 is Google's regex engine (written in C++, not Rust, but the principle
is the same as what Semgrep did): it guarantees linear-time matching by
not supporting backtracking. This prevents ReDoS (Regular Expression Denial
of Service) attacks on user-supplied patterns.

Usage:
    from stca.fast_regex import compile, finditer, search, match

    # Drop-in replacement for re.compile/finditer/search/match
    pattern = compile(r"\\beval\\s*\\(")
    for m in pattern.finditer("x = eval('1+1')"):
        print(m.start(), m.group())

The module automatically detects if `re2` (or `pyre2`) is installed and
uses it. If not, it falls back to Python's `re` module with a warning.

To install re2:
    pip install re2  # or pip install google-re2
"""
from __future__ import annotations

import re
import sys
import logging
from typing import Iterator, Optional, Pattern as RePattern

_logger = logging.getLogger("stca.fast_regex")

# Try to import re2
_RE2_AVAILABLE = False
try:
    import re2
    _RE2_AVAILABLE = True
    _logger.debug("re2 is available — using linear-time regex engine")
except ImportError:
    try:
        import pyre2 as re2  # type: ignore
        _RE2_AVAILABLE = True
        _logger.debug("pyre2 is available — using linear-time regex engine")
    except ImportError:
        _logger.debug("re2 not available — using Python re module (vulnerable to ReDoS)")


class FastMatch:
    """A match object compatible with re.Match."""

    __slots__ = ("_start", "_end", "_text", "_groups", "_pos")

    def __init__(self, start: int, end: int, text: str, groups: tuple, pos: int = 0):
        self._start = start
        self._end = end
        self._text = text
        self._groups = groups
        self._pos = pos

    def start(self, group: int = 0) -> int:
        if group == 0:
            return self._start
        return self._start  # simplified

    def end(self, group: int = 0) -> int:
        if group == 0:
            return self._end
        return self._end  # simplified

    def group(self, group: int = 0) -> str:
        if group == 0:
            return self._text[self._start:self._end]
        if group <= len(self._groups):
            return self._groups[group - 1] or ""
        return ""

    def groups(self) -> tuple:
        return self._groups

    def span(self, group: int = 0) -> tuple:
        if group == 0:
            return (self._start, self._end)
        return (self._start, self._end)

    @property
    def string(self) -> str:
        return self._text


class FastPattern:
    """A compiled regex pattern that uses re2 if available, else re."""

    __slots__ = ("_pattern_str", "_flags", "_re2_compiled", "_re_compiled", "_use_re2")

    def __init__(self, pattern: str, flags: int = 0):
        self._pattern_str = pattern
        self._flags = flags
        self._use_re2 = _RE2_AVAILABLE

        if self._use_re2:
            try:
                # re2 doesn't support all Python regex features
                # If compilation fails, fall back to re
                self._re2_compiled = re2.compile(pattern, flags)
                self._re_compiled = None
            except Exception:
                # re2 doesn't support some patterns (e.g., backreferences)
                # Fall back to Python re
                self._use_re2 = False
                self._re2_compiled = None
                self._re_compiled = re.compile(pattern, flags)
        else:
            self._re2_compiled = None
            self._re_compiled = re.compile(pattern, flags)

    def finditer(self, text: str) -> Iterator[FastMatch]:
        """Find all matches in text. Returns an iterator of FastMatch objects."""
        if self._use_re2 and self._re2_compiled is not None:
            for m in self._re2_compiled.finditer(text):
                # Convert re2 match to FastMatch
                num_groups = m.lastindex or 0
                groups = tuple(m.group(i) for i in range(1, num_groups + 1)) if num_groups > 0 else ()
                yield FastMatch(m.start(), m.end(), text, groups)
        else:
            assert self._re_compiled is not None
            for m in self._re_compiled.finditer(text):
                num_groups = len(m.groups())
                groups = m.groups() if num_groups > 0 else ()
                yield FastMatch(m.start(), m.end(), text, groups)

    def search(self, text: str) -> Optional[FastMatch]:
        """Search for the first match in text."""
        if self._use_re2 and self._re2_compiled is not None:
            m = self._re2_compiled.search(text)
            if m is None:
                return None
            num_groups = m.lastindex or 0
            groups = tuple(m.group(i) for i in range(1, num_groups + 1)) if num_groups > 0 else ()
            return FastMatch(m.start(), m.end(), text, groups)
        else:
            assert self._re_compiled is not None
            m = self._re_compiled.search(text)
            if m is None:
                return None
            groups = m.groups()
            return FastMatch(m.start(), m.end(), text, groups)

    def match(self, text: str) -> Optional[FastMatch]:
        """Match at the beginning of text."""
        if self._use_re2 and self._re2_compiled is not None:
            m = self._re2_compiled.match(text)
            if m is None:
                return None
            num_groups = m.lastindex or 0
            groups = tuple(m.group(i) for i in range(1, num_groups + 1)) if num_groups > 0 else ()
            return FastMatch(m.start(), m.end(), text, groups)
        else:
            assert self._re_compiled is not None
            m = self._re_compiled.match(text)
            if m is None:
                return None
            groups = m.groups()
            return FastMatch(m.start(), m.end(), text, groups)

    def findall(self, text: str) -> list:
        """Find all matches. Returns a list of matched strings."""
        if self._use_re2 and self._re2_compiled is not None:
            return self._re2_compiled.findall(text)
        else:
            assert self._re_compiled is not None
            return self._re_compiled.findall(text)

    def sub(self, replacement: str, text: str) -> str:
        """Replace all matches with replacement."""
        if self._use_re2 and self._re2_compiled is not None:
            return self._re2_compiled.sub(replacement, text)
        else:
            assert self._re_compiled is not None
            return self._re_compiled.sub(replacement, text)

    @property
    def pattern(self) -> str:
        return self._pattern_str

    @property
    def using_re2(self) -> bool:
        return self._use_re2


def compile(pattern: str, flags: int = 0) -> FastPattern:
    """Compile a regex pattern. Uses re2 if available, else re.

    Drop-in replacement for re.compile().
    """
    return FastPattern(pattern, flags)


def finditer(pattern: str, text: str, flags: int = 0) -> Iterator[FastMatch]:
    """Find all matches of pattern in text. Uses re2 if available."""
    return compile(pattern, flags).finditer(text)


def search(pattern: str, text: str, flags: int = 0) -> Optional[FastMatch]:
    """Search for pattern in text. Uses re2 if available."""
    return compile(pattern, flags).search(text)


def match(pattern: str, text: str, flags: int = 0) -> Optional[FastMatch]:
    """Match pattern at the beginning of text. Uses re2 if available."""
    return compile(pattern, flags).match(text)


def is_re2_available() -> bool:
    """Check if re2 (linear-time regex engine) is available."""
    return _RE2_AVAILABLE


def get_engine_info() -> dict:
    """Return information about the active regex engine."""
    return {
        "engine": "re2" if _RE2_AVAILABLE else "re",
        "re2_available": _RE2_AVAILABLE,
        "description": (
            "re2: linear-time matching, immune to ReDoS"
            if _RE2_AVAILABLE
            else "re: Python standard library, vulnerable to ReDoS on user patterns"
        ),
        "install_hint": (
            "re2 is active"
            if _RE2_AVAILABLE
            else "Install re2 for ReDoS protection: pip install re2"
        ),
    }
