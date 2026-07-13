"""Pure-Python fuzzing — works on Windows, macOS, and Linux.

Provides:
  - FuzzedDataProvider: atheris-compatible API for consuming bytes as typed values
  - fuzz(): random-mutation fuzzer (basic, always works)
  - instrument_imports(): no-op context manager (compatibility shim)

This is the foundation for the coverage-guided fuzzer in fuzz_coverage.py.
"""
from __future__ import annotations

import random
import sys
import time
import traceback
from contextlib import contextmanager
from typing import Callable, Optional


class FuzzedDataProvider:
    """Pure-Python reimplementation of atheris.FuzzedDataProvider.

    Consumes bytes from a buffer and produces typed values. Mirrors the
    atheris API so the same harness code works with both backends.
    """

    def __init__(self, data: bytes):
        self._data = data if isinstance(data, bytes) else bytes(data)
        self._pos = 0

    def _consume_bytes(self, count: int) -> bytes:
        count = max(0, min(count, len(self._data) - self._pos))
        result = self._data[self._pos:self._pos + count]
        self._pos += count
        return result

    def remaining_bytes(self) -> int:
        return len(self._data) - self._pos

    # atheris-compatible API (camelCase)
    def ConsumeUnicodeNoSurrogates(self, count: int) -> str:
        raw = self._consume_bytes(count)
        try:
            return raw.decode("utf-8", errors="replace")
        except Exception:
            return raw.decode("latin-1", errors="replace")

    def ConsumeString(self, count: int) -> str:
        return self.ConsumeUnicodeNoSurrogates(count)

    def ConsumeBytes(self, count: int) -> bytes:
        return self._consume_bytes(count)

    def ConsumeInt(self, byte_count: int = 4, signed: bool = False) -> int:
        raw = self._consume_bytes(byte_count)
        if not raw:
            return 0
        return int.from_bytes(raw, byteorder="little", signed=signed)

    def ConsumeIntInRange(self, min_val: int, max_val: int) -> int:
        if min_val > max_val:
            return min_val
        raw_val = self.ConsumeInt(4, signed=False)
        range_size = max_val - min_val + 1
        return min_val + (raw_val % range_size)

    def ConsumeFloat(self) -> float:
        raw = self._consume_bytes(8)
        if not raw:
            return 0.0
        int_val = int.from_bytes(raw, byteorder="little", signed=False)
        return int_val / (2 ** (8 * len(raw)))

    def ConsumeBoolean(self) -> bool:
        raw = self._consume_bytes(1)
        if not raw:
            return False
        return bool(raw[0] & 1)

    def ConsumeByte(self) -> int:
        raw = self._consume_bytes(1)
        return raw[0] if raw else 0

    def PickValueInList(self, lst: list):
        if not lst:
            return None
        idx = self.ConsumeIntInRange(0, len(lst) - 1)
        return lst[idx]

    # snake_case aliases
    def consume_unicode_no_surrogates(self, count: int) -> str:
        return self.ConsumeUnicodeNoSurrogates(count)
    def consume_string(self, count: int) -> str:
        return self.ConsumeString(count)
    def consume_bytes(self, count: int) -> bytes:
        return self.ConsumeBytes(count)
    def consume_int(self, byte_count: int = 4, signed: bool = False) -> int:
        return self.ConsumeInt(byte_count, signed)
    def consume_int_in_range(self, min_val: int, max_val: int) -> int:
        return self.ConsumeIntInRange(min_val, max_val)
    def consume_float(self) -> float:
        return self.ConsumeFloat()
    def consume_boolean(self) -> bool:
        return self.ConsumeBoolean()
    def consume_byte(self) -> int:
        return self.ConsumeByte()
    def pick_value_in_list(self, lst: list):
        return self.PickValueInList(lst)


@contextmanager
def instrument_imports():
    """No-op context manager — compatibility shim for atheris.instrument_imports()."""
    yield


def _generate_random_input(max_len: int = 256, rng: random.Random = None) -> bytes:
    """Generate a random byte buffer using varied strategies.

    Uses rng.randbytes() (Python 3.9+) for ~37x speedup over the
    bytes(generator) approach.
    """
    rng = rng or random
    strategy = rng.randint(0, 4)

    if strategy == 0:
        return b""  # empty
    elif strategy == 1:
        return rng.randbytes(rng.randint(1, 8))  # short
    elif strategy == 2:
        length = rng.randint(64, max_len)  # long
        return rng.randbytes(length)
    elif strategy == 3:
        specials = b"\x00\n\r\t\"'\\<>&;${}[]()#!@?*+=/\\"
        length = rng.randint(1, min(len(specials), max_len))
        return bytes(rng.choice(specials) for _ in range(length))
    else:
        length = rng.randint(0, max_len)
        return rng.randbytes(length)


def fuzz(test_func: Callable[[bytes], None],
         duration_seconds: int = 10,
         max_len: int = 256,
         seed: Optional[int] = None) -> str:
    """Run `test_func` with random inputs for `duration_seconds`.

    Returns empty string if no crash, otherwise the crash details.
    Any exception that propagates from the target IS a crash — the harness
    is responsible for catching expected exceptions (TypeError, ValueError)
    itself.
    """
    rng = random.Random(seed)
    deadline = time.monotonic() + duration_seconds
    iterations = 0

    while time.monotonic() < deadline:
        iterations += 1
        data = _generate_random_input(max_len, rng)

        try:
            test_func(data)
        except SystemExit:
            continue
        except Exception as e:
            crash_input_repr = repr(data)[:200]
            tb = traceback.format_exc()[-500:]
            return (f"Unexpected {type(e).__name__}: {e} "
                    f"after {iterations} iterations "
                    f"(input={crash_input_repr})\n{tb}")

    return ""
