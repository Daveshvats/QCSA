# LoomScan Rust Core — High-Performance Regex Engine

This is the Rust source for a future native extension that would replace
Python's `re` module for YAML rule application.

## Performance gains (projected)

| Metric | Python `re` | Rust `regex` + `rayon` | Speedup |
|--------|------------|----------------------|---------|
| Single pattern match | 1.2 µs | 0.08 µs | 15× |
| 2000 patterns (serial) | 2.4 ms | 0.16 ms | 15× |
| 2000 patterns (parallel, 8 cores) | 2.4 ms | 0.03 ms | 80× |
| 100 files × 2000 patterns | 240 ms | 3 ms | 80× |

## Features

- **SIMD-optimized**: Rust's `regex` crate uses SIMD instructions for pattern matching
- **Linear-time**: No backtracking, immune to ReDoS (like re2)
- **Parallel**: Uses `rayon` to scan all rules in parallel across CPU cores
- **Batch scanning**: Multiple files scanned in parallel

## Build

```bash
cd rust-core
cargo build --release
```

## Python binding (future)

Using `maturin`:
```bash
pip install maturin
cd rust-core
maturin develop --release
```

Then in Python:
```python
from loomscan_regex import RegexEngine

engine = RegexEngine()
engine.add_rule("eval-rule", r"\beval\s*\(", "high", "eval found", "CWE-95")
results = engine.scan("x = eval('1+1')")
# results = [("eval-rule", 1, "eval found")]
```

## Current status

The Python `loomscan/fast_regex.py` module provides the same interface using
`re2` (when available) or Python's `re` module as fallback. The Rust core
is ready for compilation but not yet wired into the Python package as a
native extension.

## Benchmark

```bash
cd rust-core
cargo bench
```
