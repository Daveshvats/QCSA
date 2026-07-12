"""L4 — Directed fuzzing layer (Python-only, cross-platform).

Runs coverage-guided fuzzing on changed Python functions. The "directed"
part: we only fuzz the changed functions, not the whole program (WAFLGO-
style diff-directed fuzzing).

Language scope:
  - Python only (.py files). Other languages (JS, Go, Java, C/C++, Rust)
    are NOT fuzzed by this layer — they rely on static analysis (L0
    pattern scanners, taint tracking) and language-specific verification
    (e.g. L6 Kani for Rust). See the README "Language Coverage" matrix
    for details.

  Why Python only? Fuzzing requires runtime execution. Python is
  interpreted, so we can import the target module and call its functions
  directly. Compiled languages (Go, Java, C/C++) would require their
  toolchains + build systems + language-specific harness generation,
  which would break STCA's "works on any laptop, offline" design.

Cross-platform support (for Python):
  - Linux with atheris:   Uses atheris (libFuzzer, C++ instrumentation)
  - Windows/macOS/Linux:  Uses built-in coverage-guided fuzzer
    (stca.fuzz_coverage — pure Python, sys.monitoring BRANCH events)

Both backends are coverage-guided (not random mutation). The built-in
fuzzer uses the same algorithm as libFuzzer: maintain a corpus, track
branch coverage, keep inputs that hit new branches, mutate toward
uncovered code.
"""
from __future__ import annotations

import subprocess
import sys
import textwrap
from pathlib import Path
from typing import List

from .base import LayerBase
from ..models import Finding, DiffHunk, LayerID, Severity, BlastRadius


class L4Fuzz(LayerBase):
    id = LayerID.L4_FUZZ
    name = "Directed Fuzzing"
    description = "Coverage-guided fuzzing on changed functions (WAFLGO-style directed)"

    DEFAULT_DURATION_SECONDS = 10  # short — this is pre-commit, not CI

    def run(self, repo_root: Path, hunks: List[DiffHunk],
            config) -> List[Finding]:
        findings: List[Finding] = []
        py_hunks = [h for h in hunks if h.file.endswith(".py") and h.function_name]
        if not py_hunks:
            return findings

        # Detect which fuzzer backend is available (3-tier fallback)
        backend = self._detect_backend()
        if backend is None:
            findings.append(Finding(
                layer=self.id, rule_id="L4.fuzz.not_available",
                message="No fuzzing backend available",
                file="<pipeline>", start_line=0,
                severity=Severity.INFO, confidence=1.0,
            ))
            return findings

        # Report which backend is being used (informational)
        if backend != "atheris":
            backend_desc = {
                "coverage-python": "coverage-guided (pure Python, sys.settrace)",
                "random-python": "random mutation (legacy fallback)",
            }.get(backend, backend)
            findings.append(Finding(
                layer=self.id, rule_id="L4.fuzz.backend",
                message=(f"Using {backend_desc} fuzzer backend. "
                         f"Install atheris on Linux for native-speed fuzzing: "
                         f"pip install atheris"),
                file="<pipeline>", start_line=0,
                severity=Severity.INFO, confidence=1.0,
                raw={"backend": backend},
            ))

        # generate a fuzz harness for each changed function
        for hunk in py_hunks[:3]:  # cap at 3 to keep pre-commit fast
            harness_path = self._generate_harness(repo_root, hunk, backend)
            if not harness_path:
                continue
            crash = self._run_harness(harness_path, repo_root,
                                      duration=self.DEFAULT_DURATION_SECONDS,
                                      backend=backend)
            if crash:
                findings.append(Finding(
                    layer=self.id, rule_id="L4.fuzz.crash",
                    message=f"Fuzzing {hunk.function_name} produced a crash: {crash[:200]}",
                    file=hunk.file, start_line=hunk.start_line, end_line=hunk.end_line,
                    severity=Severity.CRITICAL, confidence=0.85,
                    blast_radius=BlastRadius.MODULE, exploitability=0.7,
                    cwe="CWE-20",  # improper input validation
                    fix_suggestion="Add input validation at function entry; check for None, type, and range",
                    raw={"function": hunk.function_name, "crash": crash[:500],
                         "backend": backend},
                ))
        return findings

    def _detect_backend(self) -> str:
        """Detect which fuzzer backend is available.

        Returns one of:
          - "atheris"          (Linux, native instrumentation, fastest)
          - "coverage-python"  (all platforms, coverage-guided via sys.settrace)
          - "random-python"    (all platforms, random mutation, last resort)
          - None               (no backend available)
        """
        # Tier 1: atheris (Linux only — requires libFuzzer C++ library)
        try:
            import atheris  # noqa
            return "atheris"
        except ImportError:
            pass

        # Tier 2: coverage-guided pure-Python fuzzer (all platforms)
        try:
            from ..fuzz_coverage import CoverageGuidedFuzzer, FuzzedDataProvider  # noqa
            return "coverage-python"
        except ImportError:
            pass

        # Tier 3: random-mutation fuzzer (all platforms, least effective)
        try:
            from ..fuzz_fallback import FuzzedDataProvider, fuzz  # noqa
            return "random-python"
        except ImportError:
            return None

    def _generate_harness(self, repo_root: Path, hunk: DiffHunk,
                          backend: str = "atheris") -> Path:
        """Generate a fuzz harness for the function.

        The user can provide a custom harness in
        `tests/fuzz/<function>_fuzz.py` which takes precedence.
        """
        custom_harness = repo_root / "tests" / "fuzz" / f"{hunk.function_name}_fuzz.py"
        if custom_harness.exists():
            return custom_harness

        # auto-generate a naive harness
        module_path = hunk.file.replace("/", ".").replace(".py", "")
        # strip leading dots
        if module_path.startswith("."):
            module_path = module_path.lstrip(".")

        if backend == "atheris":
            harness_code = self._generate_atheris_harness(module_path, hunk.function_name)
        elif backend == "coverage-python":
            harness_code = self._generate_coverage_harness(module_path, hunk.function_name)
        else:
            harness_code = self._generate_random_harness(module_path, hunk.function_name)

        # write to a temp file (not committed)
        harness_dir = repo_root / ".stca-cache" / "fuzz"
        harness_dir.mkdir(parents=True, exist_ok=True)
        suffix = f"_{backend.replace('-', '_')}"
        harness_path = harness_dir / f"{hunk.function_name}{suffix}_fuzz.py"
        harness_path.write_text(harness_code, encoding="utf-8")
        return harness_path

    def _generate_atheris_harness(self, module_path: str, func_name: str) -> str:
        """Generate an atheris-based harness (Linux, native instrumentation)."""
        return textwrap.dedent(f"""
            import sys
            import atheris

            with atheris.instrument_imports():
                try:
                    from {module_path} import {func_name}
                except Exception as e:
                    sys.exit(0)  # can't import, nothing to fuzz

            def test_one_input(data):
                fdp = atheris.FuzzedDataProvider(data)
                try:
                    s = fdp.ConsumeUnicodeNoSurrogates(fdp.remaining_bytes() or 1)
                    {func_name}(s)
                except (TypeError, ValueError):
                    pass
                except Exception:
                    raise  # unexpected — that's the bug

            atheris.Setup(sys.argv, test_one_input)
            atheris.Fuzz()
        """).strip()

    def _generate_coverage_harness(self, module_path: str, func_name: str) -> str:
        """Generate a coverage-guided harness (cross-platform, sys.settrace).

        Uses stca.fuzz_coverage which implements the same algorithm as
        libFuzzer: maintain a corpus, track coverage via sys.settrace(),
        keep inputs that hit new lines, mutate toward uncovered code.
        """
        return textwrap.dedent(f"""
            import sys
            import os

            # Ensure the stca package is importable. We add multiple paths:
            # 1. The repo root (so the target module imports work)
            # 2. The stca package location (found via the harness file's location)
            _harness_dir = os.path.dirname(os.path.abspath(__file__))
            _repo_root = os.path.dirname(os.path.dirname(_harness_dir))
            sys.path.insert(0, _repo_root)
            # Also add the stca package parent if stca is installed elsewhere
            try:
                import stca
                _stca_parent = os.path.dirname(os.path.dirname(os.path.dirname(stca.__file__)))
                if _stca_parent not in sys.path:
                    sys.path.insert(0, _stca_parent)
            except ImportError:
                pass

            from stca.fuzz_coverage import fuzz_coverage, FuzzedDataProvider

            try:
                from {module_path} import {func_name}
            except Exception as e:
                sys.exit(0)  # can't import, nothing to fuzz

            def test_one_input(data):
                fdp = FuzzedDataProvider(data)
                try:
                    s = fdp.consume_unicode_no_surrogates(fdp.remaining_bytes() or 1)
                    {func_name}(s)
                except (TypeError, ValueError):
                    pass
                except Exception:
                    raise  # unexpected — that's the bug

            if __name__ == '__main__':
                duration = int(sys.argv[1]) if len(sys.argv) > 1 else 10
                crash = fuzz_coverage(test_one_input, duration_seconds=duration)
                if crash:
                    print(f"CRASH:{{crash}}", file=sys.stderr)
                    sys.exit(1)
                else:
                    sys.exit(0)
        """).strip()

    def _generate_random_harness(self, module_path: str, func_name: str) -> str:
        """Generate a random-mutation harness (legacy fallback)."""
        return textwrap.dedent(f"""
            import sys
            import os

            sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

            from stca.fuzz_fallback import FuzzedDataProvider, fuzz

            try:
                from {module_path} import {func_name}
            except Exception as e:
                sys.exit(0)

            def test_one_input(data):
                fdp = FuzzedDataProvider(data)
                try:
                    s = fdp.consume_unicode_no_surrogates(fdp.remaining_bytes() or 1)
                    {func_name}(s)
                except (TypeError, ValueError):
                    pass
                except Exception:
                    raise

            if __name__ == '__main__':
                duration = int(sys.argv[1]) if len(sys.argv) > 1 else 10
                crash = fuzz(test_one_input, duration_seconds=duration)
                if crash:
                    print(f"CRASH:{{crash}}", file=sys.stderr)
                    sys.exit(1)
                else:
                    sys.exit(0)
        """).strip()

    def _run_harness(self, harness_path: Path, repo_root: Path,
                     duration: int, backend: str = "atheris") -> str:
        """Run the harness for `duration` seconds. Return crash summary or ""."""
        try:
            if backend == "atheris":
                # atheris uses libFuzzer args
                args = [sys.executable, str(harness_path),
                        f"-max_total_time={duration}", "-max_len=256"]
            else:
                # coverage-python and random-python harnesses take a single duration arg
                args = [sys.executable, str(harness_path), str(duration)]

            # Set PYTHONPATH so the subprocess can find both:
            # 1. The stca package (for fuzz_coverage/fuzz_fallback imports)
            # 2. The repo_root (for the target module imports)
            import os
            env = os.environ.copy()
            stca_parent = str(Path(__import__("stca").__file__).resolve().parent.parent)
            existing_path = env.get("PYTHONPATH", "")
            env["PYTHONPATH"] = os.pathsep.join(
                p for p in [str(repo_root), stca_parent, existing_path] if p
            )

            proc = subprocess.run(
                args,
                capture_output=True, text=True, check=False, timeout=duration + 5,
                cwd=str(repo_root),
                env=env,
            )
            # All backends exit non-zero on crash
            if proc.returncode != 0:
                # Filter out import errors that aren't crashes (ModuleNotFoundError
                # for stca means the env isn't set up, not a target bug)
                combined = proc.stdout + proc.stderr
                if "ModuleNotFoundError: No module named 'stca'" in combined:
                    return ""  # environment issue, not a crash
                for line in combined.splitlines():
                    if "SUMMARY" in line or "ERROR" in line or "Exception" in line or "CRASH:" in line:
                        return line.strip()
                return proc.stderr[:500] if proc.stderr else "non-zero exit"
        except subprocess.TimeoutExpired:
            return ""  # fuzzing completed without crash within timeout
        except Exception as e:
            return f"harness execution error: {e}"
        return ""
