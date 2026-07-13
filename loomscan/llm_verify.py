"""LLM-as-oracle with verified reasoning.

Most LLM-based bug detectors fail because:
  1. LLMs hallucinate bugs that don't exist
  2. LLMs can't explain WHY a bug is a bug
  3. There's no way to verify the LLM's claim

This module uses a different pattern: the LLM proposes a potential bug,
then we VERIFY it with deterministic execution. The LLM is the hypothesis
generator; deterministic execution is the oracle.

Pattern (LLM-Verify):
  1. LLM proposes: "I think function foo() crashes on input None"
  2. LoomScan verifies: actually call foo(None) in a sandbox
  3. If foo(None) raises → confirmed bug; if it returns → false positive, drop

This is the "LLM as hypothesis generator, deterministic oracle as verifier"
pattern from the 2024-2025 LLM4SE research wave.

We do NOT use the LLM to:
  - Generate patches (we have L8 Auto-Fix for that)
  - Decide whether to flag (the FIS does that)
  - Aggregate findings (the FIS does that)

The LLM is ONLY a hypothesis generator, and every hypothesis is verified.
"""
from __future__ import annotations

import ast
import json
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import List, Optional, Tuple
from dataclasses import dataclass


@dataclass
class LLMHypothesis:
    """A bug hypothesis proposed by the LLM."""
    function: str
    file: str
    hypothesis: str  # human-readable description
    test_input: str  # the input the LLM thinks triggers the bug
    expected_behavior: str  # what should happen
    expected_failure: str  # what the LLM thinks will happen


@dataclass
class VerifiedBug:
    """An LLM hypothesis that was confirmed by execution."""
    function: str
    file: str
    hypothesis: str
    test_input: str
    actual_error: str  # the actual exception/crash observed
    cwe: str = "CWE-754"  # improper check for unusual condition


def generate_hypotheses(function_name: str, function_body: str,
                         llm_client=None, language: str = "python") -> List[LLMHypothesis]:
    """Ask the LLM to propose potential bugs in a function.

    Returns a list of testable hypotheses. Each hypothesis is verifiable:
    we can construct the input and check the outcome.

    v5.3: Added language parameter — supports python, javascript, java, go.
    For non-Python languages, hypotheses are generated but not executed
    (no runtime verification — the LLM's analysis is reported as-is).
    """
    if llm_client is None or not llm_client.is_available():
        return []

    # v5.3: Language-aware prompt
    lang_labels = {
        "python": ("Python", "python"),
        "javascript": ("JavaScript", "javascript"),
        "java": ("Java", "java"),
        "go": ("Go", "go"),
    }
    lang_name, lang_code = lang_labels.get(language, ("Python", "python"))

    prompt = f"""Analyze this {lang_name} function for potential bugs. For each bug you hypothesize,
provide a SPECIFIC input that would trigger it, and what you expect to happen.

Function:
```{lang_code}
{function_body[:1500]}
```

Respond in JSON:
{{
  "hypotheses": [
    {{
      "function": "{function_name}",
      "hypothesis": "description of the bug",
      "test_input": "Python expression that produces the triggering input, e.g. `None` or `[1,2,3]` or `'-' * 1000`",
      "expected_behavior": "what the function SHOULD do with this input",
      "expected_failure": "what you predict will happen (e.g. 'raises TypeError', 'returns None', 'infinite loop')"
    }}
  ]
}}

Only propose hypotheses that can be verified by calling the function with a single argument.
Limit to 3-5 high-confidence hypotheses. Skip style/naming issues — focus on bugs that
would crash or produce wrong output.
"""
    raw = llm_client.generate(prompt, system="You are a Python bug-finding expert. Be precise and testable.",
                               temperature=0.2)
    if not raw:
        return []

    try:
        start = raw.find("{")
        end = raw.rfind("}")
        if start == -1 or end == -1:
            return []
        data = json.loads(raw[start:end+1])
    except json.JSONDecodeError:
        return []

    hypotheses: List[LLMHypothesis] = []
    for h in data.get("hypotheses", []):
        hypotheses.append(LLMHypothesis(
            function=h.get("function", function_name),
            file="",  # filled in by caller
            hypothesis=h.get("hypothesis", ""),
            test_input=h.get("test_input", "None"),
            expected_behavior=h.get("expected_behavior", ""),
            expected_failure=h.get("expected_failure", ""),
        ))
    return hypotheses


def verify_hypothesis(hypothesis: LLMHypothesis,
                       file_path: Path,
                       repo_root: Path = None,
                       language: str = "python") -> Optional[VerifiedBug]:
    """Verify a hypothesis by executing the function with the test input.

    Returns a VerifiedBug if the hypothesis is confirmed, None otherwise.

    v5.3: For non-Python languages, the hypothesis is reported as a
    "static hypothesis" (not execution-verified) since we can't run
    JS/Java/Go code in the LoomScan runtime.
    """
    if not file_path.exists():
        return None
    rel_path = str(file_path.relative_to(repo_root)) if repo_root else str(file_path)

    # v5.3: For non-Python, return the hypothesis as a static finding
    if language != "python":
        return VerifiedBug(
            function=hypothesis.function,
            hypothesis=hypothesis.hypothesis,
            test_input=hypothesis.test_input,
            actual_error=f"[Static analysis — not execution-verified] {hypothesis.expected_failure}",
            cwe="CWE-754",
        )

    # Python: execution-verified
    module_path = rel_path.replace("/", ".").replace(".py", "").lstrip(".")

    # Build a small test script that imports the function and calls it
    test_script = f"""
import sys
import json
import traceback

try:
    from {module_path} import {hypothesis.function}
except Exception as e:
    print(json.dumps({{"import_error": str(e)}}))
    sys.exit(0)

try:
    test_input = {hypothesis.test_input}
except Exception as e:
    print(json.dumps({{"input_construction_error": str(e)}}))
    sys.exit(0)

try:
    result = {hypothesis.function}(test_input)
    print(json.dumps({{"result": repr(result)[:500]}}))
except Exception as e:
    print(json.dumps({{"exception": type(e).__name__, "message": str(e)[:500],
                       "traceback": traceback.format_exc()[:1000]}}))
"""

    # write to temp file and run
    with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False, encoding="utf-8") as f:
        f.write(test_script)
        temp_path = Path(f.name)

    try:
        proc = subprocess.run(
            [sys.executable, str(temp_path)],
            capture_output=True, text=True, check=False, timeout=10,
            cwd=str(repo_root or file_path.parent),
        )
    except subprocess.TimeoutExpired:
        # function hung — that's also a bug
        return VerifiedBug(
            function=hypothesis.function,
            file=rel_path,
            hypothesis=hypothesis.hypothesis,
            test_input=hypothesis.test_input,
            actual_error="Timeout (function did not return within 10s)",
            cwe="CWE-835",  # loop with unreachable exit condition
        )
    finally:
        temp_path.unlink(missing_ok=True)

    try:
        result = json.loads(proc.stdout)
    except json.JSONDecodeError:
        return None

    # check if the hypothesis was confirmed
    if "exception" in result:
        # the function crashed — hypothesis is likely correct
        return VerifiedBug(
            function=hypothesis.function,
            file=rel_path,
            hypothesis=hypothesis.hypothesis,
            test_input=hypothesis.test_input,
            actual_error=f"{result['exception']}: {result['message']}",
        )
    if "import_error" in result:
        return None  # can't verify — function not importable
    if "input_construction_error" in result:
        return None  # LLM gave a bad test_input
    # function returned successfully — check if expected_behavior was violated
    # (we don't auto-judge this; the FIS will treat the hypothesis as unverified)
    return None


def llm_verify_function(file_path: Path, function_name: str,
                         function_body: str,
                         llm_client=None,
                         repo_root: Path = None,
                         language: str = "python") -> List[VerifiedBug]:
    """End-to-end: generate hypotheses, verify them, return confirmed bugs.

    v5.3: Added language parameter. For non-Python languages, hypotheses
    are generated by the LLM but reported as static (not execution-verified).
    """
    hypotheses = generate_hypotheses(function_name, function_body, llm_client, language=language)
    confirmed: List[VerifiedBug] = []
    for h in hypotheses:
        h.file = str(file_path.relative_to(repo_root)) if repo_root else str(file_path)
        verified = verify_hypothesis(h, file_path, repo_root, language=language)
        if verified:
            confirmed.append(verified)
    return confirmed
