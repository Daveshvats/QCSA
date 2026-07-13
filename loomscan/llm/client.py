"""Ollama-based LLM client.

Minimal HTTP client to a local Ollama instance. No SDK dependency.
Falls back gracefully if Ollama isn't running — the pipeline stays deterministic.
"""
from __future__ import annotations

import json
import urllib.request
import urllib.error
from typing import Optional, Dict, Any, List


class LLMClient:
    def __init__(self, endpoint: str = "http://localhost:11434",
                 model: str = "qwen3-coder-1.5b", timeout: int = 60):
        self.endpoint = endpoint.rstrip("/")
        self.model = model
        self.timeout = timeout

    def is_available(self) -> bool:
        """Quick health check."""
        try:
            req = urllib.request.Request(f"{self.endpoint}/api/tags", method="GET")
            with urllib.request.urlopen(req, timeout=3) as resp:
                return resp.status == 200
        except Exception:
            return False

    def generate(self, prompt: str, system: str = "",
                 temperature: float = 0.2) -> Optional[str]:
        """Generate a completion. Returns None on failure."""
        if not self.is_available():
            return None
        payload = {
            "model": self.model,
            "prompt": prompt,
            "system": system,
            "stream": False,
            "options": {"temperature": temperature, "num_predict": 1024},
        }
        try:
            req = urllib.request.Request(
                f"{self.endpoint}/api/generate",
                data=json.dumps(payload).encode("utf-8"),
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                return data.get("response", "").strip()
        except (urllib.error.URLError, json.JSONDecodeError, TimeoutError):
            return None

    def review_finding(self, finding_summary: str, function_body: str,
                       spec_context: str = "") -> Optional[Dict[str, Any]]:
        """Ask the LLM to review a finding the FIS was uncertain about.

        Returns a structured response with: verdict, confidence, reasoning_steps,
        and step_scores (for PRM scoring).
        """
        system = (
            "You are a code reviewer helping triage a static analysis finding. "
            "Be skeptical. If the finding is a false positive, say so. "
            "Respond ONLY in JSON."
        )
        prompt = f"""Review this code review finding:

FINDING: {finding_summary}

FUNCTION UNDER REVIEW:
```python
{function_body[:1500]}
```

ADDITIONAL CONTEXT:
{spec_context or '(no additional context)'}

Respond with JSON in exactly this format:
{{
  "verdict": "confirmed" | "false_positive" | "uncertain",
  "confidence": 0.0-1.0,
  "reasoning_steps": [
    "step 1: ...",
    "step 2: ...",
    "step 3: ..."
  ],
  "suggested_fix": "..."
}}

Limit reasoning to 3-5 concrete steps. Each step must reference a specific line or pattern.
"""
        raw = self.generate(prompt, system=system, temperature=0.1)
        if not raw:
            return None
        # extract JSON from response (LLMs sometimes wrap in markdown)
        try:
            # find first { and last }
            start = raw.find("{")
            end = raw.rfind("}")
            if start == -1 or end == -1:
                return None
            return json.loads(raw[start:end + 1])
        except json.JSONDecodeError:
            return None
