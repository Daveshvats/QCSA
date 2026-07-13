"""Process Reward Model (PRM) — step-level scoring of LLM reasoning.

Inspired by CodePRM (ACL 2025) and FG-PRM (arXiv:2410.06304). Process reward
models score *each step* of an LLM's reasoning, not just the final answer.
This catches hallucinated reasoning that ends in a "plausible-sounding" verdict.

We implement a lightweight heuristic-based PRM (no neural net required) that
scores each reasoning step on:
  - specificity (does it reference a concrete line/pattern?)
  - grounding (does it cite the actual code?)
  - consistency (does it contradict earlier steps?)

Steps with low scores drag down the overall finding confidence.
"""
from __future__ import annotations

import re
from typing import List, Dict, Any


class PRMScorer:
    """Heuristic process reward model."""

    # weights for each scoring dimension
    WEIGHTS = {
        "specificity": 0.35,
        "grounding": 0.35,
        "consistency": 0.20,
        "non_hedging": 0.10,
    }

    HEDGING_WORDS = {"maybe", "possibly", "might", "could", "perhaps",
                     "seems", "appears", "likely", "probably"}

    def score_step(self, step: str, function_body: str) -> Dict[str, float]:
        """Score a single reasoning step."""
        step_lower = step.lower()

        # specificity: does it reference a line number, variable, or function?
        has_line_ref = bool(re.search(r"line\s+\d+", step_lower))
        has_var_ref = bool(re.search(r"`[a-z_][a-z0-9_]*`|'[a-z_][a-z0-9_]*'", step, re.IGNORECASE))
        has_func_ref = bool(re.search(r"\bfunction\b|\bmethod\b|\bcall\b", step_lower))
        specificity = 0.4 * has_line_ref + 0.3 * has_var_ref + 0.3 * has_func_ref

        # grounding: does it cite actual code from the function?
        # check if any 4+ word phrase from the step appears in the function body
        words = re.findall(r"\w+", step)
        grounded = 0
        total_phrases = 0
        for i in range(len(words) - 3):
            phrase = " ".join(words[i:i+4]).lower()
            if len(phrase) > 12:
                total_phrases += 1
                if phrase in function_body.lower():
                    grounded += 1
        grounding = grounded / total_phrases if total_phrases > 0 else 0.0

        # consistency: step doesn't contradict earlier — handled at score_reasoning level
        consistency = 1.0  # default

        # non-hedging: avoid "maybe", "possibly", etc.
        hedging_count = sum(1 for w in self.HEDGING_WORDS if w in step_lower)
        non_hedging = max(0.0, 1.0 - 0.3 * hedging_count)

        return {
            "specificity": specificity,
            "grounding": grounding,
            "consistency": consistency,
            "non_hedging": non_hedging,
            "overall": (
                self.WEIGHTS["specificity"] * specificity +
                self.WEIGHTS["grounding"] * grounding +
                self.WEIGHTS["consistency"] * consistency +
                self.WEIGHTS["non_hedging"] * non_hedging
            ),
        }

    def score_reasoning(self, response: Dict[str, Any],
                        function_body: str) -> Dict[str, Any]:
        """Score an entire LLM response."""
        steps: List[str] = response.get("reasoning_steps", [])
        if not steps:
            return {
                "overall_prm_score": 0.3,
                "step_scores": [],
                "verdict_trusted": False,
                "reason": "no reasoning steps provided",
            }

        step_scores = []
        # check consistency between steps (do later steps contradict earlier?)
        prior_claims = []
        for i, step in enumerate(steps):
            score = self.score_step(step, function_body)
            # consistency check: does this step contradict earlier ones?
            step_lower = step.lower()
            contradiction_penalty = 0.0
            for claim in prior_claims:
                # very simple heuristic: if a previous step said "X is Y"
                # and this step says "X is not Y", that's a contradiction
                if re.search(rf"\b{re.escape(claim)}\b.*\bnot\b", step_lower):
                    contradiction_penalty = 0.5
                    break
            score["consistency"] = max(0.0, 1.0 - contradiction_penalty)
            score["overall"] = (
                self.WEIGHTS["specificity"] * score["specificity"] +
                self.WEIGHTS["grounding"] * score["grounding"] +
                self.WEIGHTS["consistency"] * score["consistency"] +
                self.WEIGHTS["non_hedging"] * score["non_hedging"]
            )
            step_scores.append({"step": step, "score": score})
            # extract simple claims for consistency checking
            claims = re.findall(r"\b([a-z_]\w*)\s+is\s+(\w+)", step_lower)
            prior_claims.extend([c[0] for c in claims])

        # overall PRM score = weighted average of step scores, weighted by step position
        # (later steps weighted more, like a process reward model)
        n = len(step_scores)
        weights = [(i + 1) / (n * (n + 1) / 2) for i in range(n)]
        overall = sum(w * s["score"]["overall"]
                      for w, s in zip(weights, step_scores))

        return {
            "overall_prm_score": overall,
            "step_scores": step_scores,
            "verdict_trusted": overall >= 0.5,
            "reason": f"weighted step-score average: {overall:.2f}",
        }
