"""Learning & adaptation: code embeddings, active learning, GNN-on-CPG.

Three components that turn the deterministic pipeline into one that learns
from feedback and improves over time — without requiring a GPU or large
training corpora.

  - CodeEmbeddings:        character 3-gram TF vectors + cosine similarity
  - ActiveLearning:        pick which findings a human should label next
  - GNNOnCPG:              tiny per-language graph-feature scorer over the CPG
"""
from __future__ import annotations
from .text_utils import extract_block as _shared_extract_block

import hashlib
import json
import math
import re
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple


# =============================================================================
# Code embeddings (character 3-gram TF)
# =============================================================================

class CodeEmbeddings:
    """Character 3-gram TF embeddings.

    Surprisingly effective for "find similar code" tasks because most bug
    patterns share lexical structure (variable names, operator order, etc.).
    Embeddings are sparse dicts {trigram: count} for memory efficiency.
    """

    def __init__(self, n: int = 3) -> None:
        self.n = n
        self.vectors: Dict[str, Dict[str, float]] = {}

    def embed(self, code: str) -> Dict[str, float]:
        code = re.sub(r"\s+", " ", code).strip()
        if len(code) < self.n:
            return {code: 1.0} if code else {}
        counts: Counter = Counter()
        for i in range(len(code) - self.n + 1):
            counts[code[i:i + self.n]] += 1
        # L1-normalize so longer snippets don't dominate
        total = sum(counts.values()) or 1
        return {k: v / total for k, v in counts.items()}

    def add(self, key: str, code: str) -> None:
        self.vectors[key] = self.embed(code)

    def similarity(self, a: Dict[str, float], b: Dict[str, float]) -> float:
        """Cosine similarity between two sparse vectors."""
        if not a or not b:
            return 0.0
        # iterate over the smaller dict
        if len(a) > len(b):
            a, b = b, a
        dot = 0.0
        for k, v in a.items():
            if k in b:
                dot += v * b[k]
        norm_a = math.sqrt(sum(v * v for v in a.values()))
        norm_b = math.sqrt(sum(v * v for v in b.values()))
        if norm_a == 0 or norm_b == 0:
            return 0.0
        return dot / (norm_a * norm_b)

    def find_similar(self, code: str, top_k: int = 5) -> List[Tuple[str, float]]:
        """Return the top-k most similar snippets from the index."""
        q = self.embed(code)
        scores = [(key, self.similarity(q, v)) for key, v in self.vectors.items()]
        scores.sort(key=lambda x: x[1], reverse=True)
        return scores[:top_k]

    def save(self, path: Path) -> None:
        try:
            path.write_text(json.dumps(self.vectors), encoding="utf-8")
        except Exception:
            pass

    def load(self, path: Path) -> None:
        try:
            self.vectors = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            self.vectors = {}


# =============================================================================
# Active learning
# =============================================================================

@dataclass
class LearningCandidate:
    """A finding suggested for human labeling."""
    finding_key: str
    rule_id: str
    file: str
    line: int
    informativeness: float   # higher = more informative to label
    reason: str = ""


class ActiveLearning:
    """Suggest which findings a human should label next.

    Uses three signals:
      - uncertainty:    findings near the warn/pass FIS boundary (0.4-0.6)
      - novelty:        findings on rules with <5 historical labels
      - disagreement:   findings where FIS and counterfactual disagree
    """

    def __init__(self, label_counts: Optional[Dict[str, int]] = None) -> None:
        self.label_counts: Dict[str, int] = label_counts or {}

    def suggest(self, findings: List[dict], top_k: int = 10) -> List[LearningCandidate]:
        cands: List[LearningCandidate] = []
        for f in findings:
            rule_id = f.get("rule_id", "")
            conf = float(f.get("confidence", 0.5))
            uncertainty = 1.0 - abs(conf - 0.5) * 2  # peaks at 0.5
            labels = self.label_counts.get(rule_id, 0)
            novelty = 1.0 / (1.0 + labels)            # less-labeled rules are more novel
            disagree = 1.0 if f.get("counterfactual_disagree") else 0.0
            score = 0.5 * uncertainty + 0.3 * novelty + 0.2 * disagree
            cands.append(LearningCandidate(
                finding_key=f.get("fingerprint", f"{f.get('file','')}:{f.get('line',0)}:{rule_id}"),
                rule_id=rule_id, file=f.get("file", ""), line=int(f.get("line", 0)),
                informativeness=score,
                reason=f"uncertainty={uncertainty:.2f} novelty={novelty:.2f} "
                       f"disagreement={disagree:.2f}"))
        cands.sort(key=lambda c: c.informativeness, reverse=True)
        return cands[:top_k]

    def record_label(self, rule_id: str) -> None:
        self.label_counts[rule_id] = self.label_counts.get(rule_id, 0) + 1


# =============================================================================
# GNN-on-CPG (graph-feature scorer)
# =============================================================================

# Per-language function-definition regexes. The "GNN" is a hand-crafted
# feature scorer over the Code Property Graph neighborhood of each function —
# no learned weights, no GPU, no ML framework. Just graph features + sigmoid.

_FUNC_REGEX: Dict[str, re.Pattern] = {
    "python": re.compile(
        r"^(?P<indent>\s*)(?:async\s+)?def\s+(?P<name>\w+)\s*\((?P<args>[^)]*)\)\s*(?:->\s*[^:]+)?:",
        re.MULTILINE),
    "javascript": re.compile(
        r"(?:async\s+)?function\s+(?P<name>\w+)\s*\((?P<args>[^)]*)\)\s*\{|"
        r"(?:const|let|var)\s+(?P<name2>\w+)\s*=\s*(?:async\s*)?\((?P<args2>[^)]*)\)\s*=>\s*\{",
        re.MULTILINE),
    "go": re.compile(
        r"^func\s+(?:\([^)]*\)\s+)?(?P<name>\w+)\s*\((?P<args>[^)]*)\)\s*(?:\([^)]*\))?\s*\{",
        re.MULTILINE),
    "java": re.compile(
        r"(?:public|private|protected|static)\s+[\w<>\[\]]+\s+(?P<name>\w+)\s*\((?P<args>[^)]*)\)\s*(?:throws\s+[\w.,\s]+)?\{",
        re.MULTILINE),
    "cpp": re.compile(
        r"(?:[\w:<>\*&]+\s+)+(?P<name>\w+)\s*\((?P<args>[^)]*)\)\s*(?:const)?\s*\{",
        re.MULTILINE),
}

_SENSITIVE_TOKENS = re.compile(
    r"\b(password|secret|token|key|admin|root|exec|eval|sql|query|delete|"
    r"update|insert|drop|system|cmd|shell|os\.|subprocess|pickle|yaml\.load|"
    r"innerHTML|document\.write|dangerouslySetInnerHTML)\b", re.IGNORECASE)

_UNSAFE_LIBS = re.compile(
    r"\b(?:md5|sha1|DES|ECB|PKCS1_v1_5|random\.|Math\.random|strcpy|gets|sprintf)\b")


@dataclass
class GNNResult:
    function: str
    file: str
    line: int
    score: float           # 0..1 risk score
    features: Dict[str, float] = field(default_factory=dict)
    language: str = ""


class GNNOnCPG:
    """Tiny graph-feature scorer over per-function CPG neighborhoods.

    Features extracted per function:
      - num_calls:             call-site count (fan-out)
      - num_branches:          if/elif/else count
      - num_loops:             for/while count
      - num_sensitive_tokens:  count of dangerous-symbols in body
      - num_unsafe_libs:       count of weak crypto / unsafe API uses
      - num_args:              arity
      - has_try:               exception handling?
      - body_length:           lines of code

    Score = sigmoid(w · features) where w is a fixed, hand-tuned weight vector.
    """

    WEIGHTS: Dict[str, float] = {
        "num_calls": 0.10,
        "num_branches": 0.05,
        "num_loops": 0.08,
        "num_sensitive_tokens": 0.30,
        "num_unsafe_libs": 0.45,
        "num_args": 0.02,
        "has_try": -0.10,
        "body_length": 0.005,
    }

    def __init__(self, language: str = "python") -> None:
        self.language = language

    def score_file(self, file_path: Path) -> List[GNNResult]:
        if not file_path.exists():
            return []
        try:
            source = file_path.read_text(encoding="utf-8", errors="replace")
        except Exception:
            return []
        return self._score_source(source, str(file_path))

    def _score_source(self, source: str, file: str) -> List[GNNResult]:
        rx = _FUNC_REGEX.get(self.language)
        if not rx:
            return []
        out: List[GNNResult] = []
        for m in rx.finditer(source):
            name = m.group("name") or (m.groupdict().get("name2") or "<anon>")
            args_str = m.group("args") or (m.groupdict().get("args2") or "")
            start = m.end()
            body = self._extract_block(source, start)
            line = source[:m.start()].count("\n") + 1
            feats = self._extract_features(args_str, body)
            score = self._score(feats)
            out.append(GNNResult(
                function=name, file=file, line=line,
                score=score, features=feats, language=self.language))
        return out
    def _extract_block(self, source: str, start: int) -> str:
        return _shared_extract_block(source, start)
        return body

    def _extract_features(self, args_str: str, body: str) -> Dict[str, float]:
        args = [a.strip() for a in args_str.split(",") if a.strip()]
        return {
            "num_calls": float(len(re.findall(r"\w+\s*\(", body))),
            "num_branches": float(len(re.findall(r"\bif\b|\belif\b|\belse\b", body))),
            "num_loops": float(len(re.findall(r"\bfor\b|\bwhile\b", body))),
            "num_sensitive_tokens": float(len(_SENSITIVE_TOKENS.findall(body))),
            "num_unsafe_libs": float(len(_UNSAFE_LIBS.findall(body))),
            "num_args": float(len(args)),
            "has_try": 1.0 if re.search(r"\btry\b|\bcatch\b|\bexcept\b", body) else 0.0,
            "body_length": float(body.count("\n")),
        }

    def _score(self, feats: Dict[str, float]) -> float:
        z = sum(self.WEIGHTS.get(k, 0.0) * v for k, v in feats.items())
        return 1.0 / (1.0 + math.exp(-z))


def scan_repo_with_gnn(repo_root: Path) -> List[GNNResult]:
    """Walk a repo, detect language per file, and score every function."""
    from .multi_lang import get_language
    out: List[GNNResult] = []
    skip = {"node_modules", ".git", "vendor", "__pycache__", "dist", "build"}
    for path in repo_root.rglob("*"):
        if not path.is_file():
            continue
        if any(s in str(path) for s in skip):
            continue
        lang = get_language(path)
        if lang == "unknown":
            continue
        gnn = GNNOnCPG(language=lang)
        out.extend(gnn.score_file(path))
    return out
