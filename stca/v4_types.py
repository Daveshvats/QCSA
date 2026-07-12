"""v4.27: Shared types for all v4 modules. Breaks circular imports."""
from __future__ import annotations
from dataclasses import dataclass, field
from typing import Dict, Any
from pathlib import Path


@dataclass
class UnifiedFinding:
    """A finding from any v4 scanner — unified format for all languages."""
    rule_id: str
    severity: str
    description: str
    file: str
    line: int
    function: str = ""
    language: str = ""
    category: str = ""
    cwe: str = ""
    suggestion: str = ""
    evidence: str = ""
    raw: Dict[str, Any] = None


def _detect_lang_by_ext(file_path):
    """Detect language by file extension (fallback when tree-sitter unavailable)."""
    if not isinstance(file_path, Path):
        file_path = Path(file_path)
    ext = file_path.suffix.lower()
    if ext == ".py": return "python"
    if ext in (".js", ".jsx", ".mjs", ".cjs"): return "javascript"
    if ext in (".ts", ".tsx"): return "typescript"
    if ext == ".go": return "go"
    if ext == ".java": return "java"
    if ext in (".c", ".h"): return "c"
    if ext in (".cpp", ".cc", ".cxx", ".hpp", ".hxx"): return "cpp"
    if ext == ".rs": return "rust"
    if ext in (".php", ".phtml"): return "php"
    if ext in (".rb", ".rake"): return "ruby"
    if ext == ".cs": return "csharp"
    if ext in (".kt", ".kts"): return "kotlin"
    if ext == ".swift": return "swift"
    if ext in (".scala", ".sc"): return "scala"
    return "unknown"
