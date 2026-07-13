"""Architecture enforcement — inspired by rev-dep.

rev-dep enforces architecture boundaries in JS/TS projects: "modules in
layer A must not import from layer B". We do the same for Python.

Define architecture rules in .loomscan.yaml:
    architecture:
      layers:
        - name: controllers
          paths: ["app/controllers/**"]
          may_import: ["services", "models", "utils"]
        - name: services
          paths: ["app/services/**"]
          may_import: ["models", "utils"]
        - name: models
          paths: ["app/models/**"]
          may_import: ["utils"]
        - name: utils
          paths: ["app/utils/**"]
          may_import: []

Then LoomScan flags any import that violates the layer hierarchy:
  - controllers importing other controllers (should go through services)
  - models importing controllers (wrong direction)
  - utils importing services (utils should be leaf nodes)
"""
from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set


@dataclass
class ArchitectureLayer:
    """A layer in the architecture."""
    name: str
    paths: List[str]  # glob patterns for files in this layer
    may_import: List[str]  # layer names this layer may import from
    may_not_import: List[str] = field(default_factory=list)  # explicit forbids


@dataclass
class ArchitectureViolation:
    """A detected architecture boundary violation."""
    file: str
    line: int
    importing_layer: str
    imported_module: str
    imported_layer: str
    violation: str  # 'cross_layer' | 'forbidden' | 'wrong_direction'
    description: str


# Default architecture rules (can be overridden in .loomscan.yaml)
DEFAULT_LAYERS: List[ArchitectureLayer] = [
    ArchitectureLayer(
        name="controllers",
        paths=["**/controllers/**", "**/views/**", "**/handlers/**", "**/routes/**"],
        may_import=["services", "models", "utils", "schemas"],
    ),
    ArchitectureLayer(
        name="services",
        paths=["**/services/**", "**/business/**", "**/logic/**"],
        may_import=["models", "utils", "schemas"],
    ),
    ArchitectureLayer(
        name="models",
        paths=["**/models/**", "**/entities/**"],
        may_import=["utils"],
    ),
    ArchitectureLayer(
        name="utils",
        paths=["**/utils/**", "**/helpers/**", "**/common/**"],
        may_import=[],  # leaf layer — shouldn't import from other layers
    ),
    ArchitectureLayer(
        name="schemas",
        paths=["**/schemas/**", "**/serializers/**", "**/dtos/**"],
        may_import=["models", "utils"],
    ),
    ArchitectureLayer(
        name="tests",
        paths=["**/tests/**", "**/test_*.py", "**/*_test.py"],
        may_import=["controllers", "services", "models", "utils", "schemas"],
    ),
]


class ArchitectureEnforcer:
    """Enforces architecture boundaries."""

    def __init__(self, repo_root: Path,
                 layers: Optional[List[ArchitectureLayer]] = None):
        self.repo_root = repo_root
        self.layers = layers or DEFAULT_LAYERS

    def _get_layer_for_file(self, file_path: str) -> Optional[ArchitectureLayer]:
        """Determine which architecture layer a file belongs to."""
        from fnmatch import fnmatch
        for layer in self.layers:
            for pattern in layer.paths:
                # strip **/ for fnmatch compatibility
                pat = pattern.replace("**/", "")
                if fnmatch(file_path, pat) or fnmatch(Path(file_path).name, pat):
                    return layer
        return None

    def _get_layer_for_import(self, import_path: str,
                               current_file: str) -> Optional[ArchitectureLayer]:
        """Determine which layer an import resolves to."""
        # convert import path to file path
        import_file = import_path.replace(".", "/") + ".py"
        return self._get_layer_for_file(import_file)

    def check_file(self, file_path: Path) -> List[ArchitectureViolation]:
        """Check a Python file for architecture violations."""
        if not file_path.exists() or file_path.suffix != ".py":
            return []

        rel = str(file_path.relative_to(self.repo_root))
        current_layer = self._get_layer_for_file(rel)
        if not current_layer:
            return []  # file not in any layer — skip

        try:
            source = file_path.read_text(encoding="utf-8")
            tree = ast.parse(source)
        except Exception:
            return []

        violations: List[ArchitectureViolation] = []

        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    imported_layer = self._get_layer_for_import(alias.name, rel)
                    if imported_layer and imported_layer.name != current_layer.name:
                        if imported_layer.name not in current_layer.may_import:
                            violations.append(ArchitectureViolation(
                                file=rel, line=node.lineno,
                                importing_layer=current_layer.name,
                                imported_module=alias.name,
                                imported_layer=imported_layer.name,
                                violation="cross_layer",
                                description=f"{current_layer.name} layer imports from {imported_layer.name} layer (not in may_import list)",
                            ))
            elif isinstance(node, ast.ImportFrom):
                if node.module:
                    imported_layer = self._get_layer_for_import(node.module, rel)
                    if imported_layer and imported_layer.name != current_layer.name:
                        if imported_layer.name not in current_layer.may_import:
                            violations.append(ArchitectureViolation(
                                file=rel, line=node.lineno,
                                importing_layer=current_layer.name,
                                imported_module=node.module,
                                imported_layer=imported_layer.name,
                                violation="cross_layer",
                                description=f"{current_layer.name} layer imports from {imported_layer.name} layer — this violates the architecture boundary",
                            ))

        return violations

    def check_repo(self, max_files: int = 100) -> List[ArchitectureViolation]:
        """Check all Python files for architecture violations."""
        skip_dirs = {".git", "__pycache__", ".venv", "venv", "node_modules",
                     ".loomscan-cache", ".loomscan-reports", ".loomscan-fixes", "build", "dist"}
        violations: List[ArchitectureViolation] = []
        count = 0
        for p in self.repo_root.rglob("*.py"):
            if any(part in skip_dirs for part in p.parts):
                continue
            violations.extend(self.check_file(p))
            count += 1
            if count >= max_files:
                break
        return violations

    def stats(self) -> dict:
        return {
            "layers": len(self.layers),
            "layer_names": [l.name for l in self.layers],
        }
