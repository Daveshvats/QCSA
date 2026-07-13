"""Knowledge Graph builder — codebase structure graph with impact analysis."""
from __future__ import annotations
import ast, re, json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Set, Tuple, Optional, Any
from collections import defaultdict

@dataclass
class KGNode:
    id: str; kind: str; name: str; file: str; line: int
    language: str = ""; summary: str = ""; layer: str = ""
    attributes: Dict[str, Any] = field(default_factory=dict)

@dataclass
class KGEdge:
    src: str; dst: str; kind: str

@dataclass
class KnowledgeGraph:
    nodes: Dict[str, KGNode] = field(default_factory=dict)
    edges: List[KGEdge] = field(default_factory=list)
    successors: Dict[str, List[Tuple[str, str]]] = field(default_factory=dict)
    predecessors: Dict[str, List[Tuple[str, str]]] = field(default_factory=dict)
    by_name: Dict[str, Set[str]] = field(default_factory=dict)
    by_file: Dict[str, Set[str]] = field(default_factory=dict)
    by_kind: Dict[str, Set[str]] = field(default_factory=dict)

    def add_node(self, node):
        self.nodes[node.id] = node
        self.by_name.setdefault(node.name, set()).add(node.id)
        self.by_file.setdefault(node.file, set()).add(node.id)
        self.by_kind.setdefault(node.kind, set()).add(node.id)

    def add_edge(self, src, dst, kind):
        self.edges.append(KGEdge(src=src, dst=dst, kind=kind))
        self.successors.setdefault(src, []).append((kind, dst))
        self.predecessors.setdefault(dst, []).append((kind, src))

    def get_callers(self, name):
        return [self.nodes[cid] for tid in self.by_name.get(name, set())
                for k, cid in self.predecessors.get(tid, []) if k == "calls" and cid in self.nodes]

    def get_callees(self, name):
        return [self.nodes[cid] for tid in self.by_name.get(name, set())
                for k, cid in self.successors.get(tid, []) if k == "calls" and cid in self.nodes]

    def search(self, query, limit=20):
        ql = query.lower()
        scored = [(s, n) for s, n in [(sum([3 if ql in n.name.lower() else 0, 2 if ql in n.summary.lower() else 0, 1 if ql in n.file.lower() else 0]), n) for n in self.nodes.values()] if s > 0]
        scored.sort(key=lambda x: -x[0])
        return [n for _, n in scored[:limit]]

    def impact_analysis(self, changed_files, max_depth=3):
        affected_ids = set()
        for f in changed_files:
            affected_ids.update(self.by_file.get(f, set()))
            for fk, nids in self.by_file.items():
                if f in fk or fk in f: affected_ids.update(nids)
        visited = set(); queue = list(affected_ids); depth_map = {nid: 0 for nid in affected_ids}
        while queue:
            nid = queue.pop(0)
            if nid in visited: continue
            visited.add(nid); cd = depth_map.get(nid, 0)
            if cd >= max_depth: continue
            for k, pid in self.predecessors.get(nid, []):
                if k in ("calls", "imports", "depends_on") and pid not in visited:
                    depth_map[pid] = cd + 1; queue.append(pid)
        result = []
        for nid in visited:
            if nid in self.nodes:
                n = self.nodes[nid]; n.attributes["impact_depth"] = depth_map.get(nid, 0); result.append(n)
        result.sort(key=lambda n: n.attributes.get("impact_depth", 0))
        return result

    def stats(self):
        from collections import Counter
        c = Counter(n.layer for n in self.nodes.values() if n.layer)
        return {"total_nodes": len(self.nodes), "total_edges": len(self.edges),
                "by_kind": {k: len(v) for k, v in self.by_kind.items()},
                "by_layer": dict(c.most_common()), "files": len(self.by_file)}

    def to_dict(self):
        return {"nodes": [{"id": n.id, "kind": n.kind, "name": n.name, "file": n.file, "line": n.line, "language": n.language, "summary": n.summary, "layer": n.layer} for n in self.nodes.values()],
                "edges": [{"src": e.src, "dst": e.dst, "kind": e.kind} for e in self.edges], "stats": self.stats()}

class KnowledgeGraphBuilder:
    def __init__(self, repo_root):
        self.repo_root = repo_root; self.graph = KnowledgeGraph()

    def build(self, max_files=200):
        skip = {".git", "__pycache__", ".venv", "venv", "node_modules", ".loomscan-cache", "build", "dist", "target"}
        try: from .multi_lang import ALL_SOURCE_EXTS, get_language
        except: ALL_SOURCE_EXTS = {".py", ".js", ".ts", ".go", ".java", ".c", ".cpp"}; get_language = lambda p: "python" if p.suffix == ".py" else "unknown"
        count = 0
        for p in sorted(self.repo_root.rglob("*")):
            if not p.is_file() or any(d in p.parts for d in skip): continue
            if p.suffix.lower() not in ALL_SOURCE_EXTS or p.stat().st_size > 200000: continue
            rel = str(p.relative_to(self.repo_root))
            try: lang = get_language(p)
            except: lang = "unknown"
            fid = f"file:{rel}"
            self.graph.add_node(KGNode(id=fid, kind="file", name=p.name, file=rel, line=1, language=lang, summary=f"Source: {p.name}", layer=self._layer(rel)))
            if lang == "python": self._parse_py(p, rel, fid)
            else: self._parse_regex(p, rel, fid, lang)
            count += 1
            if count >= max_files: break
        self._resolve_calls()
        return self.graph

    def _layer(self, fp):
        fp = fp.lower()
        if any(x in fp for x in ("api", "route", "endpoint")): return "api"
        if any(x in fp for x in ("service", "business", "logic")): return "service"
        if any(x in fp for x in ("model", "schema", "db", "repository")): return "data"
        if any(x in fp for x in ("ui", "view", "component")): return "ui"
        if any(x in fp for x in ("util", "helper", "common")): return "util"
        if "test" in fp: return "test"
        return "core"

    def _parse_py(self, fp, rel, fid):
        try: source = fp.read_text(encoding="utf-8", errors="replace"); tree = ast.parse(source)
        except: return
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                fnid = f"{rel}:{node.lineno}:{node.name}"
                self.graph.add_node(KGNode(id=fnid, kind="function", name=node.name, file=rel, line=node.lineno, language="python", summary=ast.get_docstring(node) or f"Function {node.name}", layer=self._layer(rel)))
                self.graph.add_edge(fid, fnid, "contains")
                for child in ast.walk(node):
                    if isinstance(child, ast.Call):
                        cn = child.func.id if isinstance(child.func, ast.Name) else (child.func.attr if isinstance(child.func, ast.Attribute) else "")
                        if cn:
                            cid = f"call:{rel}:{child.lineno}:{cn}"
                            self.graph.add_node(KGNode(id=cid, kind="call", name=cn, file=rel, line=child.lineno, language="python", summary=f"Call to {cn}", layer=self._layer(rel)))
                            self.graph.add_edge(fnid, cid, "calls")
            elif isinstance(node, ast.ClassDef):
                cnid = f"{rel}:{node.lineno}:{node.name}"
                self.graph.add_node(KGNode(id=cnid, kind="class", name=node.name, file=rel, line=node.lineno, language="python", summary=f"Class: {node.name}", layer=self._layer(rel)))
                self.graph.add_edge(fid, cnid, "contains")

    def _parse_regex(self, fp, rel, fid, lang):
        try: source = fp.read_text(encoding="utf-8", errors="replace")
        except: return
        pats = {"go": r'func\s+(?:\([^)]*\)\s+)?(\w+)\s*\(', "java": r'(?:public|private|protected)\s+\w+\s+(\w+)\s*\(', "rust": r'fn\s+(\w+)\s*\(', "javascript": r'function\s+(\w+)\s*\('}
        pat = pats.get(lang, r'\b(\w+)\s*\(')
        for m in re.finditer(pat, source):
            name = m.group(1); line = source[:m.start()].count('\n') + 1
            fnid = f"{rel}:{line}:{name}"
            self.graph.add_node(KGNode(id=fnid, kind="function", name=name, file=rel, line=line, language=lang, summary=f"Function: {name}", layer=self._layer(rel)))
            self.graph.add_edge(fid, fnid, "contains")

    def _resolve_calls(self):
        fbn = {}
        for nid, n in self.graph.nodes.items():
            if n.kind == "function": fbn.setdefault(n.name, nid)
        for nid, n in list(self.graph.nodes.items()):
            if n.kind == "call" and n.name in fbn: self.graph.add_edge(nid, fbn[n.name], "calls")

class DiffImpactAnalyzer:
    def __init__(self, graph): self.graph = graph

    def analyze_changed_files(self, changed_files):
        affected = self.graph.impact_analysis(changed_files, max_depth=3)
        direct = [n for n in affected if n.attributes.get("impact_depth", 0) == 0]
        trans = [n for n in affected if n.attributes.get("impact_depth", 0) > 0]
        by_layer = defaultdict(list)
        for n in affected:
            if n.kind == "function": by_layer[n.layer].append(n.name)
        return {"directly_affected": [n.name for n in direct if n.kind == "function"], "transitively_affected": [n.name for n in trans if n.kind == "function"], "total_blast_radius": len(affected), "by_layer": dict(by_layer), "changed_files": changed_files}

    def suggest_tests(self, changed_files):
        affected = self.graph.impact_analysis(changed_files, max_depth=2)
        return sorted({n.file for n in affected if n.kind == "function" and n.layer == "test" or (n.kind == "file" and "test" in n.file.lower())})

def build_and_save_graph(repo_root, output_path=None):
    builder = KnowledgeGraphBuilder(repo_root); graph = builder.build(max_files=300)
    if output_path: output_path.write_text(json.dumps(graph.to_dict(), indent=2), encoding="utf-8")
    return graph
