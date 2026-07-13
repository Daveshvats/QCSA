"""Supply chain intelligence — SBOM, typosquat, license, abandoned deps, Maven CVEs."""
from __future__ import annotations
import json, re
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

import logging
_logger = logging.getLogger(__name__.replace('loomscan.', ''))

@dataclass
class DependencyInfo:
    name: str; version: str; ecosystem: str; direct: bool = True; license: Optional[str] = None; source_repo: Optional[str] = None

@dataclass
class SupplyChainIssue:
    kind: str; package: str; version: str; description: str; severity: str; fix: str; confidence: float = 0.7; cve: Optional[str] = None

TOP_PYPI = {"requests","numpy","pandas","django","flask","fastapi","pyyaml","setuptools","pip","wheel","pytest","scipy","matplotlib","torch","tensorflow","beautifulsoup4","bs4","sqlalchemy","celery","redis","psycopg2","pytz","python-dateutil","six","urllib3","certifi","idna","chardet","click","jinja2","werkzeug","tornado","aiohttp","httpx","pillow","pymongo","boto3","openai","anthropic","langchain","pydantic"}
TOP_NPM = {"react","react-dom","vue","angular","express","next","lodash","axios","moment","typescript","webpack","babel","eslint","jest","chai","mocha","uuid","fs-extra","commander","chalk","debug","request","rxjs","redux","immer","zod","yup","ws","bcrypt","jsonwebtoken","passport","cors","helmet","mongoose","knex","sequelize","prisma","graphql"}

def _scan_pip_requirements(repo):
    deps = []
    for fname in ("requirements.txt","requirements-prod.txt","requirements-base.txt"):
        f = repo/fname
        if not f.exists(): continue
        try:
            for line in f.read_text().splitlines():
                line = line.strip().split(";")[0].strip()
                if not line or line.startswith("#"): continue
                m = re.match(r'^([a-zA-Z0-9_-]+)\s*(?:[<>=!~]+\s*)?([\w.]+)?', line)
                if m: deps.append(DependencyInfo(m.group(1).lower(), m.group(2) or "latest", "pypi"))
        except Exception: pass  # v4.5: suppressed — add logging
    return deps

def _scan_package_json(repo):
    pkg = repo/"package.json"
    if not pkg.exists(): return []
    deps = []
    try:
        data = json.loads(pkg.read_text())
        for kind in ("dependencies","devDependencies","peerDependencies","optionalDependencies"):
            for name, version in data.get(kind,{}).items():
                deps.append(DependencyInfo(name.lower(), version.lstrip("^~><= "), "npm", direct=(kind=="dependencies")))
    except Exception: pass  # v4.5: suppressed — add logging
    return deps

def _scan_go_mod(repo):
    gomod = repo/"go.mod"
    if not gomod.exists(): return []
    deps = []
    try:
        for line in gomod.read_text().splitlines():
            m = re.match(r'^\s*([^\s]+)\s+(v[\d.]+)', line)
            if m: deps.append(DependencyInfo(m.group(1), m.group(2), "go"))
    except Exception: pass  # v4.5: suppressed — add logging
    return deps

def _scan_pom_xml(repo):
    pom = repo/"pom.xml"
    if not pom.exists(): return []
    deps = []
    try:
        content = pom.read_text()
        for m in re.finditer(r'<dependency>(.*?)</dependency>', content, re.DOTALL):
            block = m.group(1)
            gid = re.search(r'<groupId>([^<]+)</groupId>', block)
            aid = re.search(r'<artifactId>([^<]+)</artifactId>', block)
            ver = re.search(r'<version>([^<]+)</version>', block)
            if aid: deps.append(DependencyInfo(f"{gid.group(1) if gid else ''}:{aid.group(1)}", ver.group(1) if ver else "latest", "maven"))
    except Exception: pass  # v4.5: suppressed — add logging
    return deps

def _scan_pyproject(repo):
    pp = repo/"pyproject.toml"
    if not pp.exists(): return []
    deps = []
    try:
        content = pp.read_text()
        for m in re.finditer(r'\[project\].*?dependencies\s*=\s*\[(.*?)\]', content, re.DOTALL):
            for line in m.group(1).splitlines():
                line = line.strip().strip(',').strip('"').strip("'")
                if not line or line.startswith("#"): continue
                dm = re.match(r'^([a-zA-Z0-9_-]+)\s*([<>=!~^]+\s*[\w.]+)?', line)
                if dm: deps.append(DependencyInfo(dm.group(1).lower(), dm.group(2).strip().lstrip("=<>!~^") if dm.group(2) else "latest", "pypi"))
    except Exception: pass  # v4.5: suppressed — add logging
    return deps

def _scan_cargo_toml(repo):
    cargo = repo/"Cargo.toml"
    if not cargo.exists(): return []
    deps = []
    try:
        in_deps = False
        for line in cargo.read_text().splitlines():
            line = line.strip()
            if line in ("[dependencies]","[dev-dependencies]"): in_deps = True; continue
            if line.startswith("["): in_deps = False; continue
            if in_deps and "=" in line:
                m = re.match(r'^([a-zA-Z0-9_-]+)\s*=\s*["\']([^"\']+)["\']', line)
                if m: deps.append(DependencyInfo(m.group(1).lower(), m.group(2).lstrip("=<>!~^"), "cargo"))
    except Exception: pass  # v4.5: suppressed — add logging
    return deps

def _scan_gemfile(repo):
    gf = repo/"Gemfile"
    if not gf.exists(): return []
    deps = []
    try:
        for line in gf.read_text().splitlines():
            line = line.strip()
            if line.startswith("#"): continue
            m = re.match(r'^gem\s+["\']([^"\']+)["\'](?:\s*,\s*["\']([^"\']+)["\'])?', line)
            if m: deps.append(DependencyInfo(m.group(1).lower(), m.group(2) or "latest", "gem"))
    except Exception: pass  # v4.5: suppressed — add logging
    return deps

def _scan_gradle(repo):
    gradle = repo/"build.gradle"
    if not gradle.exists(): gradle = repo/"build.gradle.kts"
    if not gradle.exists(): return []
    deps = []
    try:
        content = gradle.read_text()
        for m in re.finditer(r"(?:implementation|api|compileOnly|runtimeOnly)\s+['\"]([^'\"]+)['\"]", content):
            parts = m.group(1).split(":")
            if len(parts) >= 3: deps.append(DependencyInfo(f"{parts[0]}:{parts[1]}", parts[2], "maven"))
            elif len(parts) == 2: deps.append(DependencyInfo(parts[0], parts[1], "maven"))
    except Exception: pass  # v4.5: suppressed — add logging
    return deps

def _scan_composer_json(repo):
    comp = repo/"composer.json"
    if not comp.exists(): return []
    deps = []
    try:
        data = json.loads(comp.read_text())
        for kind in ("require","require-dev"):
            for name, version in data.get(kind,{}).items():
                deps.append(DependencyInfo(name.lower(), version.lstrip("^~><= "), "composer"))
    except Exception: pass  # v4.5: suppressed — add logging
    return deps

def _levenshtein(a, b):
    if len(a) < len(b): return _levenshtein(b, a)
    if len(b) == 0: return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a):
        curr = [i + 1]
        for j, cb in enumerate(b):
            curr.append(min(prev[j+1]+1, curr[j]+1, prev[j]+(ca != cb)))
        prev = curr
    return prev[-1]

def detect_typosquats(deps):
    findings = []
    for d in deps:
        popular = TOP_PYPI if d.ecosystem == "pypi" else TOP_NPM if d.ecosystem == "npm" else set()
        if not popular or d.name in popular: continue
        for pn in popular:
            dist = _levenshtein(d.name, pn)
            if dist == 1 and len(d.name) >= 4:
                findings.append(SupplyChainIssue("typosquat", d.name, d.version,
                    f"Possible typosquat: '{d.name}' is 1 edit from '{pn}'", "high",
                    f"Verify intended package", 0.8))
                break
            if dist == 2 and len(d.name) == len(pn) and len(d.name) >= 6:
                findings.append(SupplyChainIssue("typosquat", d.name, d.version,
                    f"Possible typosquat: '{d.name}' is 2 edits from '{pn}'", "medium",
                    f"Verify intended package", 0.5))
                break
    return findings

def detect_abandoned_deps(deps, repo_root):
    findings = []
    pkg_lock = repo_root / "package-lock.json"
    if pkg_lock.exists():
        try:
            data = json.loads(pkg_lock.read_text())
            for name, info in data.get("packages",{}).items():
                if not name or name.startswith("node_modules/"): continue
                version = info.get("version","")
                if version.startswith("0.0."):
                    findings.append(SupplyChainIssue("abandoned", name, version,
                        f"Package '{name}' v{version} — possibly abandoned", "low", "Check maintenance", 0.4))
        except Exception: pass  # v4.5: suppressed — add logging
    return findings

def analyze_supply_chain(repo_root, project_license="MIT"):
    deps = []
    deps += _scan_pip_requirements(repo_root)
    deps += _scan_pyproject(repo_root)
    deps += _scan_package_json(repo_root)
    deps += _scan_go_mod(repo_root)
    deps += _scan_pom_xml(repo_root)
    deps += _scan_cargo_toml(repo_root)
    deps += _scan_gemfile(repo_root)
    deps += _scan_gradle(repo_root)
    deps += _scan_composer_json(repo_root)
    findings = []
    findings += detect_typosquats(deps)
    findings += detect_abandoned_deps(deps, repo_root)
    # Maven CVE cross-referencing
    try:
        from .maven_cve_db import scan_pom_xml_for_cves
        pom_path = repo_root / "pom.xml"
        if pom_path.exists():
            for cf in scan_pom_xml_for_cves(pom_path):
                findings.append(SupplyChainIssue("maven_cve", cf["package"], cf["version"],
                    f"{cf['cve_id']}: {cf['description']}", cf["severity"], cf["fix"], 0.9, cf["cve_id"]))
    except Exception: pass  # v4.5: suppressed — add logging
    # Unified CVE DB (npm, PyPI, Go, etc. via OSV.dev)
    try:
        from .unified_cve_db import UnifiedCVEDatabase, scan_package_json_unified, scan_requirements_unified
        cve_db = UnifiedCVEDatabase()
        # npm
        pkg_json = repo_root / "package.json"
        if pkg_json.exists():
            for cf in scan_package_json_unified(pkg_json, cve_db):
                findings.append(SupplyChainIssue("npm_cve", cf["package"], cf["version"],
                    f"{cf['cve_id']}: {cf['description']}", cf["severity"], cf["fix"], 0.9, cf["cve_id"]))
        # PyPI
        for req_name in ("requirements.txt", "requirements-prod.txt"):
            req_file = repo_root / req_name
            if req_file.exists():
                for cf in scan_requirements_unified(req_file, cve_db):
                    findings.append(SupplyChainIssue("pypi_cve", cf["package"], cf["version"],
                        f"{cf['cve_id']}: {cf['description']}", cf["severity"], cf["fix"], 0.9, cf["cve_id"]))
    except Exception: pass  # v4.5: suppressed — add logging
    sbom = _format_cyclonedx(deps, repo_root)
    return findings, sbom

def _format_cyclonedx(deps, repo_root):
    return {"bomFormat":"CycloneDX","specVersion":"1.5","version":1,
            "metadata":{"component":{"type":"application","name":repo_root.name}},
            "components":[{"type":"library","name":d.name,"version":d.version,
                          "purl":f"pkg:{d.ecosystem}/{d.name}@{d.version}",
                          "licenses":[{"license":{"name":d.license}}] if d.license else []} for d in deps]}

def _format_spdx(deps, repo_root):
    return {"spdxVersion":"SPDX-2.3","dataLicense":"CC0-1.0","SPDXID":"SPDXRef-DOCUMENT",
            "name":repo_root.name,
            "creationInfo":{"creators":["Tool: LoomScan"],"created":"2026-01-01T00:00:00Z"},
            "packages":[{"SPDXID":f"SPDXRef-Package-{i}","name":d.name,"versionInfo":d.version,
                        "downloadLocation":"NOASSERTION","filesAnalyzed":False,
                        "licenseConcluded":d.license or "NOASSERTION","licenseDeclared":d.license or "NOASSERTION",
                        "supplier":f"Organization: {d.ecosystem}"} for i,d in enumerate(deps)]}

def generate_sbom(repo_root, output_format="spdx"):
    deps = []
    deps += _scan_pip_requirements(repo_root)
    deps += _scan_pyproject(repo_root)
    deps += _scan_package_json(repo_root)
    deps += _scan_go_mod(repo_root)
    deps += _scan_pom_xml(repo_root)
    deps += _scan_cargo_toml(repo_root)
    deps += _scan_gemfile(repo_root)
    deps += _scan_gradle(repo_root)
    deps += _scan_composer_json(repo_root)
    return _format_spdx(deps, repo_root) if output_format == "spdx" else _format_cyclonedx(deps, repo_root)
