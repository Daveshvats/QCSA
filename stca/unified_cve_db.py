"""Unified CVE database — OSV.dev-backed multi-ecosystem vulnerability intelligence.

Design: Instead of bundling per-ecosystem CVE lists (space-heavy, stale), we use
a single unified approach:

1. **Bundled seed DB** — 90 high-severity Maven CVEs (already curated in maven_cve_db.py)
   for offline-first operation.

2. **OSV.dev API integration** — Queries https://api.osv.dev/v1/querybatch on demand
   for any ecosystem (Maven, npm, PyPI, Go, Cargo, Gem, Composer). Results are
   cached locally in a SQLite DB with a 7-day TTL.

3. **SQLite cache** — Minimal storage. Only stores (ecosystem, package, version,
   cve_id, severity, description, fixed_version, query_date). Automatically
   prunes entries older than 7 days.

This approach:
  - Zero space complexity for unused ecosystems (unlike bundling npm+PyPI+Go CVEs)
  - Always up-to-date (OSV.dev aggregates NVD, GitHub Advisories, PyPA, RustSec, Go vuln DB)
  - Works offline for Maven (seed DB) + whatever's cached
  - Single API call per package batch (OSV.dev batch endpoint)
"""
from __future__ import annotations

import json
import sqlite3
import urllib.request
import urllib.error
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Tuple


@dataclass
class UnifiedCVE:
    cve_id: str
    ecosystem: str  # 'Maven', 'npm', 'PyPI', 'Go', 'Cargo', 'Gem', 'Composer'
    package: str
    version: str
    severity: str
    cwe: str
    description: str
    fixed_version: str
    source: str  # 'seed' | 'osv' | 'cache'


CACHE_DB_NAME = "cve_cache.db"
CACHE_TTL_DAYS = 7
OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"
OSV_LOOKUP_URL = "https://api.osv.dev/v1/vulns/"


class UnifiedCVEDatabase:
    """Multi-ecosystem CVE database backed by OSV.dev + SQLite cache."""

    def __init__(self, cache_dir: Optional[Path] = None):
        self.cache_dir = cache_dir or Path.home() / ".stca-cache"
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.db_path = self.cache_dir / CACHE_DB_NAME
        self._init_db()

    def _init_db(self):
        """Initialize SQLite cache table."""
        conn = sqlite3.connect(str(self.db_path))
        conn.execute("""
            CREATE TABLE IF NOT EXISTS cve_cache (
                cve_id TEXT,
                ecosystem TEXT,
                package TEXT,
                version TEXT,
                severity TEXT,
                cwe TEXT,
                description TEXT,
                fixed_version TEXT,
                query_date TEXT,
                PRIMARY KEY (cve_id, ecosystem, package, version)
            )
        """)
        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_pkg ON cve_cache(ecosystem, package, version)
        """)
        conn.commit()
        conn.close()

    def _get_cached(self, ecosystem: str, package: str, version: str) -> List[UnifiedCVE]:
        """Get cached CVEs (within TTL)."""
        cutoff = (datetime.now() - timedelta(days=CACHE_TTL_DAYS)).isoformat()
        conn = sqlite3.connect(str(self.db_path))
        rows = conn.execute(
            "SELECT cve_id, severity, cwe, description, fixed_version FROM cve_cache "
            "WHERE ecosystem=? AND package=? AND version=? AND query_date > ?",
            (ecosystem, package, version, cutoff)
        ).fetchall()
        conn.close()
        return [
            UnifiedCVE(
                cve_id=r[0], ecosystem=ecosystem, package=package, version=version,
                severity=r[1], cwe=r[2], description=r[3], fixed_version=r[4],
                source="cache"
            )
            for r in rows
        ]

    def _store_cached(self, ecosystem: str, package: str, version: str,
                      cves: List[UnifiedCVE]):
        """Store CVEs in cache."""
        if not cves:
            # Store a "no CVEs" marker so we don't re-query
            conn = sqlite3.connect(str(self.db_path))
            conn.execute(
                "INSERT OR REPLACE INTO cve_cache VALUES (?,?,?,?,?,?,?,?,?)",
                ("NONE", ecosystem, package, version, "none", "", "No CVEs found",
                 "", datetime.now().isoformat())
            )
            conn.commit()
            conn.close()
            return

        conn = sqlite3.connect(str(self.db_path))
        for cve in cves:
            conn.execute(
                "INSERT OR REPLACE INTO cve_cache VALUES (?,?,?,?,?,?,?,?,?)",
                (cve.cve_id, ecosystem, package, version, cve.severity,
                 cve.cwe, cve.description, cve.fixed_version, datetime.now().isoformat())
            )
        conn.commit()
        conn.close()

    def _query_osv_batch(self, queries: List[dict]) -> List[dict]:
        """Query OSV.dev batch API. Returns list of vulnerability IDs."""
        try:
            payload = json.dumps({"queries": queries}).encode("utf-8")
            req = urllib.request.Request(
                OSV_BATCH_URL, data=payload,
                headers={"Content-Type": "application/json"},
                method="POST"
            )
            with urllib.request.urlopen(req, timeout=15) as resp:
                data = json.loads(resp.read())
            return data.get("results", [])
        except Exception:
            return []

    def _fetch_vuln_details(self, vuln_id: str) -> Optional[dict]:
        """Fetch vulnerability details from OSV.dev."""
        try:
            url = f"{OSV_LOOKUP_URL}{vuln_id}"
            with urllib.request.urlopen(url, timeout=10) as resp:
                return json.loads(resp.read())
        except Exception:
            return None

    def _extract_cve_info(self, vuln: dict, ecosystem: str,
                          package: str, version: str) -> Optional[UnifiedCVE]:
        """Extract CVE info from OSV.dev vulnerability object."""
        cve_id = vuln.get("id", "")
        # Try to get CVE ID from aliases
        for alias in vuln.get("aliases", []):
            if alias.startswith("CVE-"):
                cve_id = alias
                break

        # Severity
        severity = "medium"
        for sev in vuln.get("severity", []):
            if sev.get("type") in ("CVSS_V3", "CVSS_V4"):
                score = sev.get("score", "")
                if "AV:N" in score and "AC:L" in score:
                    severity = "critical" if "C:H" in score else "high"
                elif "AV:N" in score:
                    severity = "high"
                break

        # Affected versions + fixed version
        fixed_version = ""
        for affected in vuln.get("affected", []):
            pkg = affected.get("package", {})
            if pkg.get("name") == package and pkg.get("ecosystem") == ecosystem:
                for rng in affected.get("ranges", []):
                    for event in rng.get("events", []):
                        if "fixed" in event:
                            fixed_version = event["fixed"]

        description = vuln.get("summary", vuln.get("details", ""))[:300]

        return UnifiedCVE(
            cve_id=cve_id, ecosystem=ecosystem, package=package,
            version=version, severity=severity, cwe="",
            description=description, fixed_version=fixed_version,
            source="osv"
        )

    def lookup(self, ecosystem: str, package: str, version: str) -> List[UnifiedCVE]:
        """Look up CVEs for a package version.

        1. Check SQLite cache (7-day TTL)
        2. If not cached, query OSV.dev API
        3. Store results in cache

        Args:
            ecosystem: 'Maven', 'npm', 'PyPI', 'Go', 'Cargo', 'Gem', 'Composer'
            package: Package name (e.g., 'org.springframework:spring-beans')
            version: Version string (e.g., '5.3.16')
        """
        # Step 1: Check cache
        cached = self._get_cached(ecosystem, package, version)
        if cached:
            return [c for c in cached if c.cve_id != "NONE"]

        # Step 2: For Maven, also check seed DB
        if ecosystem == "Maven":
            try:
                from .maven_cve_db import MavenCVEDatabase
                maven_db = MavenCVEDatabase(self.cache_dir)
                seed_cves = maven_db.lookup(package, version)
                if seed_cves:
                    results = [
                        UnifiedCVE(
                            cve_id=c.cve_id, ecosystem="Maven", package=package,
                            version=version, severity=c.severity, cwe=c.cwe,
                            description=c.description, fixed_version=c.fixed_version,
                            source="seed"
                        )
                        for c in seed_cves
                    ]
                    self._store_cached(ecosystem, package, version, results)
                    return results
            except Exception:
                pass

        # Step 3: Query OSV.dev
        query = {"package": {"ecosystem": ecosystem, "name": package}, "version": version}
        batch_results = self._query_osv_batch([query])

        cves: List[UnifiedCVE] = []
        if batch_results:
            for vuln_id in batch_results[0].get("vulns", []):
                vuln_details = self._fetch_vuln_details(vuln_id)
                if vuln_details:
                    cve = self._extract_cve_info(vuln_details, ecosystem, package, version)
                    if cve:
                        cves.append(cve)

        # Step 4: Cache results
        self._store_cached(ecosystem, package, version, cves)

        return cves

    def lookup_batch(self, packages: List[Tuple[str, str, str]]) -> List[UnifiedCVE]:
        """Look up CVEs for multiple packages efficiently.

        Args:
            packages: List of (ecosystem, package, version) tuples

        Returns: List of CVEs found.
        """
        # Separate cached from uncached
        uncached: List[Tuple[int, str, str, str]] = []
        results: List[UnifiedCVE] = []

        for i, (eco, pkg, ver) in enumerate(packages):
            cached = self._get_cached(eco, pkg, ver)
            if cached:
                results.extend(c for c in cached if c.cve_id != "NONE")
            else:
                # For Maven, check seed DB first
                if eco == "Maven":
                    try:
                        from .maven_cve_db import MavenCVEDatabase
                        maven_db = MavenCVEDatabase(self.cache_dir)
                        seed_cves = maven_db.lookup(pkg, ver)
                        if seed_cves:
                            seed_results = [
                                UnifiedCVE(c.cve_id, "Maven", pkg, ver, c.severity,
                                          c.cwe, c.description, c.fixed_version, "seed")
                                for c in seed_cves
                            ]
                            self._store_cached(eco, pkg, ver, seed_results)
                            results.extend(seed_results)
                            continue
                    except Exception:
                        pass
                uncached.append((i, eco, pkg, ver))

        if not uncached:
            return results

        # Batch query OSV.dev (max 1000 per batch)
        batch_size = 100
        for chunk_start in range(0, len(uncached), batch_size):
            chunk = uncached[chunk_start:chunk_start + batch_size]
            queries = [
                {"package": {"ecosystem": eco, "name": pkg}, "version": ver}
                for _, eco, pkg, ver in chunk
            ]
            batch_results = self._query_osv_batch(queries)

            for i, (_, eco, pkg, ver) in enumerate(chunk):
                if i >= len(batch_results):
                    continue
                vuln_ids = batch_results[i].get("vulns", [])
                chunk_cves: List[UnifiedCVE] = []
                for vid in vuln_ids:
                    details = self._fetch_vuln_details(vid)
                    if details:
                        cve = self._extract_cve_info(details, eco, pkg, ver)
                        if cve:
                            chunk_cves.append(cve)
                self._store_cached(eco, pkg, ver, chunk_cves)
                results.extend(chunk_cves)

        return results

    def update_all(self, packages: List[Tuple[str, str, str]]) -> int:
        """Force-update CVEs for all packages (bypasses cache TTL).

        Returns: Number of CVEs found.
        """
        # Clear cache for these packages
        conn = sqlite3.connect(str(self.db_path))
        for eco, pkg, ver in packages:
            conn.execute(
                "DELETE FROM cve_cache WHERE ecosystem=? AND package=? AND version=?",
                (eco, pkg, ver)
            )
        conn.commit()
        conn.close()

        # Re-query
        cves = self.lookup_batch(packages)
        return len(cves)

    def prune(self):
        """Remove stale cache entries older than TTL."""
        cutoff = (datetime.now() - timedelta(days=CACHE_TTL_DAYS)).isoformat()
        conn = sqlite3.connect(str(self.db_path))
        conn.execute("DELETE FROM cve_cache WHERE query_date < ?", (cutoff,))
        conn.commit()
        conn.close()

    def stats(self) -> dict:
        """Return cache statistics."""
        conn = sqlite3.connect(str(self.db_path))
        total = conn.execute("SELECT COUNT(*) FROM cve_cache").fetchone()[0]
        by_eco = dict(conn.execute(
            "SELECT ecosystem, COUNT(*) FROM cve_cache GROUP BY ecosystem"
        ).fetchall())
        conn.close()
        return {
            "total_cached_entries": total,
            "by_ecosystem": by_eco,
            "db_path": str(self.db_path),
            "db_size_bytes": self.db_path.stat().st_size if self.db_path.exists() else 0,
            "ttl_days": CACHE_TTL_DAYS,
        }


# === Integration: Scan SBOM against unified DB ===

def scan_sbom_unified(sbom: dict, cve_db: Optional[UnifiedCVEDatabase] = None) -> List[dict]:
    """Scan a CycloneDX SBOM against the unified CVE database.

    Works for ALL ecosystems: Maven, npm, PyPI, Go, Cargo, Gem, Composer.
    """
    if cve_db is None:
        cve_db = UnifiedCVEDatabase()

    # Build package list from SBOM
    packages: List[Tuple[str, str, str]] = []
    for component in sbom.get("components", []):
        purl = component.get("purl", "")
        # purl format: pkg:maven/group:artifact@version
        import re
        m = re.match(r'pkg:([^/]+)/([^@]+)@(.+)', purl)
        if not m:
            continue
        ecosystem = m.group(1)
        # Normalize ecosystem names
        eco_map = {"maven": "Maven", "npm": "npm", "pypi": "PyPI",
                   "go": "Go", "cargo": "Cargo", "gem": "Gem", "composer": "Composer"}
        ecosystem = eco_map.get(ecosystem.lower(), ecosystem)
        package = m.group(2)
        version = m.group(3)
        packages.append((ecosystem, package, version))

    # Look up CVEs
    cves = cve_db.lookup_batch(packages)

    # Convert to finding dicts
    findings = []
    for cve in cves:
        findings.append({
            "cve_id": cve.cve_id,
            "ecosystem": cve.ecosystem,
            "package": cve.package,
            "version": cve.version,
            "severity": cve.severity,
            "cwe": cve.cwe,
            "description": cve.description,
            "fixed_version": cve.fixed_version,
            "source": cve.source,
            "fix": f"Upgrade {cve.package} from {cve.version} to {cve.fixed_version or 'latest'}",
        })

    return findings


def scan_pom_xml_unified(pom_path: Path, cve_db: Optional[UnifiedCVEDatabase] = None) -> List[dict]:
    """Scan pom.xml using the unified DB (Maven seed + OSV.dev)."""
    if cve_db is None:
        cve_db = UnifiedCVEDatabase()

    # Use existing maven_cve_db for parsing + BOM resolution
    try:
        from .maven_cve_db import scan_pom_xml_for_cves
        return scan_pom_xml_for_cves(pom_path)
    except Exception:
        return []


def scan_package_json_unified(pkg_json_path: Path,
                               cve_db: Optional[UnifiedCVEDatabase] = None) -> List[dict]:
    """Scan package.json using OSV.dev (npm ecosystem)."""
    if cve_db is None:
        cve_db = UnifiedCVEDatabase()

    try:
        data = json.loads(pkg_json_path.read_text())
    except Exception:
        return []

    packages: List[Tuple[str, str, str]] = []
    for kind in ("dependencies", "devDependencies"):
        for name, version in data.get(kind, {}).items():
            # Strip ^~ from version
            clean_ver = version.lstrip("^~><= ")
            if clean_ver:
                packages.append(("npm", name, clean_ver))

    cves = cve_db.lookup_batch(packages)

    return [
        {
            "cve_id": c.cve_id, "ecosystem": "npm", "package": c.package,
            "version": c.version, "severity": c.severity, "cwe": c.cwe,
            "description": c.description, "fixed_version": c.fixed_version,
            "source": c.source, "fix": f"Upgrade {c.package} to {c.fixed_version or 'latest'}",
        }
        for c in cves
    ]


def scan_requirements_unified(req_path: Path,
                               cve_db: Optional[UnifiedCVEDatabase] = None) -> List[dict]:
    """Scan requirements.txt using OSV.dev (PyPI ecosystem)."""
    if cve_db is None:
        cve_db = UnifiedCVEDatabase()

    try:
        source = req_path.read_text()
    except Exception:
        return []

    import re
    packages: List[Tuple[str, str, str]] = []
    for line in source.splitlines():
        line = line.strip().split(";")[0].strip()
        if not line or line.startswith("#"):
            continue
        m = re.match(r'^([a-zA-Z0-9_-]+)\s*(?:[<>=!~]+\s*)?([\w.]+)?', line)
        if m:
            packages.append(("PyPI", m.group(1).lower(), m.group(2) or "latest"))

    cves = cve_db.lookup_batch(packages)

    return [
        {
            "cve_id": c.cve_id, "ecosystem": "PyPI", "package": c.package,
            "version": c.version, "severity": c.severity, "cwe": c.cwe,
            "description": c.description, "fixed_version": c.fixed_version,
            "source": c.source, "fix": f"Upgrade {c.package} to {c.fixed_version or 'latest'}",
        }
        for c in cves
    ]
