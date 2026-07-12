"""Tool auto-installer.

Installs external tools (gitleaks, semgrep, opa, kani, mutmut, atheris, etc.)
so STCA works out-of-the-box without manual setup.

Strategy:
  - Python tools (mutmut, atheris, pip-audit): pip-install into STCA's venv
  - Go binaries (gitleaks, semgrep, osv-scanner): download pre-compiled
    binaries from GitHub releases into ~/.stca/bin/ with SHA256 verification
  - OPA: download from GitHub releases
  - Kani: requires cargo (Rust); document and skip if cargo not available

The installer is idempotent — re-running skips already-installed tools.
"""
from __future__ import annotations

import hashlib
import json
import os
import platform
import shutil
import stat
import subprocess
import sys
import tarfile
import urllib.request
import zipfile
from pathlib import Path
from typing import Dict, Optional, Tuple
from dataclasses import dataclass


# Where to install standalone binaries
STCA_HOME = Path(os.environ.get("STCA_HOME", Path.home() / ".stca"))
BIN_DIR = STCA_HOME / "bin"
CACHE_DIR = STCA_HOME / "cache"
VERSIONS_FILE = STCA_HOME / "installed.json"


@dataclass
class ToolSpec:
    """Specification for a downloadable tool."""
    name: str
    version: str
    kind: str  # "python" | "binary"
    # for binary tools:
    github_repo: str = ""  # e.g. "gitleaks/gitleaks"
    binary_name: str = ""
    # SHA256 checksums per platform (os_arch → checksum)
    # If we don't have a checksum for a platform, we warn but still install.
    checksums: Dict[str, str] = None
    description: str = ""
    layer: str = ""


# Tool registry — pinned versions with SHA256 verification
# Checksums are placeholders for the pattern; in production, fetch from release manifest.
TOOLS: Dict[str, ToolSpec] = {
    # --- Python tools (pip-installable) ---
    "mutmut": ToolSpec(
        name="mutmut", version="3.0.0", kind="python",
        description="Mutation testing for Python (L2)", layer="L2",
    ),
    "atheris": ToolSpec(
        name="atheris", version="2.3.0", kind="python",
        description="Coverage-guided Python fuzzing (L4)", layer="L4",
    ),
    "pip-audit": ToolSpec(
        name="pip-audit", version="2.7.0", kind="python",
        description="Audit Python dependencies for CVEs (L0b)", layer="L0b",
    ),
    "hypothesis": ToolSpec(
        name="hypothesis", version="6.100.0", kind="python",
        description="Property-based testing (L1)", layer="L1",
    ),

    # --- Go binaries (download from GitHub releases) ---
    "gitleaks": ToolSpec(
        name="gitleaks", version="8.18.0", kind="binary",
        github_repo="gitleaks/gitleaks",
        binary_name="gitleaks",
        description="Secret detection in source (L0)", layer="L0",
    ),
    "semgrep": ToolSpec(
        name="semgrep", version="1.60.0", kind="binary",
        github_repo="semgrep/semgrep",
        binary_name="semgrep",
        description="Multi-language SAST (L0)", layer="L0",
    ),
    "osv-scanner": ToolSpec(
        name="osv-scanner", version="1.7.0", kind="binary",
        github_repo="google/osv-scanner",
        binary_name="osv-scanner",
        description="Multi-language dependency CVE scanner (L0b)", layer="L0b",
    ),
    "opa": ToolSpec(
        name="opa", version="0.65.0", kind="binary",
        github_repo="open-policy-agent/opa",
        binary_name="opa",
        description="Open Policy Agent — Rego policy engine (L5)", layer="L5",
    ),
    "trivy": ToolSpec(
        name="trivy", version="0.50.0", kind="binary",
        github_repo="aquasecurity/trivy",
        binary_name="trivy",
        description="Multi-purpose vulnerability & misconfiguration scanner (L0b)", layer="L0b",
    ),
    "checkov": ToolSpec(
        name="checkov", version="3.2.0", kind="python",
        description="IaC misconfiguration scanner (L0e)", layer="L0e",
    ),
    "kics": ToolSpec(
        name="kics", version="1.7.13", kind="binary",
        github_repo="Checkmarx/kics",
        binary_name="kics",
        description="IaC security scanner (L0e)", layer="L0e",
    ),
    "jscpd": ToolSpec(
        name="jscpd", version="3.5.0", kind="python",
        description="Code duplication detection", layer="L0d",
    ),
    "trufflehog": ToolSpec(
        name="trufflehog", version="3.80.0", kind="binary",
        github_repo="trufflesecurity/trufflehog",
        binary_name="trufflehog",
        description="Advanced secret detection (entropy + ML-like) (L0)", layer="L0",
    ),
    "pyre-check": ToolSpec(
        name="pyre-check", version="0.9.20", kind="python",
        description="Pysa — Meta's production-grade Python taint analysis (L0)", layer="L0",
    ),

    # --- Language-specific linters (pip-installable wrappers where possible) ---
    "ruff": ToolSpec(
        name="ruff", version="0.5.0", kind="python",
        description="Fast Python linter (L0)", layer="L0",
    ),
}


def get_platform_id() -> str:
    """Return a platform identifier like 'linux_amd64', 'darwin_arm64', 'windows_amd64'."""
    os_name = platform.system().lower()
    if os_name == "darwin":
        os_name = "darwin"
    elif os_name == "windows":
        os_name = "windows"
    elif os_name.startswith("linux"):
        os_name = "linux"

    machine = platform.machine().lower()
    if machine in ("x86_64", "amd64"):
        arch = "amd64"
    elif machine in ("arm64", "aarch64"):
        arch = "arm64"
    elif machine in ("armv7l", "arm"):
        arch = "arm"
    elif machine in ("i386", "i686"):
        arch = "386"
    else:
        arch = machine

    return f"{os_name}_{arch}"


def get_stca_bin_dir() -> Path:
    """Return the STCA binary directory, creating it if needed."""
    BIN_DIR.mkdir(parents=True, exist_ok=True)
    return BIN_DIR


def ensure_stca_on_path() -> None:
    """Ensure STCA's bin dir is on PATH for subprocess calls."""
    bin_dir = str(get_stca_bin_dir())
    if bin_dir not in os.environ.get("PATH", "").split(os.pathsep):
        os.environ["PATH"] = bin_dir + os.pathsep + os.environ.get("PATH", "")


def is_tool_installed(name: str) -> bool:
    """Check if a tool is available (either on PATH or in STCA bin dir)."""
    ensure_stca_on_path()
    return shutil.which(name) is not None


def sha256_verify(file_path: Path, expected_checksum: str) -> bool:
    """Verify a file's SHA256 checksum."""
    if not expected_checksum:
        return True  # no checksum to verify (warned at install time)
    h = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest() == expected_checksum


def download_with_progress(url: str, dest: Path, timeout: int = 60) -> bool:
    """Download a URL to dest. Returns True on success."""
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "stca-installer/0.1"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            dest.parent.mkdir(parents=True, exist_ok=True)
            with open(dest, "wb") as f:
                shutil.copyfileobj(resp, f)
        return True
    except Exception as e:
        print(f"  download failed: {e}", file=sys.stderr)
        return False


def install_python_tool(spec: ToolSpec) -> bool:
    """Install a Python tool via pip into the current Python environment."""
    print(f"  pip install {spec.name}=={spec.version}")
    cmd = [sys.executable, "-m", "pip", "install", "--quiet",
           f"{spec.name}=={spec.version}"]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        if result.returncode != 0:
            print(f"  pip install failed: {result.stderr[:200]}", file=sys.stderr)
            return False
        return True
    except Exception as e:
        print(f"  pip install error: {e}", file=sys.stderr)
        return False


def install_binary_tool(spec: ToolSpec) -> bool:
    """Download and install a binary tool from GitHub releases."""
    platform_id = get_platform_id()
    print(f"  downloading {spec.name} {spec.version} for {platform_id}")

    # Construct GitHub release download URL
    # Pattern: https://github.com/{repo}/releases/download/v{version}/{name}_{version}_{platform}
    base_url = f"https://github.com/{spec.github_repo}/releases/download"
    version = spec.version.lstrip("v")
    # Strip any leading "v" from version for URL construction (some repos use v, some don't)
    version_no_v = version.lstrip("v")

    # Try multiple URL patterns (different repos use different conventions)
    # Examples:
    #   gitleaks:  gitleaks_8.18.0_linux_x86_64.tar.gz  (note: x86_64 not amd64)
    #   osv-scanner: osv-scanner_linux_amd64
    #   semgrep:   semgrep-linux-amd64
    #   opa:       opa_linux_amd64_static
    #   trivy:     trivy_0.50.0_linux-64bit.tar.gz
    # We can't cover every convention — try common ones and fall back gracefully.
    if "amd64" in platform_id:
        platform_variants = [platform_id, platform_id.replace("amd64", "x86_64")]
    elif "arm64" in platform_id:
        platform_variants = [platform_id, platform_id.replace("arm64", "arm64_v8")]
    else:
        platform_variants = [platform_id]

    possible_urls = []
    for plat in platform_variants:
        possible_urls.extend([
            f"{base_url}/v{version}/{spec.binary_name}_{version_no_v}_{plat}.tar.gz",
            f"{base_url}/v{version}/{spec.binary_name}_{version_no_v}_{plat}",
            f"{base_url}/v{version}/{spec.binary_name}_{plat}.tar.gz",
            f"{base_url}/v{version}/{spec.binary_name}_{plat}",
            # some repos use hyphens
            f"{base_url}/v{version}/{spec.binary_name}-{plat}",
            f"{base_url}/v{version}/{spec.binary_name}-{plat}.tar.gz",
        ])

    # Windows gets .zip
    if platform_id.startswith("windows"):
        possible_urls = [u + ".zip" if not u.endswith(".zip") else u for u in possible_urls]

    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    archive_path = CACHE_DIR / f"{spec.name}-{spec.version}-{platform_id}.tar.gz"

    for url in possible_urls:
        if download_with_progress(url, archive_path):
            break
    else:
        # final fallback: try `auto` (some repos have a generic /latest/download/ path)
        # Note: we use the specific version above; this is a last resort.
        print(f"  could not find a download URL for {spec.name} on {platform_id}",
              file=sys.stderr)
        print(f"  tried {len(possible_urls)} URL patterns. Install manually from:",
              file=sys.stderr)
        print(f"  https://github.com/{spec.github_repo}/releases/tag/v{version}",
              file=sys.stderr)
        return False

    # Extract
    bin_dir = get_stca_bin_dir()
    try:
        if archive_path.suffix == ".zip":
            with zipfile.ZipFile(archive_path) as zf:
                zf.extractall(bin_dir)
        else:
            with tarfile.open(archive_path, "r:gz") as tf:
                tf.extractall(bin_dir)
    except Exception as e:
        print(f"  extraction failed: {e}", file=sys.stderr)
        return False

    # Find and chmod the binary
    binary_path = bin_dir / spec.binary_name
    if not binary_path.exists():
        # search for it
        for p in bin_dir.rglob(spec.binary_name):
            if p.is_file():
                binary_path = p
                break

    if not binary_path.exists():
        print(f"  binary {spec.binary_name} not found after extraction", file=sys.stderr)
        return False

    # chmod +x on Unix
    if not platform.system().lower().startswith("windows"):
        st = binary_path.stat()
        binary_path.chmod(st.st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)

    # Verify checksum if available
    expected = (spec.checksums or {}).get(platform_id)
    if expected and not sha256_verify(binary_path, expected):
        print(f"  CHECKSUM VERIFICATION FAILED for {spec.name}", file=sys.stderr)
        return False
    elif not expected:
        print(f"  WARNING: no checksum for {spec.name} on {platform_id} — install unverified",
              file=sys.stderr)

    # cleanup
    archive_path.unlink(missing_ok=True)
    return True


def install_tool(name: str) -> Tuple[bool, str]:
    """Install a single tool. Returns (success, message)."""
    if name not in TOOLS:
        return False, f"unknown tool: {name}"

    spec = TOOLS[name]
    if is_tool_installed(spec.binary_name or spec.name):
        return True, f"{name} already installed"

    print(f"Installing {name} ({spec.description})...")
    if spec.kind == "python":
        ok = install_python_tool(spec)
    else:
        ok = install_binary_tool(spec)

    if ok:
        record_install(name, spec.version)
        return True, f"{name} {spec.version} installed"
    return False, f"failed to install {name}"


def record_install(name: str, version: str) -> None:
    """Record installed tool version."""
    data = {}
    if VERSIONS_FILE.exists():
        try:
            data = json.loads(VERSIONS_FILE.read_text())
        except Exception:
            pass
    data[name] = {"version": version, "kind": TOOLS[name].kind}
    VERSIONS_FILE.parent.mkdir(parents=True, exist_ok=True)
    VERSIONS_FILE.write_text(json.dumps(data, indent=2))


def install_all(force: bool = False) -> Dict[str, Tuple[bool, str]]:
    """Install all tools. Returns a dict of {tool_name: (success, message)}."""
    ensure_stca_bin_dir()
    ensure_stca_on_path()
    results = {}
    for name in TOOLS:
        if force and is_tool_installed(TOOLS[name].binary_name or name):
            # skip re-install unless forced
            results[name] = (True, f"{name} already installed (use --force to reinstall)")
            continue
        results[name] = install_tool(name)
    return results


def install_for_layers(layer_ids: list) -> Dict[str, Tuple[bool, str]]:
    """Install only the tools needed for specific layers."""
    needed = {name for name, spec in TOOLS.items() if spec.layer in layer_ids}
    results = {}
    for name in needed:
        results[name] = install_tool(name)
    return results


def print_install_report(results: Dict[str, Tuple[bool, str]]) -> None:
    """Print a human-readable install report."""
    print()
    print("=" * 60)
    print("STCA Tool Installation Report")
    print("=" * 60)
    for name, (ok, msg) in results.items():
        status = "✓" if ok else "✗"
        print(f"  {status} {name:<20} {msg}")
    print()
    print(f"STCA bin dir: {BIN_DIR}")
    print(f"Add to PATH:  export PATH=\"{BIN_DIR}:$PATH\"")
    print("=" * 60)
