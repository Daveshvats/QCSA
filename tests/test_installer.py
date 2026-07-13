"""Tests for the installer module."""
import pytest
from loomscan.installer import (
    TOOLS, ToolSpec, get_platform_id, is_tool_installed,
)


def test_platform_id_format():
    pid = get_platform_id()
    assert "_" in pid
    parts = pid.split("_")
    assert len(parts) == 2
    assert parts[0] in ("linux", "darwin", "windows")
    assert parts[1] in ("amd64", "arm64", "arm", "386", "x86_64")


def test_tool_registry_has_required_tools():
    """The registry should include all the tools we promise."""
    required = ["gitleaks", "semgrep", "opa", "mutmut", "atheris", "pip-audit",
                "osv-scanner", "trivy", "ruff", "hypothesis"]
    for name in required:
        assert name in TOOLS, f"Missing tool: {name}"


def test_each_tool_has_layer_assignment():
    """Every tool should be tagged with the layer it serves."""
    valid_layers = ("L0", "L0b", "L0c", "L0d", "L0e", "L0f",
                    "L1", "L2", "L4", "L5", "L6", "L7", "L8")
    for name, spec in TOOLS.items():
        assert spec.layer in valid_layers, \
               f"{name} has invalid layer: {spec.layer}"


def test_python_tools_have_pip_installable_names():
    """Python tools must be pip-installable (name == package name)."""
    for name, spec in TOOLS.items():
        if spec.kind == "python":
            assert spec.name == name


def test_binary_tools_have_github_repo():
    """Binary tools must have a github_repo for download."""
    for name, spec in TOOLS.items():
        if spec.kind == "binary":
            assert spec.github_repo, f"{name} missing github_repo"
            assert "/" in spec.github_repo, f"{name} invalid github_repo: {spec.github_repo}"
            assert spec.binary_name, f"{name} missing binary_name"


def test_is_tool_installed_returns_bool():
    """is_tool_installed should return a bool."""
    assert isinstance(is_tool_installed("definitely_not_a_tool_xyz123"), bool)
    assert is_tool_installed("definitely_not_a_tool_xyz123") is False
