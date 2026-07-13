"""Tests for the L0b supply chain layer."""
import pytest
from pathlib import Path
from loomscan.layers.l0b_supply_chain import L0bSupplyChain, TYPOSQUATS, EOL_PYTHON
from loomscan.models import Severity


@pytest.fixture
def layer():
    return L0bSupplyChain()


def test_typosquats_dictionary_has_known_examples(layer):
    """The typosquat dictionary should catch well-known bad packages."""
    assert "reqeusts" in TYPOSQUATS
    assert TYPOSQUATS["reqeusts"] == "requests"


def test_eol_python_versions_defined():
    """Python 3.7/3.8/3.9 are EOL."""
    assert "3.7" in EOL_PYTHON
    assert "3.8" in EOL_PYTHON
    assert "3.9" in EOL_PYTHON
    assert "3.10" not in EOL_PYTHON


def test_check_typosquats_finds_bad_package(layer, tmp_path):
    """Should detect a typosquatted package in requirements.txt."""
    req = tmp_path / "requirements.txt"
    req.write_text("reqeusts==2.28.0\nrequests==2.28.0\n")
    findings = layer._check_typosquats(tmp_path)
    assert any("typosquat" in f.rule_id and "reqeusts" in f.rule_id for f in findings)


def test_check_eol_versions_finds_old_python_in_dockerfile(layer, tmp_path):
    """Should flag EOL Python in a Dockerfile."""
    dockerfile = tmp_path / "Dockerfile"
    dockerfile.write_text("FROM python:3.7-slim\nCMD python app.py\n")
    findings = layer._check_eol_versions(tmp_path)
    eol_findings = [f for f in findings if "eol" in f.rule_id]
    assert any("python" in f.rule_id for f in eol_findings)


def test_check_eol_versions_finds_old_node_in_nvmrc(layer, tmp_path):
    """Should flag EOL Node in .nvmrc."""
    nvmrc = tmp_path / ".nvmrc"
    nvmrc.write_text("v16.20.0\n")
    findings = layer._check_eol_versions(tmp_path)
    assert any("nvmrc" in f.rule_id for f in findings)


def test_check_eol_versions_passes_for_modern_python(layer, tmp_path):
    """No finding when running on Python 3.12+."""
    # we can't easily change sys.version_info in a test, so just verify
    # the Dockerfile check doesn't fire for modern base images
    dockerfile = tmp_path / "Dockerfile"
    dockerfile.write_text("FROM python:3.12-slim\n")
    findings = layer._check_eol_versions(tmp_path)
    eol_docker = [f for f in findings if "eol.docker_python" in f.rule_id]
    assert len(eol_docker) == 0
