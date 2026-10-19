from pathlib import Path
import importlib
import pytest

def _analyzer():
    return importlib.import_module("dockguard.analyzer")

def test_all_three_samples_exist(sample_root):
    assert {p.name for p in sample_root.iterdir() if p.is_dir()} >= {"unsafe-flask", "leaky-node", "cloud-worker"}

def test_fixture_files_contain_expected_signals(sample_root):
    assert "AWS_SECRET_ACCESS_KEY" in (sample_root / "unsafe-flask/app.py").read_text()
    assert "axios.get(target)" in (sample_root / "leaky-node/server.js").read_text()
    assert "yaml.load" in (sample_root / "cloud-worker/worker.py").read_text()

def test_analyze_sample_finds_issues(sample_root):
    mod = _analyzer()
    result = mod.analyze(sample_root / "unsafe-flask")
    findings = getattr(result, "findings", result["findings"] if isinstance(result, dict) else [])
    assert findings

def test_analyzer_finding_has_location_and_severity(sample_root):
    result = _analyzer().analyze(sample_root / "cloud-worker")
    findings = getattr(result, "findings", result["findings"] if isinstance(result, dict) else [])
    first = findings[0]
    assert (getattr(first, "severity", None) or first.get("severity")) in {"critical", "high", "medium", "low"}
    assert getattr(first, "line", None) or first.get("line")

def test_clean_directory_has_no_findings(tmp_path):
    (tmp_path / "safe.py").write_text("def add(a, b):\n    return a + b\n")
    result = _analyzer().analyze(tmp_path)
    findings = getattr(result, "findings", result["findings"] if isinstance(result, dict) else [])
    assert findings == []

def test_missing_path_is_rejected(tmp_path):
    with pytest.raises((FileNotFoundError, ValueError)):
        _analyzer().analyze(tmp_path / "missing")

def test_secret_evidence_is_redacted(sample_root):
    result = _analyzer().analyze(sample_root / "unsafe-flask")
    text = str(result)
    assert "wJalrXUtnFEMI" not in text

def test_dependency_files_are_scanned(sample_root):
    result = _analyzer().analyze(sample_root / "leaky-node")
    findings = getattr(result, "findings", result["findings"] if isinstance(result, dict) else [])
    assert any("depend" in str(f).lower() or "pin" in str(f).lower() for f in findings)
