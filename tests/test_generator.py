import importlib
import json

def _report(result):
    mod = importlib.import_module("dockguard.generator")
    for name in ("generate_report", "render_report", "build_report"):
        if hasattr(mod, name):
            return getattr(mod, name)(result)
    raise AssertionError("generator public report function is missing")

def test_json_report_is_serializable(sample_root):
    result = importlib.import_module("dockguard.analyzer").analyze(sample_root / "unsafe-flask")
    output = _report(result)
    if isinstance(output, str):
        json.loads(output)
    else:
        json.dumps(output)

def test_report_contains_findings(sample_root):
    result = importlib.import_module("dockguard.analyzer").analyze(sample_root / "cloud-worker")
    output = str(_report(result)).lower()
    assert "finding" in output or "severity" in output

def test_report_supports_markdown_or_text(sample_root):
    result = importlib.import_module("dockguard.analyzer").analyze(sample_root / "leaky-node")
    output = _report(result)
    assert isinstance(output, (str, dict, list))
