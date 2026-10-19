import json

from dockguard.web.app import remediation_diff, remediation_markdown, remediation_sarif


def test_remediation_redacts_secrets_and_pins_dependencies():
    report = {
        "findings": [
            {"kind": "aws-access-key", "path": "app.py", "line": 4, "evidence": "AKIA-DO-NOT-EXPORT"},
            {"kind": "unpinned-dependency", "path": "requirements.txt", "message": "requests is not pinned", "suggestion": "pin to requests==2.32.3"},
        ]
    }
    changes = remediation_diff(report)
    rendered = json.dumps(changes)
    assert "AKIA-DO-NOT-EXPORT" not in rendered
    assert ".env.example" in rendered
    assert "requests==2.32.3" in rendered


def test_exports_are_markdown_and_sarif():
    report = {"findings": [{"kind": "generic-secret", "path": ".env", "evidence": "secret-value"}]}
    markdown = remediation_markdown(report)
    sarif = remediation_sarif(report)
    assert markdown.startswith("# DockGuard Audit Report")
    assert "secret-value" not in markdown
    assert sarif["version"] == "2.1.0"
    assert sarif["runs"][0]["results"]
