from click.testing import CliRunner
import importlib
import pytest

def test_cli_exposes_command():
    cli = importlib.import_module("dockguard.cli")
    command = getattr(cli, "cli", getattr(cli, "main", None))
    assert command is not None

def test_cli_analyze_json(sample_root):
    cli = importlib.import_module("dockguard.cli")
    command = getattr(cli, "cli", getattr(cli, "main", None))
    result = CliRunner().invoke(command, ["analyze", str(sample_root / "unsafe-flask"), "--format", "json"])
    assert result.exit_code == 0, result.output
    assert "severity" in result.output.lower() or "finding" in result.output.lower()

def test_cli_missing_path_returns_error():
    cli = importlib.import_module("dockguard.cli")
    command = getattr(cli, "cli", getattr(cli, "main", None))
    result = CliRunner().invoke(command, ["analyze", "does-not-exist"])
    assert result.exit_code != 0
