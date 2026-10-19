"""DockGuard command line interface."""
from __future__ import annotations

import json
from pathlib import Path

import typer
from rich.console import Console

from .analyzer import analyze
from .generator import generate

_typer_app = typer.Typer(help="Analyze projects and generate hardened container artifacts.")
app = _typer_app
console = Console()


@_typer_app.command("analyze")
@_typer_app.command("scan")
def scan(path: Path = typer.Argument(Path("."), exists=True, file_okay=False), output_format: str = typer.Option("text", "--format")):
    """Analyze a project and print its score and findings."""
    report = analyze(path)
    if output_format == "json":
        console.print(json.dumps(report.to_dict(), default=str))
        return
    console.print(f"[bold]DockGuard score:[/bold] {report.score}/100")
    console.print(f"Security: {report.security_score}/100 | Reproducibility: {report.repository.reproducibility_score}/100")
    for finding in report.findings:
        console.print(f"• [{finding.severity}] {finding.message}")


@_typer_app.command("generate")
def generate_cmd(path: Path = typer.Argument(Path("."), exists=True, file_okay=False), output: Path = typer.Option(Path("."), "--output", "-o")):
    """Generate Dockerfile, compose, ignore, and pinned dependencies."""
    written = generate(analyze(path)).write(output)
    for item in written:
        console.print(f"[green]wrote[/green] {item}")


@_typer_app.command("serve")
def serve(host: str = "127.0.0.1", port: int = 8080):
    """Launch the local FastAPI dashboard."""
    import uvicorn
    uvicorn.run("dockguard.web.app:app", host=host, port=port)


cli = typer.main.get_command(_typer_app)

if __name__ == "__main__":
    _typer_app()
