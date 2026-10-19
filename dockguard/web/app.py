"""FastAPI entrypoint for DockGuard's developer dashboard.

The small adapter layer deliberately accepts the analyzer/generator APIs used by
both the CLI and older integrations, keeping the HTTP contract stable.
"""
from __future__ import annotations

import io
import inspect
import json
import tempfile
import zipfile
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse, StreamingResponse, Response
from pydantic import BaseModel, Field, field_validator

ROOT = Path(__file__).resolve().parents[2]
STATIC = Path(__file__).resolve().parent / "static"
app = FastAPI(title="DockGuard", version="1.0.0")


class ScanRequest(BaseModel):
    path: str | None = Field(default=None, max_length=2048)
    github_url: str | None = Field(default=None, max_length=2048)

    @field_validator("path", "github_url")
    @classmethod
    def nonempty(cls, value: str | None) -> str | None:
        if value is not None and not value.strip():
            raise ValueError("value must not be empty")
        return value.strip() if value else value


class GenerateRequest(ScanRequest):
    report: dict[str, Any] | None = None


class ReportRequest(ScanRequest):
    """A report may be posted directly so CI does not need a local checkout."""
    report: dict[str, Any] | None = None


def _call(fn: Any, source: str, report: dict[str, Any] | None = None) -> Any:
    """Invoke a project function while tolerating path/url and report signatures."""
    try:
        sig = inspect.signature(fn)
        names = list(sig.parameters)
        if report is not None and any(n in names for n in ("report", "analysis", "findings")):
            return fn(report=report) if "report" in names else fn(report)
        if "github_url" in names:
            return fn(github_url=source)
        if names and names[0] in ("path", "source", "project"):
            return fn(source)
        return fn(source)
    except (TypeError, ValueError):
        return fn(source)


def _jsonable(value: Any) -> Any:
    if hasattr(value, "model_dump"):
        return value.model_dump()
    if hasattr(value, "dict"):
        return value.dict()
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    if isinstance(value, dict):
        return {str(k): _jsonable(v) for k, v in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [_jsonable(v) for v in value]
    return {k: _jsonable(v) for k, v in vars(value).items() if not k.startswith("_")}


def _report_findings(report: dict[str, Any]) -> list[dict[str, Any]]:
    """Read both the flat and AnalysisReport-shaped report contracts."""
    findings = report.get("findings") or report.get("issues")
    if findings is None:
        audit = report.get("audit") or {}
        repository = report.get("repository") or {}
        findings = audit.get("findings") or repository.get("findings") or []
    return [f for f in findings if isinstance(f, dict)]


def _secret_finding(finding: dict[str, Any]) -> bool:
    text = " ".join(str(finding.get(k, "")) for k in ("kind", "title", "rule", "message", "description"))
    return any(word in text.lower() for word in ("secret", "token", "password", "credential", "private-key", "api-key", "access-key", "aws"))


def remediation_diff(report: dict[str, Any]) -> list[dict[str, Any]]:
    """Produce a stable, safe Before/After list; never copy secret evidence."""
    changes: list[dict[str, Any]] = []
    for finding in _report_findings(report):
        kind = str(finding.get("kind") or finding.get("rule") or "finding")
        path = str(finding.get("path") or "")
        line = finding.get("line")
        location = f"{path}:{line}" if path and line else path
        if _secret_finding(finding):
            slug = "_".join(c for c in f"{kind}_{path}".upper().replace("/", "_").replace(".", "_") if c.isalnum() or c == "_").strip("_")[:60] or "SECRET"
            variable = f"DOCKGUARD_{slug}"
            changes.append({"kind": "secret", "location": location, "before": "[REDACTED SECRET]", "after": f".env.example: {variable}=<your-secret>"})
        elif kind == "unpinned-dependency" or "unpinned" in kind.lower():
            suggested = finding.get("suggested_pin")
            if not suggested:
                suggestion = str(finding.get("suggestion") or "")
                suggested = suggestion.split("pin to", 1)[-1].strip() if "pin to" in suggestion else "<exact-version>"
            changes.append({"kind": "dependency", "location": location, "before": str(finding.get("requested") or finding.get("message") or "unpinned"), "after": str(suggested)})
    # Dependency objects are present in AnalysisReport even when callers omit
    # the corresponding audit findings (for example, imported CI reports).
    audit = report.get("audit") or {}
    dependencies = report.get("dependencies") or audit.get("dependencies") or []
    for dep in dependencies:
        if not isinstance(dep, dict) or dep.get("pinned"):
            continue
        name = str(dep.get("name") or "dependency")
        suggested = str(dep.get("suggested_pin") or "<exact-version>")
        ecosystem = str(dep.get("ecosystem") or "")
        filename = {"node": "package.json", "python": "requirements.txt", "rust": "Cargo.toml"}.get(ecosystem, "dependency manifest")
        item = {"kind": "dependency", "location": filename, "before": f"{name} {dep.get('requested', '*')}", "after": suggested}
        if item not in changes:
            changes.append(item)
    return sorted(changes, key=lambda item: (item["location"], item["kind"], item["before"], item["after"]))


def _safe_report(report: dict[str, Any]) -> dict[str, Any]:
    """Strip potentially sensitive values before serializing an export."""
    safe = {"findings": []}
    for finding in _report_findings(report):
        item = {k: v for k, v in finding.items() if k not in {"evidence", "value", "secret", "raw"}}
        if _secret_finding(item):
            item["evidence"] = "[REDACTED SECRET]"
        safe["findings"].append(item)
    return safe


def remediation_markdown(report: dict[str, Any]) -> str:
    rows = remediation_diff(report)
    lines = ["# DockGuard Audit Report", "", "## Remediation diff", "", "| Location | Kind | Before | After |", "| --- | --- | --- | --- |"]
    for row in rows:
        before = row["before"].replace("|", "\\|")
        after = row["after"].replace("|", "\\|")
        lines.append(f"| {row['location'] or 'repository'} | {row['kind']} | {before} | {after} |")
    if not rows:
        lines.append("| repository | — | No remediation required | No changes |")
    return "\n".join(lines) + "\n"


def remediation_sarif(report: dict[str, Any]) -> dict[str, Any]:
    results = []
    for change in remediation_diff(report):
        rule = "dockguard/" + change["kind"]
        result: dict[str, Any] = {"ruleId": rule, "level": "warning", "message": {"text": f"Remediate: {change['after']}"}}
        if change["location"]:
            path, _, line = change["location"].rpartition(":")
            result["locations"] = [{"physicalLocation": {"artifactLocation": {"uri": path or change["location"]}, **({"region": {"startLine": int(line)}} if line.isdigit() else {})}}]
        results.append(result)
    return {"$schema": "https://json.schemastore.org/sarif-2.1.0.json", "version": "2.1.0", "runs": [{"tool": {"driver": {"name": "DockGuard", "version": app.version}}, "results": results}]}


def analyze(source: str) -> dict[str, Any]:
    try:
        from dockguard import analyzer
        fn = next((getattr(analyzer, n) for n in ("analyze", "scan", "analyze_project", "run") if callable(getattr(analyzer, n, None))), None)
        if fn is None:
            raise RuntimeError("dockguard.analyzer has no supported entrypoint")
        result = _jsonable(_call(fn, source))
        return result if isinstance(result, dict) else {"findings": result}
    except ImportError as exc:
        raise RuntimeError("DockGuard analyzer is not installed") from exc


def generate(source: str, report: dict[str, Any] | None = None) -> dict[str, str]:
    try:
        from dockguard import generator
        fn = next((getattr(generator, n) for n in ("generate", "generate_files", "build") if callable(getattr(generator, n, None))), None)
        if fn is None:
            raise RuntimeError("dockguard.generator has no supported entrypoint")
        result = _call(fn, source, report)
        if hasattr(result, "files"):
            result = result.files
        result = _jsonable(result)
        if isinstance(result, dict):
            dockerfile = result.get("dockerfile") or result.get("Dockerfile") or result.get("docker_file") or ""
            compose = result.get("compose") or result.get("docker-compose.yml") or result.get("docker_compose") or ""
            return {"dockerfile": str(dockerfile), "compose": str(compose), "dockerignore": str(result.get(".dockerignore", ""))}
        raise RuntimeError("generator returned an unsupported result")
    except ImportError as exc:
        raise RuntimeError("DockGuard generator is not installed") from exc


def _source(req: ScanRequest) -> str:
    if bool(req.path) == bool(req.github_url):
        raise HTTPException(422, detail="Provide exactly one local path or GitHub URL")
    source = req.path or req.github_url or ""
    if req.github_url and not req.github_url.startswith(("https://github.com/", "http://github.com/")):
        raise HTTPException(422, detail="github_url must point to github.com")
    if req.path and not Path(req.path).exists():
        raise HTTPException(422, detail="Local path does not exist")
    return source


@app.get("/", include_in_schema=False)
def index() -> FileResponse:
    return FileResponse(STATIC / "index.html")


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/api/sample-projects")
def sample_projects() -> list[dict[str, str]]:
    return [{"id": "python-fastapi", "name": "Python FastAPI", "description": "Production-ready API starter"}, {"id": "node-express", "name": "Node Express", "description": "Minimal Express service"}]


@app.post("/api/scan")
def scan(req: ScanRequest) -> dict[str, Any]:
    source = _source(req)
    try:
        return {"source": source, "report": analyze(source)}
    except Exception as exc:
        raise HTTPException(400, detail=str(exc)) from exc


@app.post("/analyze")
def analyze_compat(payload: dict[str, Any]) -> dict[str, Any]:
    source = payload.get("path") or payload.get("github_url")
    if not source:
        raise HTTPException(422, detail="path is required")
    try:
        return analyze(source)
    except Exception as exc:
        raise HTTPException(422, detail=str(exc)) from exc


@app.post("/api/generate")
def generate_endpoint(req: GenerateRequest) -> dict[str, Any]:
    source = _source(req)
    try:
        report = req.report or analyze(source)
        files = generate(source, report)
        return {"source": source, "report": report, **files}
    except Exception as exc:
        raise HTTPException(400, detail=str(exc)) from exc


@app.post("/api/download")
def download(req: GenerateRequest) -> StreamingResponse:
    source = _source(req)
    files = generate(source, req.report)
    payload = io.BytesIO()
    with zipfile.ZipFile(payload, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("Dockerfile", files["dockerfile"])
        archive.writestr("docker-compose.yml", files["compose"])
    payload.seek(0)
    return StreamingResponse(payload, media_type="application/zip", headers={"Content-Disposition": "attachment; filename=dockguard-generated.zip"})


def _posted_report(req: ReportRequest) -> dict[str, Any]:
    if req.report is not None:
        return req.report
    source = _source(req)
    try:
        return analyze(source)
    except Exception as exc:
        raise HTTPException(400, detail=str(exc)) from exc


@app.post("/api/remediation")
def remediation(req: ReportRequest) -> dict[str, Any]:
    return {"changes": remediation_diff(_safe_report(_posted_report(req)))}


@app.post("/api/export/markdown")
@app.post("/api/report/markdown")
def export_markdown(req: ReportRequest) -> Response:
    return Response(remediation_markdown(_safe_report(_posted_report(req))), media_type="text/markdown", headers={"Content-Disposition": "attachment; filename=dockguard-audit.md"})


@app.post("/api/export/sarif")
@app.post("/api/report/sarif")
def export_sarif(req: ReportRequest) -> Response:
    payload = json.dumps(remediation_sarif(_safe_report(_posted_report(req))), sort_keys=True, indent=2) + "\n"
    return Response(payload, media_type="application/sarif+json", headers={"Content-Disposition": "attachment; filename=dockguard-audit.sarif.json"})
