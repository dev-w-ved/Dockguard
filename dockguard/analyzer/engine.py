"""High-level repository analysis API."""
import re
from pathlib import Path
from typing import Iterable
from .dependencies import audit_dependencies
from .models import AnalysisReport, AuditReport, Finding, RepositoryAnalysis
from .scanner import RepositoryScanner
from .secrets import scan_file

LANGUAGE_EXTENSIONS = {".py": "Python", ".js": "Node.js", ".jsx": "Node.js", ".ts": "Node.js", ".tsx": "Node.js", ".go": "Go", ".rs": "Rust", ".c": "C", ".h": "C/C++", ".cc": "C/C++", ".cpp": "C/C++", ".hpp": "C/C++"}
FRAMEWORK_MARKERS = {"django": "Django", "flask": "Flask", "fastapi": "FastAPI", "express": "Express", "next": "Next.js", "react": "React", "gin-gonic": "Gin", "actix": "Actix", "rocket": "Rocket", "spring": "Spring"}

def _files(root: Path) -> Iterable[Path]:
    ignored = {".git", "node_modules", "target", "vendor", "__pycache__", ".venv", "venv"}
    for path in root.rglob("*"):
        if path.is_file() and not any(part in ignored for part in path.parts):
            yield path

def _score(findings, base=100) -> int:
    penalty = sum({"critical": 30, "high": 18, "medium": 8, "low": 3}.get(f.severity, 5) for f in findings)
    return max(0, min(100, base - penalty))

def analyze(source: str) -> AnalysisReport:
    """Analyze a local directory or shallow-cloned public Git URL."""
    if isinstance(source, Path):
        source = str(source)
    if not isinstance(source, str) or not source.strip():
        raise ValueError("source must be a non-empty path or URL")
    if not RepositoryScanner.is_public_git_url(source) and not Path(source).expanduser().exists():
        raise FileNotFoundError(f"repository does not exist: {source}")
    try:
        with RepositoryScanner(source).checkout() as root:
            analysis = RepositoryAnalysis(source, str(root))
            all_files = list(_files(root)); analysis.files_scanned = len(all_files)
            seen = set(); frameworks = set(); findings = []
            for path in all_files:
                rel = path.relative_to(root).as_posix(); ext = path.suffix.lower()
                if ext in LANGUAGE_EXTENSIONS: analysis.languages.append(LANGUAGE_EXTENSIONS[ext])
                if path.name in ("main.py", "app.py", "manage.py", "main.go", "main.rs", "index.js", "server.js", "Dockerfile"): analysis.entry_points.append(rel)
                try: text = path.read_text(encoding="utf-8", errors="ignore") if path.stat().st_size < 1_000_000 else ""
                except OSError: text = ""
                lower = text.lower()
                for marker, framework in FRAMEWORK_MARKERS.items():
                    if marker in lower: frameworks.add(framework)
                for port in re.findall(r"(?i)(?:port|listen|run)\s*[:=( ]\s*([0-9]{2,5})", text):
                    value = int(port)
                    if 1 <= value <= 65535: analysis.ports.append(value)
                findings.extend(scan_file(path, rel))
            analysis.languages = sorted(set(analysis.languages)); analysis.frameworks = sorted(frameworks); analysis.entry_points = sorted(set(analysis.entry_points)); analysis.ports = sorted(set(analysis.ports)); analysis.findings = findings
            dependencies, dep_findings = audit_dependencies(root)
            audit = AuditReport(dependencies, findings + dep_findings, _score(findings + dep_findings))
            analysis.reproducibility_score = _score(dep_findings)
            return AnalysisReport(analysis, audit)
    except (ValueError, RuntimeError, OSError) as exc:
        return AnalysisReport(RepositoryAnalysis(source, "", reproducibility_score=0), AuditReport(security_score=0), [str(exc)])
