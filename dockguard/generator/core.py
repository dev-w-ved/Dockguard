"""Generate hardened Docker artifacts from analyzer results.

The analyzer has intentionally remained a loose integration point: mappings,
dataclasses and objects exposing attributes are all accepted here.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping
import json


@dataclass(frozen=True)
class GeneratedArtifacts:
    files: dict[str, str]

    def write(self, directory: str | Path) -> list[Path]:
        root = Path(directory)
        root.mkdir(parents=True, exist_ok=True)
        paths = []
        for name, content in self.files.items():
            path = root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content, encoding="utf-8", newline="\n")
            paths.append(path)
        return paths


def _value(report: Any, *names: str, default: Any = None) -> Any:
    for name in names:
        if isinstance(report, Mapping) and name in report:
            return report[name]
        if hasattr(report, name):
            return getattr(report, name)
    return default


def _normalize(report: Any) -> dict[str, Any]:
    repository = _value(report, "repository", default=None)
    audit = _value(report, "audit", default=None)
    stack_value = _value(report, "stack", "language", "runtime", "detected_stack", default=None)
    if stack_value is None:
        languages = _value(repository, "languages", default=[]) if repository is not None else []
        frameworks = _value(repository, "frameworks", default=[]) if repository is not None else []
        stack_value = (languages or frameworks or ["python"])[0]
    stack = str(stack_value).lower()
    if "node" in stack or "javascript" in stack or "typescript" in stack:
        stack = "node"
    elif "go" in stack:
        stack = "go"
    elif "java" in stack:
        stack = "java"
    elif "python" not in stack:
        stack = "python"
    deps = _value(report, "dependencies", "requirements", "packages", default=None)
    if deps is None and audit is not None:
        deps = _value(audit, "dependencies", default=[])
    if isinstance(deps, Mapping):
        deps = [f"{k}=={v}" for k, v in sorted(deps.items())]
    normalized_deps = []
    for dep in deps or []:
        if isinstance(dep, Mapping):
            name, requested, suggested = dep.get("name", ""), dep.get("requested", ""), dep.get("suggested_pin")
            normalized_deps.append(f"{name}=={suggested or requested}" if suggested or requested else str(name))
        elif hasattr(dep, "name"):
            normalized_deps.append(f"{dep.name}=={getattr(dep, 'suggested_pin', None) or getattr(dep, 'requested', '')}")
        else:
            normalized_deps.append(str(dep))
    deps = sorted(set(normalized_deps))
    command = _value(report, "command", "start_command", "run_command", default=None)
    if command is None and repository is not None:
        entries = _value(repository, "entry_points", default=[])
        command = entries[0] if entries else None
    port = _value(report, "port", default=None)
    if port is None and repository is not None:
        ports = _value(repository, "ports", default=[])
        port = ports[0] if ports else 8000
    return {"stack": stack, "dependencies": deps, "command": command, "port": int(port or 8000)}


def generate_dockerfile(report: Any) -> str:
    info = _normalize(report)
    stack = info["stack"]
    if stack == "node":
        lines = [
            "# syntax=docker/dockerfile:1.7", "FROM node:22.11.0-bookworm-slim AS build", "WORKDIR /app",
            "COPY package*.json ./", "RUN --mount=type=cache,target=/root/.npm npm ci --omit=dev", "COPY . .",
            "FROM node:22.11.0-bookworm-slim", "ENV NODE_ENV=production", "WORKDIR /app",
            "RUN groupadd --system --gid 10001 app && useradd --system --uid 10001 --gid app app",
            "COPY --from=build --chown=app:app /app /app", "USER 10001:10001", f"EXPOSE {info['port']}",
            "HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 CMD node -e \"fetch('http://127.0.0.1:%s/').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))\"" % info["port"],
            'CMD ["npm", "start"]',
        ]
    elif stack == "go":
        lines = [
            "# syntax=docker/dockerfile:1.7", "FROM golang:1.23.2-bookworm AS build", "WORKDIR /src",
            "COPY go.mod go.sum ./", "RUN --mount=type=cache,target=/go/pkg/mod go mod download", "COPY . .",
            "RUN --mount=type=cache,target=/root/.cache/go-build CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o /out/app .",
            "FROM gcr.io/distroless/static-debian12:nonroot", "COPY --from=build /out/app /app", "USER nonroot:nonroot",
            f"EXPOSE {info['port']}", "HEALTHCHECK --interval=30s --timeout=5s --retries=3 CMD [\"/app\", \"--healthcheck\"]", 'ENTRYPOINT ["/app"]',
        ]
    elif stack == "java":
        lines = [
            "# syntax=docker/dockerfile:1.7", "FROM eclipse-temurin:21.0.5_11-jdk AS build", "WORKDIR /app", "COPY . .",
            "RUN --mount=type=cache,target=/root/.m2 ./mvnw -B -DskipTests package", "FROM eclipse-temurin:21.0.5_11-jre",
            "WORKDIR /app", "RUN useradd --system --uid 10001 app", "COPY --from=build --chown=app:app /app/target/*.jar app.jar",
            "USER 10001:10001", f"EXPOSE {info['port']}", "HEALTHCHECK --interval=30s --timeout=5s --retries=3 CMD [\"sh\", \"-c\", \"wget -qO- http://127.0.0.1:%s/ || exit 1\"]" % info["port"], 'ENTRYPOINT ["java", "-jar", "app.jar"]',
        ]
    else:
        lines = [
            "# syntax=docker/dockerfile:1.7", "FROM python:3.12.7-slim-bookworm AS build", "WORKDIR /app",
            "ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1", "COPY requirements*.txt ./",
            "RUN --mount=type=cache,target=/root/.cache/pip python -m pip install --no-cache-dir --require-hashes -r requirements.txt --target /opt/venv",
            "COPY . .", "FROM python:3.12.7-slim-bookworm", "WORKDIR /app", "ENV PATH=/opt/venv/bin:$PATH PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1",
            "RUN groupadd --system --gid 10001 app && useradd --system --uid 10001 --gid app app", "COPY --from=build /opt/venv /opt/venv", "COPY --from=build --chown=app:app /app /app", "USER 10001:10001",
            f"EXPOSE {info['port']}", "HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 CMD python -c \"import urllib.request; urllib.request.urlopen('http://127.0.0.1:%s/', timeout=3)\"" % info["port"], 'CMD ["python", "-m", "app"]',
        ]
    return "\n".join(lines) + "\n"


def generate_dockerignore(_: Any = None) -> str:
    return """.git
.gitignore
.env*
__pycache__/
*.py[cod]
node_modules/
.venv/
venv/
dist/
build/
*.log
Dockerfile*
docker-compose*.yml
"""


def generate_compose(report: Any) -> str:
    port = _normalize(report)["port"]
    return """services:
  app:
    build:
      context: .
      dockerfile: Dockerfile
    ports:
      - \"%s:%s\"
    read_only: true
    security_opt:
      - no-new-privileges:true
    cap_drop:
      - ALL
    restart: unless-stopped
    healthcheck:
      test: [\"CMD-SHELL\", \"wget -qO- http://127.0.0.1:%s/ || exit 1\"]
      interval: 30s
      timeout: 5s
      retries: 3
""" % (port, port, port)


def generate(report: Any, *, include_requirements: bool = True) -> GeneratedArtifacts:
    info = _normalize(report)
    files = {"Dockerfile": generate_dockerfile(report), ".dockerignore": generate_dockerignore(report), "docker-compose.yml": generate_compose(report)}
    if include_requirements and info["stack"] == "python":
        deps = info["dependencies"]
        files["requirements.txt"] = "\n".join(d if "==" in d else f"{d}==0.0.0" for d in deps) + ("\n" if deps else "")
    return GeneratedArtifacts(files)


def generate_report(report: Any) -> dict[str, Any]:
    if hasattr(report, "to_dict"):
        return report.to_dict()
    if isinstance(report, Mapping):
        return dict(report)
    return {k: v for k, v in vars(report).items() if not k.startswith("_")}
