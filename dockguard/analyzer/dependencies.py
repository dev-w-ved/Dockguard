"""Manifest parsing and deterministic dependency reproducibility checks."""
import hashlib
import json
import re
from pathlib import Path
from typing import List, Tuple
from .models import Dependency, Finding

def _pin(name: str, requested: str) -> str:
    digest = hashlib.sha256((name + "@" + requested).encode()).hexdigest()
    return "0.0.0+" + digest[:12]

def audit_dependencies(root: Path) -> Tuple[List[Dependency], List[Finding]]:
    deps: List[Dependency] = []; findings: List[Finding] = []
    package = root / "package.json"
    if package.exists():
        try: data = json.loads(package.read_text(encoding="utf-8"))
        except (OSError, ValueError): data = {}
        for section in ("dependencies", "devDependencies", "peerDependencies"):
            for name, version in (data.get(section, {}) or {}).items():
                value = str(version); pinned = bool(re.fullmatch(r"\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?", value))
                dep = Dependency(name, value, pinned, None if pinned else _pin(name, value), "node")
                deps.append(dep)
                if not pinned: findings.append(Finding("unpinned-dependency", "medium", f"{name} is not pinned", "package.json", suggestion=f"pin to {dep.suggested_pin}"))
    req = root / "requirements.txt"
    if req.exists():
        for line in req.read_text(encoding="utf-8", errors="replace").splitlines():
            match = re.match(r"\s*([A-Za-z0-9_.-]+)\s*(.*)", line)
            if not match or line.lstrip().startswith("#"): continue
            name, value = match.groups(); pinned = value.startswith("==") and bool(re.match(r"==\d+\.\d+\.\d+", value))
            dep = Dependency(name, value.strip() or "*", pinned, None if pinned else _pin(name, value), "python"); deps.append(dep)
            if not pinned: findings.append(Finding("unpinned-dependency", "medium", f"{name} is not pinned", "requirements.txt", suggestion=f"pin to {dep.suggested_pin}"))
    cargo = root / "Cargo.toml"
    if cargo.exists():
        in_deps = False
        for line in cargo.read_text(encoding="utf-8", errors="replace").splitlines():
            if line.startswith("["): in_deps = line.strip() in ("[dependencies]", "[dev-dependencies]"); continue
            match = re.match(r"\s*([\w-]+)\s*=\s*\"([^\"]+)\"", line) if in_deps else None
            if match:
                name, value = match.groups(); pinned = bool(re.fullmatch(r"\d+\.\d+\.\d+", value)); dep = Dependency(name, value, pinned, None if pinned else _pin(name, value), "rust"); deps.append(dep)
                if not pinned: findings.append(Finding("unpinned-dependency", "medium", f"{name} is not pinned", "Cargo.toml", suggestion=f"pin to {dep.suggested_pin}"))
    return deps, findings
