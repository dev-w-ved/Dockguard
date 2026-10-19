"""Regex and entropy-assisted secret detection."""
import math
import re
from pathlib import Path
from typing import List
from .models import Finding

PATTERNS = [
    ("aws-access-key", re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "high"),
    ("aws-secret-key", re.compile(r"(?i)aws[_-]?secret[_-]?(?:access[_-]?)?key\s*[:=]\s*['\"]?([A-Za-z0-9/+=]{ thirty,})".replace("{ thirty,}", "{30,}")), "high"),
    ("private-key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"), "critical"),
    ("generic-secret", re.compile(r"(?i)\b(?:password|passwd|secret|api[_-]?key|token)\b\s*[:=]\s*['\"]([^'\"\s]{8,})['\"]"), "high"),
    ("github-token", re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{20,}\b"), "high"),
]

def _entropy(value: str) -> float:
    counts = {c: value.count(c) for c in set(value)}
    return -sum((n / len(value)) * math.log2(n / len(value)) for n in counts.values()) if value else 0.0

def scan_file(path: Path, relative: str) -> List[Finding]:
    if path.name in (".env", ".env.local", ".env.production"):
        return [Finding("env-exposure", "high", "environment file may expose secrets", relative, suggestion="exclude .env files and use a secret manager")]
    try:
        data = path.read_bytes()
        if b"\x00" in data or len(data) > 2_000_000:
            return []
        text = data.decode("utf-8", errors="replace")
    except OSError:
        return []
    findings: List[Finding] = []
    for line_no, line in enumerate(text.splitlines(), 1):
        for kind, pattern, severity in PATTERNS:
            match = pattern.search(line)
            if match:
                evidence = "[REDACTED SECRET]"
                findings.append(Finding(kind, severity, "possible secret detected", relative, line_no, evidence, "rotate the credential and remove it from source", 0.95))
        for candidate in re.findall(r"['\"]([A-Za-z0-9_+/=-]{20,})['\"]", line):
            if _entropy(candidate) >= 4.0 and not re.fullmatch(r"[0-9]+", candidate):
                findings.append(Finding("high-entropy-token", "medium", "high-entropy token-like value", relative, line_no, candidate[:8] + "…", "move token to managed secrets", 0.65))
    return findings
