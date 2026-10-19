"""Stable, JSON-serializable report models (stdlib only)."""
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional

@dataclass
class Finding:
    kind: str
    severity: str
    message: str
    path: Optional[str] = None
    line: Optional[int] = None
    evidence: Optional[str] = None
    suggestion: Optional[str] = None
    confidence: float = 1.0

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

@dataclass
class Dependency:
    name: str
    requested: str
    pinned: bool
    suggested_pin: Optional[str] = None
    ecosystem: str = "unknown"

@dataclass
class RepositoryAnalysis:
    source: str
    path: str
    languages: List[str] = field(default_factory=list)
    frameworks: List[str] = field(default_factory=list)
    entry_points: List[str] = field(default_factory=list)
    ports: List[int] = field(default_factory=list)
    files_scanned: int = 0
    reproducibility_score: int = 100
    findings: List[Finding] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

@dataclass
class AuditReport:
    dependencies: List[Dependency] = field(default_factory=list)
    findings: List[Finding] = field(default_factory=list)
    security_score: int = 100

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

@dataclass
class AnalysisReport:
    repository: RepositoryAnalysis
    audit: AuditReport
    errors: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @property
    def findings(self) -> List[Finding]:
        return self.audit.findings or self.repository.findings

    @property
    def security_score(self) -> int:
        return self.audit.security_score

    @property
    def score(self) -> int:
        return round((self.security_score + self.repository.reproducibility_score) / 2)
