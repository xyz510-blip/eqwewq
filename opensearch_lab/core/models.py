"""Core data models for OSINT findings, graph entities, risk scoring, and reports."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any


def utc_now_iso() -> str:
    """Return current UTC timestamp in ISO-8601 format."""
    return datetime.now(timezone.utc).isoformat()


class TargetType(str, Enum):
    """Supported investigation target types."""

    USERNAME = "username"
    EMAIL = "email"
    PHONE = "phone"
    DOMAIN = "domain"
    IP = "ip"
    URL = "url"
    CRYPTO_WALLET = "crypto_wallet"
    BANK_ACCOUNT = "bank_account"
    IMAGE_FILE = "image_file"
    FULL_NAME = "full_name"
    UNKNOWN = "unknown"


class Severity(str, Enum):
    """Severity levels for findings and risk signals."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class Finding:
    """A single intelligence finding produced by an OSINT module."""

    source: str
    category: str
    title: str
    value: str
    url: str = ""
    severity: Severity = Severity.INFO
    confidence: float = 0.8
    risk_delta: int = 0
    metadata: dict[str, Any] = field(default_factory=dict)
    timestamp: str = field(default_factory=utc_now_iso)
    verification_status: str = "unverified"  # verified | corroborated | likely | unverified_login_wall | filtered_false_positive | unverified
    signal_tier: str = "advisory"  # confirmed_threat | suspicious | advisory | trust

    def to_dict(self) -> dict[str, Any]:
        return {
            "source": self.source,
            "category": self.category,
            "title": self.title,
            "value": self.value,
            "url": self.url,
            "severity": self.severity.value if isinstance(self.severity, Severity) else str(self.severity),
            "confidence": self.confidence,
            "risk_delta": self.risk_delta,
            "metadata": self.metadata,
            "timestamp": self.timestamp,
            "verification_status": self.verification_status,
            "signal_tier": self.signal_tier,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Finding:
        sev_raw = data.get("severity", Severity.INFO.value)
        try:
            sev = Severity(sev_raw)
        except ValueError:
            sev = Severity.INFO
        return cls(
            source=str(data.get("source", "")),
            category=str(data.get("category", "general")),
            title=str(data.get("title", "")),
            value=str(data.get("value", "")),
            url=str(data.get("url", "")),
            severity=sev,
            confidence=float(data.get("confidence", 0.8)),
            risk_delta=int(data.get("risk_delta", 0)),
            metadata=dict(data.get("metadata") or {}),
            timestamp=str(data.get("timestamp") or utc_now_iso()),
            verification_status=str(data.get("verification_status", "unverified")),
            signal_tier=str(data.get("signal_tier", "advisory")),
        )


@dataclass
class EntityNode:
    """Node in the entity-relationship investigation graph."""

    id: str
    label: str
    entity_type: str
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "label": self.label,
            "entity_type": self.entity_type,
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> EntityNode:
        return cls(
            id=str(data["id"]),
            label=str(data.get("label", data["id"])),
            entity_type=str(data.get("entity_type", "entity")),
            metadata=dict(data.get("metadata") or {}),
        )


@dataclass
class EntityEdge:
    """Directed edge connecting two entities in the investigation graph."""

    source: str
    target: str
    relation: str
    weight: float = 1.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "source": self.source,
            "target": self.target,
            "relation": self.relation,
            "weight": self.weight,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> EntityEdge:
        return cls(
            source=str(data["source"]),
            target=str(data["target"]),
            relation=str(data.get("relation", "related_to")),
            weight=float(data.get("weight", 1.0)),
        )


@dataclass
class ModuleResult:
    """Output returned by a single OSINT module execution."""

    module_name: str
    display_name: str
    status: str  # ok | partial | skipped | error
    duration_ms: int
    findings: list[Finding] = field(default_factory=list)
    entities: list[EntityNode] = field(default_factory=list)
    edges: list[EntityEdge] = field(default_factory=list)
    summary: str = ""
    error: str = ""
    pivot_candidates: list[dict[str, str]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "module_name": self.module_name,
            "display_name": self.display_name,
            "status": self.status,
            "duration_ms": self.duration_ms,
            "findings": [f.to_dict() for f in self.findings],
            "entities": [e.to_dict() for e in self.entities],
            "edges": [edge.to_dict() for edge in self.edges],
            "summary": self.summary,
            "error": self.error,
            "pivot_candidates": self.pivot_candidates,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ModuleResult:
        return cls(
            module_name=str(data.get("module_name", "")),
            display_name=str(data.get("display_name", "")),
            status=str(data.get("status", "ok")),
            duration_ms=int(data.get("duration_ms", 0)),
            findings=[Finding.from_dict(f) for f in data.get("findings") or []],
            entities=[EntityNode.from_dict(e) for e in data.get("entities") or []],
            edges=[EntityEdge.from_dict(e) for e in data.get("edges") or []],
            summary=str(data.get("summary", "")),
            error=str(data.get("error", "")),
            pivot_candidates=list(data.get("pivot_candidates") or []),
        )


@dataclass
class RiskSignal:
    """Individual factor contributing to the overall scam/threat risk score."""

    source: str
    label: str
    points: int
    severity: Severity
    detail: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "source": self.source,
            "label": self.label,
            "points": self.points,
            "severity": self.severity.value if isinstance(self.severity, Severity) else str(self.severity),
            "detail": self.detail,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> RiskSignal:
        try:
            sev = Severity(data.get("severity", Severity.INFO.value))
        except ValueError:
            sev = Severity.INFO
        return cls(
            source=str(data.get("source", "")),
            label=str(data.get("label", "")),
            points=int(data.get("points", 0)),
            severity=sev,
            detail=str(data.get("detail", "")),
        )


@dataclass
class RiskAssessment:
    """Aggregated anti-scam and threat risk assessment (0-100)."""

    score: int
    level: str  # LOW | MEDIUM | HIGH | CRITICAL
    signals: list[RiskSignal] = field(default_factory=list)
    summary: str = ""
    trust_signals: list[dict[str, Any]] = field(default_factory=list)
    confidence: float = 0.8

    def to_dict(self) -> dict[str, Any]:
        return {
            "score": self.score,
            "level": self.level,
            "signals": [s.to_dict() for s in self.signals],
            "summary": self.summary,
            "trust_signals": self.trust_signals,
            "confidence": self.confidence,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> RiskAssessment:
        return cls(
            score=int(data.get("score", 0)),
            level=str(data.get("level", "LOW")),
            signals=[RiskSignal.from_dict(s) for s in data.get("signals") or []],
            summary=str(data.get("summary", "")),
            trust_signals=list(data.get("trust_signals") or []),
            confidence=float(data.get("confidence", 0.8)),
        )


@dataclass
class InvestigationReport:
    """Complete investigation dossier produced by the OpenSearch engine."""

    case_id: str
    query: str
    target_type: TargetType
    created_at: str
    duration_ms: int
    modules_run: list[ModuleResult] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    entities: list[EntityNode] = field(default_factory=list)
    edges: list[EntityEdge] = field(default_factory=list)
    risk: RiskAssessment = field(default_factory=lambda: RiskAssessment(score=0, level="LOW"))
    pivot_suggestions: list[dict[str, str]] = field(default_factory=list)
    watchlist_matches: list[dict[str, Any]] = field(default_factory=list)
    notes: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)
    filtered_false_positives: list[Finding] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "case_id": self.case_id,
            "query": self.query,
            "target_type": self.target_type.value if isinstance(self.target_type, TargetType) else str(self.target_type),
            "created_at": self.created_at,
            "duration_ms": self.duration_ms,
            "modules_run": [m.to_dict() for m in self.modules_run],
            "findings": [f.to_dict() for f in self.findings],
            "entities": [e.to_dict() for e in self.entities],
            "edges": [e.to_dict() for e in self.edges],
            "risk": self.risk.to_dict(),
            "pivot_suggestions": self.pivot_suggestions,
            "watchlist_matches": self.watchlist_matches,
            "notes": self.notes,
            "metadata": self.metadata,
            "filtered_false_positives": [f.to_dict() for f in self.filtered_false_positives],
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> InvestigationReport:
        try:
            ttype = TargetType(data.get("target_type", TargetType.UNKNOWN.value))
        except ValueError:
            ttype = TargetType.UNKNOWN
        return cls(
            case_id=str(data.get("case_id", "")),
            query=str(data.get("query", "")),
            target_type=ttype,
            created_at=str(data.get("created_at") or utc_now_iso()),
            duration_ms=int(data.get("duration_ms", 0)),
            modules_run=[ModuleResult.from_dict(m) for m in data.get("modules_run") or []],
            findings=[Finding.from_dict(f) for f in data.get("findings") or []],
            entities=[EntityNode.from_dict(e) for e in data.get("entities") or []],
            edges=[EntityEdge.from_dict(e) for e in data.get("edges") or []],
            risk=RiskAssessment.from_dict(data.get("risk") or {}),
            pivot_suggestions=list(data.get("pivot_suggestions") or []),
            watchlist_matches=list(data.get("watchlist_matches") or []),
            notes=str(data.get("notes", "")),
            metadata=dict(data.get("metadata") or {}),
            filtered_false_positives=[Finding.from_dict(f) for f in data.get("filtered_false_positives") or []],
        )
