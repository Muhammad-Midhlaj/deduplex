"""Rules-based prioritization fallback (always available).

Produces a triage score in [0, 1] and a proposed classification.
Does not suppress or auto-decide; analysts always validate.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


from app.config import get_settings


SEVERITY_WEIGHT = {
    "critical": 1.0,
    "high": 0.8,
    "medium": 0.5,
    "low": 0.25,
    "info": 0.1,
    "informational": 0.1,
}


@dataclass
class TriageRecommendation:
    score: float
    proposed_classification: str
    source: str  # rules | laya | abstain
    model_version: str
    reason: str
    abstained: bool = False
    # Internal extras (evidence_completeness, detection_basis, probabilities, etc.).
    # Not persisted to DB columns in MVP; used by callers/logging.
    metadata: dict[str, Any] = field(default_factory=dict)


def _has_usable_evidence(plugin_output: str | None, description: str | None) -> bool:
    text = (plugin_output or "") + (description or "")
    if not text.strip():
        return False
    # Treat heavily truncated markers as missing evidence.
    if "[truncated]" in text.lower() and len(text) < 40:
        return False
    return True


def rules_prioritize(
    *,
    severity: str | None,
    cvss: float | None,
    cve: str | None,
    plugin_output: str | None,
    description: str | None,
    title: str | None = None,
) -> TriageRecommendation:
    settings = get_settings()

    if not _has_usable_evidence(plugin_output, description) and not severity:
        return TriageRecommendation(
            score=0.0,
            proposed_classification="needs_review",
            source="abstain",
            model_version=settings.rules_model_version,
            reason="Missing or truncated evidence; abstaining",
            abstained=True,
        )

    sev = (severity or "info").lower()
    score = SEVERITY_WEIGHT.get(sev, 0.1)

    if cvss is not None:
        # Blend CVSS/10 with severity weight.
        score = max(score, min(cvss / 10.0, 1.0))

    if cve:
        score = min(score + 0.1, 1.0)

    title_l = (title or "").lower()
    if any(k in title_l for k in ("rce", "remote code", "authentication bypass", "sql injection")):
        score = min(score + 0.15, 1.0)

    if score >= 0.85:
        classification = "urgent_review"
    elif score >= 0.5:
        classification = "standard_review"
    else:
        classification = "low_priority_review"

    return TriageRecommendation(
        score=round(score, 4),
        proposed_classification=classification,
        source="rules",
        model_version=settings.rules_model_version,
        reason=f"Rules baseline from severity={sev}, cvss={cvss}, cve={'yes' if cve else 'no'}",
    )
