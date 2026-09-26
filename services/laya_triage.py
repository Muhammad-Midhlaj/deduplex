"""Feature-flagged Laya triage via local SDK (typed-decisions) or optional remote.

When LAYA_ENABLED is false (default), callers use rules_prioritize only.
When true: try remote service URL, then local ``laya`` SDK, then optional stub
(``LAYA_USE_STUB=true``). On abstain/failure always fall back to rules.

Laya recommends review urgency only — it does not generate report prose or
validate vulnerabilities. Analyst severity/CVSS remain authoritative separately.
"""

from __future__ import annotations

import logging
import os
import threading
from typing import Any

import httpx

from app.config import get_settings
from services.prioritization import TriageRecommendation, rules_prioritize

logger = logging.getLogger(__name__)

# Avoid TensorFlow probe deadlocks during transformers/laya import.
os.environ.setdefault("USE_TF", "0")

# typed-decisions context is 1024; keep state compact (~chars ≈ tokens * 3–4).
_EVIDENCE_CHAR_BUDGET = 1800

_URGENCY_RANK = {
    "urgent_review": 3,
    "standard_review": 2,
    "low_priority_review": 1,
    "needs_review": 1,
    "insufficient_evidence": 0,
}

_agent_lock = threading.Lock()
_agent: Any | None = None
_agent_load_failed = False


def triage_questions() -> dict[str, dict[str, Any]]:
    """Choice-typed questions shared with fine-tune schema (prefer choice over noul)."""
    from finetune.schema import triage_questions as _tq

    return _tq()


def _truncate(text: str | None, limit: int) -> str:
    if not text:
        return ""
    text = text.strip()
    if len(text) <= limit:
        return text
    return text[: max(0, limit - 12)].rstrip() + " [truncated]"


def build_observation_state(
    *,
    severity: str | None,
    cvss: float | None,
    cve: str | None,
    plugin_output: str | None,
    description: str | None,
    title: str | None = None,
    rule_id: str | None = None,
    hostname: str | None = None,
    ip_address: str | None = None,
    port: int | None = None,
    protocol: str | None = None,
    service: str | None = None,
) -> dict[str, Any]:
    """Compact state for Laya. Never includes analyst conclusions or report prose."""
    # Split evidence budget across plugin_output and description.
    half = _EVIDENCE_CHAR_BUDGET // 2
    state: dict[str, Any] = {
        "rule_id": rule_id or "",
        "title": _truncate(title, 200),
        "severity": (severity or "").lower(),
        "cvss": cvss,
        "cve": cve or "",
        "evidence_summary": {
            "plugin_output": _truncate(plugin_output, half),
            "description": _truncate(description, half),
        },
    }
    asset = {
        k: v
        for k, v in {
            "hostname": hostname,
            "ip_address": ip_address,
            "port": port,
            "protocol": protocol,
            "service": service,
        }.items()
        if v is not None and v != ""
    }
    if asset:
        state["asset"] = asset
    return state


def evidence_looks_unusable(plugin_output: str | None, description: str | None) -> bool:
    text = f"{plugin_output or ''}{description or ''}".strip()
    if not text:
        return True
    if "[truncated]" in text.lower() and len(text) < 40:
        return True
    return False


def _resolve_device(settings_device: str) -> str | None:
    d = (settings_device or "auto").strip().lower()
    if d in ("", "auto"):
        return None
    return d


def get_laya_agent(*, force_reload: bool = False) -> Any | None:
    """Lazy-load a singleton Agent. Returns None if SDK/weights unavailable."""
    global _agent, _agent_load_failed
    if force_reload:
        with _agent_lock:
            _agent = None
            _agent_load_failed = False
    if _agent is not None:
        return _agent
    if _agent_load_failed and not force_reload:
        return None

    settings = get_settings()
    with _agent_lock:
        if _agent is not None:
            return _agent
        if _agent_load_failed and not force_reload:
            return None
        try:
            import laya  # type: ignore[import-not-found]

            device = _resolve_device(settings.laya_device)
            local_ckpt = (settings.laya_local_checkpoint or "").strip()
            if local_ckpt:
                logger.info(
                    "Loading Laya agent from local checkpoint=%s device=%s",
                    local_ckpt,
                    device or "auto",
                )
                _agent = laya.Agent(local_ckpt, device=device)
                return _agent

            subfolder = settings.laya_subfolder or None
            logger.info(
                "Loading Laya agent repo=%s subfolder=%s device=%s",
                settings.laya_repo,
                subfolder,
                device or "auto",
            )
            _agent = laya.load(
                settings.laya_repo,
                device=device,
                subfolder=subfolder,
            )
            return _agent
        except Exception as exc:  # noqa: BLE001 — soft failure → rules
            _agent_load_failed = True
            logger.warning("Laya SDK load failed (%s); will fall back to rules", exc)
            return None


def reset_laya_agent_cache() -> None:
    """Test helper: clear singleton agent and failure latch without loading."""
    global _agent, _agent_load_failed
    with _agent_lock:
        _agent = None
        _agent_load_failed = False


def laya_stub_score(payload: dict[str, Any]) -> TriageRecommendation | None:
    """Deterministic stub — last resort when LAYA_USE_STUB=true only."""
    settings = get_settings()
    plugin_output = payload.get("plugin_output") or ""
    description = payload.get("description") or ""
    if evidence_looks_unusable(plugin_output, description):
        return TriageRecommendation(
            score=0.0,
            proposed_classification="needs_review",
            source="abstain",
            model_version=settings.laya_model_version,
            reason="Laya stub abstain: missing evidence",
            abstained=True,
        )

    severity = (payload.get("severity") or "info").lower()
    base = {"critical": 0.95, "high": 0.8, "medium": 0.55, "low": 0.3, "info": 0.15}.get(
        severity, 0.2
    )
    if payload.get("cve"):
        base = min(base + 0.05, 1.0)

    if base >= 0.85:
        classification = "urgent_review"
    elif base >= 0.5:
        classification = "standard_review"
    else:
        classification = "low_priority_review"

    return TriageRecommendation(
        score=round(base, 4),
        proposed_classification=classification,
        source="laya",
        model_version=settings.laya_model_version,
        reason="Laya stub recommendation (LAYA_USE_STUB=true; no real model)",
        metadata={"stub": True},
    )


def call_laya_service(payload: dict[str, Any]) -> TriageRecommendation | None:
    """Try remote Laya service; return None on any failure so SDK/rules can take over."""
    settings = get_settings()
    url = (settings.laya_service_url or "").strip()
    if not url:
        return None
    try:
        with httpx.Client(timeout=2.0) as client:
            resp = client.post(f"{url.rstrip('/')}/triage", json=payload)
            if resp.status_code != 200:
                logger.warning("Laya service returned %s", resp.status_code)
                return None
            data = resp.json()
            return TriageRecommendation(
                score=float(data.get("score", 0)),
                proposed_classification=data.get("proposed_classification", "needs_review"),
                source="laya",
                model_version=data.get("model_version", settings.laya_model_version),
                reason=data.get("reason", "Laya remote service"),
                abstained=bool(data.get("abstained", False)),
                metadata=dict(data.get("metadata") or {}),
            )
    except Exception as exc:  # noqa: BLE001 — intentional soft failure
        logger.info("Laya service unavailable (%s); trying local SDK/rules", exc)
        return None


def map_answers_to_recommendation(
    answers: dict[str, Any],
    *,
    model_version: str,
) -> TriageRecommendation:
    """Map SDK answer dict → TriageRecommendation (may abstain)."""
    route = answers.get("review_route") or {}
    completeness = answers.get("evidence_completeness") or {}
    basis = answers.get("detection_basis") or {}

    route_choice = route.get("choice") or "insufficient_evidence"
    completeness_choice = completeness.get("choice") or "insufficient"
    basis_choice = basis.get("choice") or "unknown"
    confidence = float(route.get("confidence") or 0.0)

    meta = {
        "evidence_completeness": completeness_choice,
        "detection_basis": basis_choice,
        "review_route": route_choice,
        "probabilities": {
            "review_route": route.get("probabilities"),
            "evidence_completeness": completeness.get("probabilities"),
            "detection_basis": basis.get("probabilities"),
        },
        "confidences": {
            "review_route": route.get("confidence"),
            "evidence_completeness": completeness.get("confidence"),
            "detection_basis": basis.get("confidence"),
        },
    }

    abstain = (
        route_choice == "insufficient_evidence"
        or completeness_choice == "insufficient"
    )
    if abstain:
        return TriageRecommendation(
            score=0.0,
            proposed_classification="needs_review",
            source="abstain",
            model_version=model_version,
            reason=(
                f"Laya abstain: review_route={route_choice}, "
                f"evidence_completeness={completeness_choice}"
            ),
            abstained=True,
            metadata=meta,
        )

    classification = route_choice
    if classification not in _URGENCY_RANK:
        classification = "needs_review"

    reason = (
        f"Laya typed-decisions: route={route_choice} "
        f"(conf={confidence:.3f}), evidence={completeness_choice}, "
        f"basis={basis_choice}"
    )
    return TriageRecommendation(
        score=round(max(0.0, min(confidence, 1.0)), 4),
        proposed_classification=classification,
        source="laya",
        model_version=model_version,
        reason=reason,
        metadata=meta,
    )


def apply_high_critical_safety_floor(
    laya_rec: TriageRecommendation,
    rules_rec: TriageRecommendation,
    severity: str | None,
) -> TriageRecommendation:
    """Never let Laya hide High/Critical below the rules urgency baseline."""
    sev = (severity or "").lower()
    if sev not in ("high", "critical"):
        return laya_rec
    if laya_rec.abstained:
        return laya_rec

    laya_rank = _URGENCY_RANK.get(laya_rec.proposed_classification, 0)
    rules_rank = _URGENCY_RANK.get(rules_rec.proposed_classification, 0)
    if laya_rank >= rules_rank:
        return laya_rec

    meta = dict(laya_rec.metadata or {})
    meta["safety_floor_applied"] = True
    meta["laya_classification_before_floor"] = laya_rec.proposed_classification
    return TriageRecommendation(
        score=max(laya_rec.score, rules_rec.score),
        proposed_classification=rules_rec.proposed_classification,
        source="laya",
        model_version=laya_rec.model_version,
        reason=(
            f"{laya_rec.reason}; safety floor: high/critical kept at rules "
            f"urgency ({rules_rec.proposed_classification})"
        ),
        metadata=meta,
    )


def call_laya_sdk(
    *,
    severity: str | None,
    cvss: float | None,
    cve: str | None,
    plugin_output: str | None,
    description: str | None,
    title: str | None = None,
    rule_id: str | None = None,
    hostname: str | None = None,
    ip_address: str | None = None,
    port: int | None = None,
    protocol: str | None = None,
    service: str | None = None,
    agent: Any | None = None,
) -> TriageRecommendation | None:
    """Run local SDK predict; return None on hard failure."""
    settings = get_settings()
    if evidence_looks_unusable(plugin_output, description):
        return TriageRecommendation(
            score=0.0,
            proposed_classification="needs_review",
            source="abstain",
            model_version=settings.laya_model_version,
            reason="Laya abstain: missing or truncated evidence",
            abstained=True,
            metadata={"evidence_completeness": "insufficient", "detection_basis": "unknown"},
        )

    agent = agent if agent is not None else get_laya_agent()
    if agent is None:
        return None

    state = build_observation_state(
        severity=severity,
        cvss=cvss,
        cve=cve,
        plugin_output=plugin_output,
        description=description,
        title=title,
        rule_id=rule_id,
        hostname=hostname,
        ip_address=ip_address,
        port=port,
        protocol=protocol,
        service=service,
    )
    questions = triage_questions()
    try:
        result = agent.predict(state, questions)
        answers = result.get("answers") if isinstance(result, dict) else None
        if not answers:
            logger.warning("Laya predict returned no answers")
            return None
        return map_answers_to_recommendation(
            answers, model_version=settings.laya_model_version
        )
    except Exception as exc:  # noqa: BLE001
        logger.warning("Laya predict failed (%s)", exc)
        return None


def recommend_triage(
    *,
    severity: str | None,
    cvss: float | None,
    cve: str | None,
    plugin_output: str | None,
    description: str | None,
    title: str | None = None,
    rule_id: str | None = None,
    hostname: str | None = None,
    ip_address: str | None = None,
    port: int | None = None,
    protocol: str | None = None,
    service: str | None = None,
) -> TriageRecommendation:
    """Public entry point used by the import pipeline."""
    settings = get_settings()
    rules_result = rules_prioritize(
        severity=severity,
        cvss=cvss,
        cve=cve,
        plugin_output=plugin_output,
        description=description,
        title=title,
    )

    if not settings.laya_enabled:
        return rules_result

    # Optional preload on first enabled call (still not at import time).
    if settings.laya_preload:
        get_laya_agent()

    payload = {
        "severity": severity,
        "cvss": cvss,
        "cve": cve,
        "plugin_output": plugin_output,
        "description": description,
        "title": title,
        "rule_id": rule_id,
        "hostname": hostname,
        "ip_address": ip_address,
        "port": port,
        "protocol": protocol,
        "service": service,
    }

    remote = call_laya_service(payload)
    if remote is not None and not remote.abstained:
        return apply_high_critical_safety_floor(remote, rules_result, severity)

    sdk = call_laya_sdk(
        severity=severity,
        cvss=cvss,
        cve=cve,
        plugin_output=plugin_output,
        description=description,
        title=title,
        rule_id=rule_id,
        hostname=hostname,
        ip_address=ip_address,
        port=port,
        protocol=protocol,
        service=service,
    )
    if sdk is not None and not sdk.abstained:
        return apply_high_critical_safety_floor(sdk, rules_result, severity)

    if settings.laya_use_stub:
        stub = laya_stub_score(payload)
        if stub is not None and not stub.abstained:
            return apply_high_critical_safety_floor(stub, rules_result, severity)

    # Always fall back to rules; never suppress.
    return rules_result
