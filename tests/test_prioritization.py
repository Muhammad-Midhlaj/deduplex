from types import SimpleNamespace

from services.prioritization import rules_prioritize
from services.laya_triage import (
    apply_high_critical_safety_floor,
    build_observation_state,
    call_laya_sdk,
    laya_stub_score,
    map_answers_to_recommendation,
    recommend_triage,
    reset_laya_agent_cache,
    triage_questions,
)
from services.prioritization import TriageRecommendation
from app.config import get_settings


def test_rules_high_severity():
    r = rules_prioritize(
        severity="critical",
        cvss=9.8,
        cve="CVE-2021-44228",
        plugin_output="exploitable",
        description="Log4Shell",
        title="Remote code execution",
    )
    assert r.source == "rules"
    assert r.score >= 0.85
    assert r.proposed_classification == "urgent_review"
    assert not r.abstained


def test_rules_abstain_on_missing_evidence():
    r = rules_prioritize(
        severity=None,
        cvss=None,
        cve=None,
        plugin_output=None,
        description=None,
    )
    assert r.abstained
    assert r.source == "abstain"


def test_laya_disabled_uses_rules(monkeypatch):
    settings = get_settings()
    monkeypatch.setattr(settings, "laya_enabled", False)
    r = recommend_triage(
        severity="high",
        cvss=7.5,
        cve=None,
        plugin_output="output present",
        description="desc",
        title="x",
    )
    assert r.source == "rules"


def test_laya_stub_behind_flag():
    rec = laya_stub_score(
        {
            "severity": "high",
            "plugin_output": "something",
            "description": "desc",
            "cve": "CVE-1",
        }
    )
    assert rec is not None
    assert rec.source == "laya"
    assert not rec.abstained


def test_triage_question_schema():
    qs = triage_questions()
    assert set(qs) == {"review_route", "evidence_completeness", "detection_basis"}
    for q in qs.values():
        assert q["type"] == "choice"
        assert "instructions" in q
        assert isinstance(q["criteria"], dict)
        assert q["criteria"]
    assert set(qs["review_route"]["criteria"]) == {
        "urgent_review",
        "standard_review",
        "insufficient_evidence",
    }
    assert set(qs["evidence_completeness"]["criteria"]) == {
        "complete",
        "partial",
        "insufficient",
    }
    assert set(qs["detection_basis"]["criteria"]) == {
        "observed_behavior",
        "configuration",
        "version_only",
        "unknown",
    }


def test_build_state_excludes_analyst_fields_and_truncates():
    long_out = "x" * 5000
    state = build_observation_state(
        severity="medium",
        cvss=5.0,
        cve=None,
        plugin_output=long_out,
        description="short desc",
        title="t",
        rule_id="r1",
        hostname="h",
    )
    assert "analyst" not in str(state).lower()
    assert "report" not in state
    assert "[truncated]" in state["evidence_summary"]["plugin_output"]
    assert state["asset"]["hostname"] == "h"


def test_map_answers_abstain_insufficient():
    answers = {
        "review_route": {
            "choice": "insufficient_evidence",
            "confidence": 0.9,
            "probabilities": {"insufficient_evidence": 0.9},
        },
        "evidence_completeness": {
            "choice": "insufficient",
            "confidence": 0.8,
            "probabilities": {},
        },
        "detection_basis": {
            "choice": "unknown",
            "confidence": 0.5,
            "probabilities": {},
        },
    }
    rec = map_answers_to_recommendation(answers, model_version="laya-typed-decisions")
    assert rec.abstained
    assert rec.metadata["evidence_completeness"] == "insufficient"


def test_map_answers_standard_route():
    answers = {
        "review_route": {
            "choice": "standard_review",
            "confidence": 0.77,
            "probabilities": {"standard_review": 0.77},
        },
        "evidence_completeness": {
            "choice": "partial",
            "confidence": 0.6,
            "probabilities": {},
        },
        "detection_basis": {
            "choice": "version_only",
            "confidence": 0.55,
            "probabilities": {},
        },
    }
    rec = map_answers_to_recommendation(answers, model_version="laya-typed-decisions")
    assert not rec.abstained
    assert rec.source == "laya"
    assert rec.proposed_classification == "standard_review"
    assert rec.score == 0.77
    assert rec.metadata["detection_basis"] == "version_only"


def test_high_critical_safety_floor():
    laya_rec = TriageRecommendation(
        score=0.4,
        proposed_classification="low_priority_review",
        source="laya",
        model_version="laya-typed-decisions",
        reason="model said low",
    )
    rules_rec = TriageRecommendation(
        score=0.9,
        proposed_classification="urgent_review",
        source="rules",
        model_version="rules-v1",
        reason="rules",
    )
    floored = apply_high_critical_safety_floor(laya_rec, rules_rec, "critical")
    assert floored.proposed_classification == "urgent_review"
    assert floored.score >= 0.9
    assert floored.metadata.get("safety_floor_applied") is True

    # Medium severity: no floor
    no_floor = apply_high_critical_safety_floor(laya_rec, rules_rec, "medium")
    assert no_floor.proposed_classification == "low_priority_review"


def test_sdk_path_mocked(monkeypatch):
    settings = get_settings()
    monkeypatch.setattr(settings, "laya_enabled", True)
    monkeypatch.setattr(settings, "laya_use_stub", False)
    monkeypatch.setattr(settings, "laya_preload", False)
    # Force remote miss
    monkeypatch.setattr(
        "services.laya_triage.call_laya_service", lambda payload: None
    )

    class FakeAgent:
        def predict(self, state, questions):
            assert "review_route" in questions
            assert questions["review_route"]["type"] == "choice"
            assert "asset" in state or "title" in state
            return {
                "answers": {
                    "review_route": {
                        "choice": "urgent_review",
                        "confidence": 0.91,
                        "probabilities": {"urgent_review": 0.91},
                    },
                    "evidence_completeness": {
                        "choice": "complete",
                        "confidence": 0.8,
                        "probabilities": {"complete": 0.8},
                    },
                    "detection_basis": {
                        "choice": "observed_behavior",
                        "confidence": 0.7,
                        "probabilities": {"observed_behavior": 0.7},
                    },
                }
            }

    reset_laya_agent_cache()
    monkeypatch.setattr(
        "services.laya_triage.get_laya_agent", lambda force_reload=False: FakeAgent()
    )

    r = recommend_triage(
        severity="high",
        cvss=8.0,
        cve="CVE-1",
        plugin_output="behavior observed in logs",
        description="RCE proof",
        title="Remote code execution",
        rule_id="x",
        hostname="host1",
    )
    assert r.source == "laya"
    assert r.proposed_classification == "urgent_review"
    assert r.metadata["detection_basis"] == "observed_behavior"


def test_sdk_abstain_falls_back_to_rules(monkeypatch):
    settings = get_settings()
    monkeypatch.setattr(settings, "laya_enabled", True)
    monkeypatch.setattr(settings, "laya_use_stub", False)
    monkeypatch.setattr(
        "services.laya_triage.call_laya_service", lambda payload: None
    )

    class AbstainAgent:
        def predict(self, state, questions):
            return {
                "answers": {
                    "review_route": {
                        "choice": "insufficient_evidence",
                        "confidence": 0.95,
                        "probabilities": {},
                    },
                    "evidence_completeness": {
                        "choice": "insufficient",
                        "confidence": 0.9,
                        "probabilities": {},
                    },
                    "detection_basis": {
                        "choice": "unknown",
                        "confidence": 0.5,
                        "probabilities": {},
                    },
                }
            }

    monkeypatch.setattr(
        "services.laya_triage.get_laya_agent", lambda force_reload=False: AbstainAgent()
    )
    r = recommend_triage(
        severity="medium",
        cvss=5.0,
        cve=None,
        plugin_output="some output",
        description="desc",
        title="t",
    )
    assert r.source == "rules"


def test_sdk_failure_falls_back_to_rules(monkeypatch):
    settings = get_settings()
    monkeypatch.setattr(settings, "laya_enabled", True)
    monkeypatch.setattr(settings, "laya_use_stub", False)
    monkeypatch.setattr(
        "services.laya_triage.call_laya_service", lambda payload: None
    )
    monkeypatch.setattr(
        "services.laya_triage.get_laya_agent", lambda force_reload=False: None
    )
    r = recommend_triage(
        severity="low",
        cvss=2.0,
        cve=None,
        plugin_output="banner",
        description="info",
        title="t",
    )
    assert r.source == "rules"


def test_call_laya_sdk_missing_evidence_abstains(monkeypatch):
    monkeypatch.setattr(
        "services.laya_triage.get_laya_agent",
        lambda force_reload=False: SimpleNamespace(predict=lambda *a, **k: {}),
    )
    rec = call_laya_sdk(
        severity="high",
        cvss=9.0,
        cve=None,
        plugin_output=None,
        description=None,
    )
    assert rec is not None
    assert rec.abstained


def test_safety_floor_via_recommend(monkeypatch):
    settings = get_settings()
    monkeypatch.setattr(settings, "laya_enabled", True)
    monkeypatch.setattr(settings, "laya_use_stub", False)
    monkeypatch.setattr(
        "services.laya_triage.call_laya_service", lambda payload: None
    )

    class SoftAgent:
        def predict(self, state, questions):
            return {
                "answers": {
                    "review_route": {
                        "choice": "standard_review",
                        "confidence": 0.4,
                        "probabilities": {"standard_review": 0.4},
                    },
                    "evidence_completeness": {
                        "choice": "complete",
                        "confidence": 0.8,
                        "probabilities": {},
                    },
                    "detection_basis": {
                        "choice": "version_only",
                        "confidence": 0.6,
                        "probabilities": {},
                    },
                }
            }

    monkeypatch.setattr(
        "services.laya_triage.get_laya_agent", lambda force_reload=False: SoftAgent()
    )
    r = recommend_triage(
        severity="critical",
        cvss=9.8,
        cve="CVE-2021-44228",
        plugin_output="exploitable evidence here",
        description="Log4Shell",
        title="Remote code execution",
    )
    assert r.source == "laya"
    assert r.proposed_classification == "urgent_review"
    assert r.metadata.get("safety_floor_applied") is True
