"""Unit tests for Laya fine-tune pipeline (no GPU / no HF download)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from finetune.dataset import (
    assert_split_integrity,
    build_training_item,
    class_coverage,
    engagement_aware_split,
)
from finetune.evaluate import compute_metrics, evaluate, rules_predict_route
from finetune.export_labels import assert_no_leakage, build_gold_labels, redact_state
from finetune.schema import (
    LEAKAGE_KEYS,
    map_decision_to_review_route,
    soft_target,
    triage_questions,
)
from finetune.synthetic import generate_synthetic_cases


def test_label_mapping_confirmed_high():
    assert (
        map_decision_to_review_route(
            decision="confirmed", proposed_classification=None, severity="critical"
        )
        == "urgent_review"
    )


def test_label_mapping_analyst_decision_beats_proposed():
    assert (
        map_decision_to_review_route(
            decision="defer",
            proposed_classification="insufficient_evidence",
            severity="high",
        )
        == "standard_review"
    )


def test_label_mapping_proposed_when_no_decision():
    assert (
        map_decision_to_review_route(
            decision=None,
            proposed_classification="insufficient_evidence",
            severity="high",
        )
        == "insufficient_evidence"
    )


def test_label_mapping_false_positive():
    assert (
        map_decision_to_review_route(
            decision="false_positive", proposed_classification=None, severity="high"
        )
        == "insufficient_evidence"
    )


def test_soft_target_smoothing():
    keys = ["a", "b", "c"]
    t = soft_target(keys, "b", mass=0.85)
    assert abs(sum(t) - 1.0) < 1e-9
    assert t[1] == pytest.approx(0.85)
    assert t[0] == pytest.approx(0.075)


def test_leakage_guard_strips_decision_fields():
    raw = {
        "rule_id": "x",
        "title": "t",
        "severity": "high",
        "cvss": 8.0,
        "cve": "",
        "tool": "nessus",
        "analyst_decision": "confirmed",
        "decision_reason": "validated",
        "proposed_classification": "urgent_review",
        "model_suggestion": "urgent",
        "evidence_summary": {"plugin_output": "ok", "description": "d"},
    }
    cleaned = redact_state(raw)
    assert_no_leakage(cleaned)
    for k in LEAKAGE_KEYS:
        assert k not in cleaned
    assert cleaned["rule_id"] == "x"
    assert "evidence_summary" in cleaned


def test_leakage_guard_raises():
    with pytest.raises(AssertionError):
        assert_no_leakage({"rule_id": "x", "analyst_decision": "confirmed"})


def test_engagement_split_integrity():
    cases = []
    for eng in (1, 2, 3, 4, 5, 6):
        for i in range(5):
            cases.append(
                {
                    "case_id": f"e{eng}-{i}",
                    "engagement_id": eng,
                    "asset_id": eng * 10 + i,
                    "gold": {"review_route": {"label": "standard_review"}},
                    "state": {"rule_id": "r"},
                    "synthetic": True,
                }
            )
    splits = engagement_aware_split(cases, seed=1)
    assert_split_integrity(splits)
    # Each engagement only in one split
    eng_to_split = {}
    for name, rows in splits.items():
        for r in rows:
            eid = r["engagement_id"]
            assert eid not in eng_to_split or eng_to_split[eid] == name
            eng_to_split[eid] = name
    assert len(eng_to_split) == 6


def test_preprocess_item_shape_with_mocked_tokenizer():
    """build_training_item with mocked laya.common helpers — no HF download."""

    class FakeTok:
        pass

    def fake_render_options(q):
        return list(q["crit"].keys())

    def fake_build_sequence(tok, state, q, max_len, head_max_len):
        keys = list(q["crit"].keys())
        # ids length 10; markers at ends of options
        ids = list(range(10))
        markers = list(range(len(keys)))
        return ids, markers

    state = {
        "rule_id": "n:1",
        "title": "t",
        "severity": "high",
        "cvss": 8.0,
        "cve": "CVE-1",
        "tool": "nessus",
        "evidence_summary": {"plugin_output": "behavior observed", "description": "d"},
    }
    gold = build_gold_labels(
        decision="confirmed",
        proposed_classification="urgent_review",
        severity="high",
        plugin_output="behavior observed",
        description="d",
        title="t",
        cve="CVE-1",
        evidence_completeness="complete",
        detection_basis="observed_behavior",
    )
    item = build_training_item(
        state,
        "review_route",
        gold["review_route"],
        tok=FakeTok(),
        cfg={"max_len": 128, "head_max_len": 64},
        build_sequence=fake_build_sequence,
        render_options=fake_render_options,
        qtypes={"choice": 0, "score": 1, "noul": 2},
    )
    assert item is not None
    assert set(item.keys()) >= {"ids", "markers", "qtype", "target", "label"}
    assert len(item["markers"]) == len(item["target"])
    assert item["qtype"] == 0
    assert abs(sum(item["target"]) - 1.0) < 1e-6


def test_evaluate_metrics_on_tiny_fixture(tmp_path: Path):
    cases = generate_synthetic_cases(24, n_engagements=4, seed=7)
    path = tmp_path / "eval.jsonl"
    with path.open("w", encoding="utf-8") as f:
        for c in cases:
            f.write(json.dumps(c) + "\n")

    # Deterministic fake predictor: always predict gold (perfect) for unit test of metrics math
    def perfect(case):
        gold = case["gold"]["review_route"]["label"]
        return {"review_route": gold, "abstained": gold == "insufficient_evidence", "source": "fake"}

    metrics = evaluate(path, predict_fn=perfect, out_dir=tmp_path / "out")
    assert metrics["n_scored"] == 24
    assert metrics["review_route_accuracy"] == pytest.approx(1.0)
    assert (tmp_path / "out" / "metrics.json").is_file()
    assert (tmp_path / "out" / "metrics.md").is_file()

    # Rules-only path also works
    rules_m = evaluate(path, use_rules_only=True, out_dir=tmp_path / "out_rules")
    assert rules_m["n_scored"] == 24
    assert rules_m["review_route_accuracy"] is not None
    assert 0.0 <= rules_m["review_route_accuracy"] <= 1.0


def test_compute_metrics_never_fabricates_empty():
    m = compute_metrics([], [])
    assert m["n_scored"] == 0
    assert m["review_route_accuracy"] is None


def test_synthetic_marked_and_coverage():
    cases = generate_synthetic_cases(90, n_engagements=5)
    assert len(cases) == 90
    assert all(c["synthetic"] is True for c in cases)
    cov = class_coverage(cases, "review_route")
    assert sum(cov.values()) == 90
    assert set(cov.keys()) <= set(triage_questions()["review_route"]["criteria"].keys())


def test_rules_predict_route_smoke():
    case = generate_synthetic_cases(1)[0]
    pred = rules_predict_route(case)
    assert "review_route" in pred


def test_triage_questions_shared_with_inference():
    from services.laya_triage import triage_questions as tq_inf

    a = triage_questions()
    b = tq_inf()
    assert set(a.keys()) == set(b.keys()) == {"review_route", "evidence_completeness", "detection_basis"}
