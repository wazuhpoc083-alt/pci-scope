"""
Tests for answer-driven gap analysis re-run (MOU-20).

Run with:  pytest tests/test_gap_engine_answers.py -v
"""

from __future__ import annotations

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app.gap_engine import (
    extract_answer_driven_cde_seeds,
    refine_findings_with_answers,
    run_gap_analysis,
)


# ---------------------------------------------------------------------------
# Fixtures / helpers...
# ---------------------------------------------------------------------------

def _make_question(qid: str, category: str, context: dict | None = None, rule_id: str | None = None) -> dict:
    return {
        "id": qid,
        "category": category,
        "text": "some question text",
        "rule_id": rule_id,
        "context": context or {},
    }


def _deny_all_finding() -> dict:
    return {
        "id": "GAP-DENY-ALL",
        "severity": "high",
        "requirement": "PCI DSS v4.0 Req 1.3.2",
        "title": "No explicit deny-all rule found",
        "description": "Deny-all missing.",
        "affected_rules": [],
        "remediation": "Add deny-all.",
    }


def _broad_inbound_finding(affected_rules: list[str] | None = None) -> dict:
    return {
        "id": "GAP-BROAD-INBOUND",
        "severity": "high",
        "requirement": "PCI DSS v4.0 Req 1.3.5",
        "title": "Overly broad permit rules",
        "description": "Rules allow any-any traffic.",
        "affected_rules": affected_rules or ["rule1"],
        "remediation": "Restrict rules.",
    }


# ---------------------------------------------------------------------------
# extract_answer_driven_cde_seeds
# ---------------------------------------------------------------------------

class TestExtractAnswerDrivenCdeSeeds:
    def test_positive_cde_id_answer_extracts_dst(self):
        questions = [_make_question("q1", "cde_id", context={"dst": "10.1.2.0/24"})]
        answers = {"q1": "Yes, this subnet processes cardholder data."}
        result = extract_answer_driven_cde_seeds(questions, answers)
        assert "10.1.2.0/24" in result

    def test_negative_answer_does_not_extract(self):
        questions = [_make_question("q1", "cde_id", context={"dst": "10.1.2.0/24"})]
        answers = {"q1": "No, this is just a monitoring server."}
        result = extract_answer_driven_cde_seeds(questions, answers)
        assert result == []

    def test_unanswered_question_returns_empty(self):
        questions = [_make_question("q1", "cde_id", context={"dst": "10.1.2.0/24"})]
        result = extract_answer_driven_cde_seeds(questions, {})
        assert result == []

    def test_non_cde_id_category_not_extracted(self):
        questions = [_make_question("q1", "ambiguity", context={"dst": "10.1.2.0/24"})]
        answers = {"q1": "Yes this is needed."}
        result = extract_answer_driven_cde_seeds(questions, answers)
        assert result == []

    def test_multiple_positive_cde_id_answers(self):
        questions = [
            _make_question("q1", "cde_id", context={"dst": "10.0.1.0/24"}),
            _make_question("q2", "cde_id", context={"dst": "10.0.2.0/24"}),
        ]
        answers = {"q1": "Yes, it does.", "q2": "Yes, confirmed."}
        result = extract_answer_driven_cde_seeds(questions, answers)
        assert "10.0.1.0/24" in result
        assert "10.0.2.0/24" in result

    def test_question_without_dst_context_is_skipped(self):
        questions = [_make_question("q1", "cde_id", context={})]
        answers = {"q1": "Yes."}
        result = extract_answer_driven_cde_seeds(questions, answers)
        assert result == []


# ---------------------------------------------------------------------------
# refine_findings_with_answers
# ---------------------------------------------------------------------------

class TestRefineFindingsWithAnswers:
    def test_upstream_deny_suppresses_gap_deny_all(self):
        findings = [_deny_all_finding()]
        questions = [_make_question("q1", "missing_rule")]
        answers = {"q1": "Yes, we have an upstream ACL that denies all unmatched traffic."}
        result = refine_findings_with_answers(findings, questions, answers)
        ids = [f["id"] for f in result]
        assert "GAP-DENY-ALL" not in ids

    def test_negative_upstream_answer_keeps_gap_deny_all(self):
        findings = [_deny_all_finding()]
        questions = [_make_question("q1", "missing_rule")]
        answers = {"q1": "No, there is no upstream control."}
        result = refine_findings_with_answers(findings, questions, answers)
        ids = [f["id"] for f in result]
        assert "GAP-DENY-ALL" in ids

    def test_unanswered_missing_rule_keeps_gap_deny_all(self):
        findings = [_deny_all_finding()]
        questions = [_make_question("q1", "missing_rule")]
        result = refine_findings_with_answers(findings, questions, {})
        ids = [f["id"] for f in result]
        assert "GAP-DENY-ALL" in ids

    def test_ambiguity_answer_annotates_matching_finding(self):
        finding = _broad_inbound_finding(affected_rules=["rule1"])
        questions = [_make_question("q1", "ambiguity", rule_id="rule1")]
        answers = {"q1": "This rule is a temporary admin override during maintenance."}
        result = refine_findings_with_answers([finding], questions, answers)
        assert len(result) == 1
        assert "User context:" in result[0]["description"]
        assert "temporary admin override" in result[0]["description"]

    def test_ambiguity_answer_does_not_suppress_finding(self):
        """Annotated findings should still appear — only deny-all is suppressed."""
        finding = _broad_inbound_finding(affected_rules=["rule1"])
        questions = [_make_question("q1", "ambiguity", rule_id="rule1")]
        answers = {"q1": "It is intentional."}
        result = refine_findings_with_answers([finding], questions, answers)
        assert len(result) == 1
        assert result[0]["id"] == "GAP-BROAD-INBOUND"

    def test_finding_with_no_matching_answer_is_unchanged(self):
        finding = _broad_inbound_finding(affected_rules=["rule99"])
        questions = [_make_question("q1", "ambiguity", rule_id="rule1")]
        answers = {"q1": "It is intentional."}
        result = refine_findings_with_answers([finding], questions, answers)
        assert result[0]["description"] == finding["description"]

    def test_no_answers_leaves_all_findings_unchanged(self):
        findings = [_deny_all_finding(), _broad_inbound_finding()]
        result = refine_findings_with_answers(findings, [], {})
        assert len(result) == 2


# ---------------------------------------------------------------------------
# run_gap_analysis — integrated answer flow
# ---------------------------------------------------------------------------

class TestRunGapAnalysisWithAnswers:
    """Integration-level tests using run_gap_analysis directly."""

    _RULES_NO_DENY_ALL = [
        {
            "policy_id": "1",
            "src_addrs": ["any"],
            "dst_addrs": ["10.0.0.1"],
            "services": ["ALL"],
            "action": "permit",
            "src_intf": None,
            "dst_intf": None,
            "comment": None,
        }
    ]

    def test_without_answers_deny_all_gap_is_present(self):
        result = run_gap_analysis(self._RULES_NO_DENY_ALL, ["10.0.0.1"], [])
        ids = [f["id"] for f in result["gap_findings"]]
        assert "GAP-DENY-ALL" in ids

    def test_upstream_deny_answer_removes_deny_all_gap(self):
        # First pass to get questions
        first = run_gap_analysis(self._RULES_NO_DENY_ALL, ["10.0.0.1"], [])
        questions = first["questions"]

        # Fabricate a missing_rule question if none generated (minimal config)
        if not any(q["category"] == "missing_rule" for q in questions):
            questions.append({
                "id": "fake-missing-q",
                "category": "missing_rule",
                "text": "Is there an upstream deny-all?",
                "rule_id": None,
                "context": {},
            })

        answers = {q["id"]: "Yes, upstream ACL handles it." for q in questions if q["category"] == "missing_rule"}
        result = run_gap_analysis(
            self._RULES_NO_DENY_ALL,
            ["10.0.0.1"],
            [],
            answers=answers,
            questions=questions,
        )
        ids = [f["id"] for f in result["gap_findings"]]
        assert "GAP-DENY-ALL" not in ids

    def test_confirmed_cde_seed_triggers_inet_to_cde_finding(self):
        """When user confirms a subnet is CDE via answer, passing it as a seed
        causes internet-to-CDE gap to fire."""
        rules = [
            {
                "policy_id": "r1",
                "src_addrs": ["0.0.0.0/0"],
                "dst_addrs": ["10.5.5.0/24"],
                "services": ["tcp/443"],
                "action": "permit",
                "src_intf": None,
                "dst_intf": None,
                "comment": None,
            }
        ]
        # Without CDE seed — no internet-to-CDE finding
        result_no_seed = run_gap_analysis(rules, [], [])
        ids_no_seed = [f["id"] for f in result_no_seed["gap_findings"]]
        assert "GAP-INET-TO-CDE" not in ids_no_seed

        # With CDE seed added via answer extraction — finding appears
        result_with_seed = run_gap_analysis(rules, ["10.5.5.0/24"], [])
        ids_with_seed = [f["id"] for f in result_with_seed["gap_findings"]]
        assert "GAP-INET-TO-CDE" in ids_with_seed
