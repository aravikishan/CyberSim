"""Service layer tests for CyberSim."""

import pytest

from services.cvss import (
    calculate_base_score,
    parse_vector_string,
    score_from_vector,
    severity_rating,
)
from services.simulator import (
    calculate_risk_score,
    get_kill_chain,
    get_techniques_for_stage,
    simulate_attack,
)


class TestCVSSCalculator:
    def test_max_score(self):
        result = calculate_base_score(
            av="N", ac="L", pr="N", ui="N", s="C", c="H", i="H", a="H"
        )
        assert result["score"] == 10.0
        assert result["severity"] == "CRITICAL"

    def test_minimum_nonzero(self):
        result = calculate_base_score(
            av="P", ac="H", pr="H", ui="R", s="U", c="N", i="N", a="L"
        )
        assert result["score"] > 0.0
        assert result["severity"] in ("LOW", "MEDIUM")

    def test_zero_impact(self):
        result = calculate_base_score(
            av="N", ac="L", pr="N", ui="N", s="U", c="N", i="N", a="N"
        )
        assert result["score"] == 0.0
        assert result["severity"] == "NONE"

    def test_known_vector_score(self):
        # CVE-2021-44228 (Log4Shell) -> 10.0
        result = calculate_base_score(
            av="N", ac="L", pr="N", ui="N", s="C", c="H", i="H", a="H"
        )
        assert result["score"] == 10.0

    def test_invalid_metric_raises(self):
        with pytest.raises(ValueError):
            calculate_base_score(av="X")

    def test_parse_vector_string(self):
        metrics = parse_vector_string("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
        assert metrics["AV"] == "N"
        assert metrics["S"] == "U"

    def test_score_from_vector(self):
        result = score_from_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
        assert result["score"] == 9.8

    def test_severity_ratings(self):
        assert severity_rating(0.0) == "NONE"
        assert severity_rating(2.5) == "LOW"
        assert severity_rating(5.0) == "MEDIUM"
        assert severity_rating(7.5) == "HIGH"
        assert severity_rating(9.5) == "CRITICAL"


class TestSimulator:
    def test_kill_chain_stages(self):
        chain = get_kill_chain()
        assert len(chain) == 7
        assert chain[0]["stage"] == "Reconnaissance"
        assert chain[-1]["stage"] == "Actions on Objectives"

    def test_techniques_for_stage(self):
        techniques = get_techniques_for_stage("Delivery")
        assert len(techniques) > 0
        ids = [t["id"] for t in techniques]
        assert "T1566.001" in ids

    def test_techniques_unknown_stage(self):
        assert get_techniques_for_stage("NonExistent") == []

    def test_risk_score_calculation(self):
        score = calculate_risk_score(9.8, "External", "Critical")
        assert 80 <= score <= 100

    def test_risk_score_low(self):
        score = calculate_risk_score(2.0, "Isolated", "Low")
        assert score < 30

    def test_simulate_attack(self):
        result = simulate_attack(
            stages=["Reconnaissance", "Delivery", "Exploitation"],
            techniques=["Active Scanning", "Spearphishing"],
            target_asset_criticality="High",
            attacker_sophistication="Medium",
        )
        assert "overall_success_probability" in result
        assert "timeline" in result
        assert len(result["timeline"]) == 3
        assert "mitigations" in result
