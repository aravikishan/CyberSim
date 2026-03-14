"""CVSS v3.1 Base Score Calculator.

Implements the full CVSS v3.1 specification for computing base scores
from the eight base metrics: AV, AC, PR, UI, S, C, I, A.

Reference: https://www.first.org/cvss/v3.1/specification-document
"""

from __future__ import annotations

import math
from typing import Any


# ── Metric value mappings ──────────────────────────────────────────────────

ATTACK_VECTOR = {
    "N": 0.85,   # Network
    "A": 0.62,   # Adjacent
    "L": 0.55,   # Local
    "P": 0.20,   # Physical
}

ATTACK_COMPLEXITY = {
    "L": 0.77,   # Low
    "H": 0.44,   # High
}

# Privileges Required values depend on Scope
PRIVILEGES_REQUIRED_UNCHANGED = {
    "N": 0.85,   # None
    "L": 0.62,   # Low
    "H": 0.27,   # High
}

PRIVILEGES_REQUIRED_CHANGED = {
    "N": 0.85,   # None
    "L": 0.68,   # Low
    "H": 0.50,   # High
}

USER_INTERACTION = {
    "N": 0.85,   # None
    "R": 0.62,   # Required
}

SCOPE = {
    "U": "Unchanged",
    "C": "Changed",
}

CIA_IMPACT = {
    "H": 0.56,   # High
    "L": 0.22,   # Low
    "N": 0.00,   # None
}

# Human-readable names
METRIC_LABELS = {
    "AV": {
        "N": "Network",
        "A": "Adjacent",
        "L": "Local",
        "P": "Physical",
    },
    "AC": {
        "L": "Low",
        "H": "High",
    },
    "PR": {
        "N": "None",
        "L": "Low",
        "H": "High",
    },
    "UI": {
        "N": "None",
        "R": "Required",
    },
    "S": {
        "U": "Unchanged",
        "C": "Changed",
    },
    "C": {
        "N": "None",
        "L": "Low",
        "H": "High",
    },
    "I": {
        "N": "None",
        "L": "Low",
        "H": "High",
    },
    "A": {
        "N": "None",
        "L": "Low",
        "H": "High",
    },
}


def _roundup(value: float) -> float:
    """Round up to one decimal place per CVSS v3.1 spec."""
    return math.ceil(value * 10) / 10


def severity_rating(score: float) -> str:
    """Return a severity string for a CVSS score."""
    if score == 0.0:
        return "NONE"
    elif score <= 3.9:
        return "LOW"
    elif score <= 6.9:
        return "MEDIUM"
    elif score <= 8.9:
        return "HIGH"
    else:
        return "CRITICAL"


def calculate_base_score(
    av: str = "N",
    ac: str = "L",
    pr: str = "N",
    ui: str = "N",
    s: str = "U",
    c: str = "H",
    i: str = "H",
    a: str = "H",
) -> dict[str, Any]:
    """Calculate the CVSS v3.1 base score.

    Parameters
    ----------
    av : str  Attack Vector (N, A, L, P)
    ac : str  Attack Complexity (L, H)
    pr : str  Privileges Required (N, L, H)
    ui : str  User Interaction (N, R)
    s  : str  Scope (U, C)
    c  : str  Confidentiality Impact (N, L, H)
    i  : str  Integrity Impact (N, L, H)
    a  : str  Availability Impact (N, L, H)

    Returns
    -------
    dict with score, severity, vector_string, and breakdown
    """
    av = av.upper()
    ac = ac.upper()
    pr = pr.upper()
    ui = ui.upper()
    s = s.upper()
    c = c.upper()
    i = i.upper()
    a = a.upper()

    # Validate inputs
    if av not in ATTACK_VECTOR:
        raise ValueError(f"Invalid Attack Vector: {av}")
    if ac not in ATTACK_COMPLEXITY:
        raise ValueError(f"Invalid Attack Complexity: {ac}")
    if pr not in PRIVILEGES_REQUIRED_UNCHANGED:
        raise ValueError(f"Invalid Privileges Required: {pr}")
    if ui not in USER_INTERACTION:
        raise ValueError(f"Invalid User Interaction: {ui}")
    if s not in SCOPE:
        raise ValueError(f"Invalid Scope: {s}")
    if c not in CIA_IMPACT:
        raise ValueError(f"Invalid Confidentiality Impact: {c}")
    if i not in CIA_IMPACT:
        raise ValueError(f"Invalid Integrity Impact: {i}")
    if a not in CIA_IMPACT:
        raise ValueError(f"Invalid Availability Impact: {a}")

    # Select PR mapping based on Scope
    scope_changed = s == "C"
    pr_values = PRIVILEGES_REQUIRED_CHANGED if scope_changed else PRIVILEGES_REQUIRED_UNCHANGED

    # Exploitability sub-score
    exploitability = 8.22 * ATTACK_VECTOR[av] * ATTACK_COMPLEXITY[ac] * pr_values[pr] * USER_INTERACTION[ui]

    # Impact sub-score
    isc_base = 1 - (1 - CIA_IMPACT[c]) * (1 - CIA_IMPACT[i]) * (1 - CIA_IMPACT[a])

    if scope_changed:
        impact = 7.52 * (isc_base - 0.029) - 3.25 * (isc_base - 0.02) ** 15
    else:
        impact = 6.42 * isc_base

    # Base score
    if impact <= 0:
        score = 0.0
    elif scope_changed:
        score = _roundup(min(1.08 * (impact + exploitability), 10.0))
    else:
        score = _roundup(min(impact + exploitability, 10.0))

    vector_string = f"CVSS:3.1/AV:{av}/AC:{ac}/PR:{pr}/UI:{ui}/S:{s}/C:{c}/I:{i}/A:{a}"

    return {
        "score": score,
        "severity": severity_rating(score),
        "vector_string": vector_string,
        "breakdown": {
            "exploitability": round(exploitability, 2),
            "impact": round(impact, 2),
            "isc_base": round(isc_base, 4),
            "metrics": {
                "Attack Vector": METRIC_LABELS["AV"].get(av, av),
                "Attack Complexity": METRIC_LABELS["AC"].get(ac, ac),
                "Privileges Required": METRIC_LABELS["PR"].get(pr, pr),
                "User Interaction": METRIC_LABELS["UI"].get(ui, ui),
                "Scope": METRIC_LABELS["S"].get(s, s),
                "Confidentiality": METRIC_LABELS["C"].get(c, c),
                "Integrity": METRIC_LABELS["I"].get(i, i),
                "Availability": METRIC_LABELS["A"].get(a, a),
            },
        },
    }


def parse_vector_string(vector: str) -> dict[str, str]:
    """Parse a CVSS v3.1 vector string into metric dict.

    Example: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
    """
    metrics = {}
    parts = vector.replace("CVSS:3.1/", "").split("/")
    for part in parts:
        if ":" in part:
            key, val = part.split(":", 1)
            metrics[key.upper()] = val.upper()
    return metrics


def score_from_vector(vector: str) -> dict[str, Any]:
    """Calculate base score from a CVSS v3.1 vector string."""
    m = parse_vector_string(vector)
    return calculate_base_score(
        av=m.get("AV", "N"),
        ac=m.get("AC", "L"),
        pr=m.get("PR", "N"),
        ui=m.get("UI", "N"),
        s=m.get("S", "U"),
        c=m.get("C", "H"),
        i=m.get("I", "H"),
        a=m.get("A", "H"),
    )
