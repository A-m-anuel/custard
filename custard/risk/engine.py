"""Risk determination per NIST SP 800-30 (2002), section 3.7 and Table 3-6.

    Likelihood values: High 1.0, Medium 0.5, Low 0.1
    Impact values:     High 100, Medium 50, Low 10
    Risk = Likelihood x Impact
    Risk scale:        High (>50 to 100); Medium (>10 to 50); Low (1 to 10)

Using integer arithmetic (likelihood x 10) keeps every product exact:
    risk = likelihood_tenths x impact / 10
"""

from __future__ import annotations

from custard.core.choices import Level

LIKELIHOOD_TENTHS = {Level.HIGH: 10, Level.MEDIUM: 5, Level.LOW: 1}
IMPACT_VALUE = {Level.HIGH: 100, Level.MEDIUM: 50, Level.LOW: 10}

# NIST SP 800-30 Table 3-7: risk level and necessary actions
ACTIONS = {
    Level.HIGH: "Strong need for corrective measures; put a corrective action plan in place as soon as possible.",
    Level.MEDIUM: "Corrective actions are needed; plan them within a reasonable period of time.",
    Level.LOW: "Decide whether corrective actions are still required or accept the risk.",
}


def risk_score(likelihood: str, impact: str) -> int:
    """Return the NIST risk score (1-100). All nine matrix cells are whole numbers."""
    product = LIKELIHOOD_TENTHS[Level(likelihood)] * IMPACT_VALUE[Level(impact)]
    assert product % 10 == 0
    return product // 10


def risk_level(score: int) -> str:
    if score > 50:
        return Level.HIGH
    if score > 10:
        return Level.MEDIUM
    return Level.LOW


def assess(likelihood: str, impact: str) -> tuple[int, str]:
    score = risk_score(likelihood, impact)
    return score, risk_level(score)
