"""CIA security scoring, as specified in the dissertation (section 3.4.4, Figures 31-32).

Each checklist item belongs to one CIA pillar. A pillar scores
    (implemented items in pillar / items in pillar) x 10,
and the asset's security score normalises the sum of the three pillar scores to 0-10:
    score = (C + I + A) / 30 x 10.

Generalisation: a custom category may leave a pillar without checklist items. That pillar is then
"not applicable" and the score is the mean of the applicable pillars, which equals the formula
above whenever all three pillars have items.

Exact fractions are used internally and rounded half-up to two decimals only at the end.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from decimal import ROUND_HALF_UP, Decimal
from fractions import Fraction

from custard.core.choices import Pillar

TWO_PLACES = Decimal("0.01")


@dataclass(frozen=True)
class ScoreResult:
    confidentiality: Decimal | None
    integrity: Decimal | None
    availability: Decimal | None
    overall: Decimal


class NoChecklistError(ValueError):
    """Raised when there is nothing to score against."""


def _to_decimal(value: Fraction) -> Decimal:
    return (Decimal(value.numerator) / Decimal(value.denominator)).quantize(TWO_PLACES, rounding=ROUND_HALF_UP)


def calculate(responses: Iterable[tuple[str, bool]]) -> ScoreResult:
    """responses: iterable of (pillar, implemented)."""
    totals = {p: [0, 0] for p in Pillar.values}  # pillar -> [implemented, total]
    for pillar, implemented in responses:
        if pillar not in totals:
            raise ValueError(f"unknown pillar {pillar!r}")
        totals[pillar][1] += 1
        totals[pillar][0] += 1 if implemented else 0

    exact: dict[str, Fraction | None] = {}
    for pillar, (done, total) in totals.items():
        exact[pillar] = Fraction(done, total) * 10 if total else None

    applicable = [v for v in exact.values() if v is not None]
    if not applicable:
        raise NoChecklistError("the asset category has no active checklist items")
    overall = sum(applicable, Fraction(0)) / len(applicable)

    def rounded(p):
        return None if exact[p] is None else _to_decimal(exact[p])

    return ScoreResult(
        confidentiality=rounded(Pillar.CONFIDENTIALITY),
        integrity=rounded(Pillar.INTEGRITY),
        availability=rounded(Pillar.AVAILABILITY),
        overall=_to_decimal(overall),
    )
