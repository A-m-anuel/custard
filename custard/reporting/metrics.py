"""Portfolio metrics shared by the dashboard, the PDF report and the API."""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from decimal import ROUND_HALF_UP, Decimal

from django.conf import settings
from django.db.models import Avg, Count
from django.utils import timezone

from custard.core.choices import Level
from custard.inventory.models import Asset
from custard.risk.models import AssetRisk, RiskTreatment


@dataclass
class Portfolio:
    total_assets: int
    assessed_assets: int
    average_score: Decimal | None
    categories_in_use: int
    exposed_assets: list
    category_counts: list
    open_risks_by_level: dict
    heatmap: dict  # (likelihood, impact) -> count of unresolved risks
    top_risks: list
    overdue_treatments: int
    expired_acceptances: list
    status_counts: dict = field(default_factory=dict)


def portfolio(top: int = 10) -> Portfolio:
    assets = Asset.objects.active().select_related("category")
    assessed = assets.assessed()
    avg = assessed.aggregate(avg=Avg("security_score"))["avg"]
    average = Decimal(str(avg)).quantize(Decimal("0.1"), rounding=ROUND_HALF_UP) if avg is not None else None

    risks = AssetRisk.objects.active_assets().select_related("asset", "vulnerability", "asset__category")
    unresolved = risks.unresolved()
    by_level = Counter(unresolved.values_list("inherent_level", flat=True))
    heat = Counter()
    for risk in unresolved.select_related("asset"):
        heat[(risk.likelihood, risk.impact)] += 1

    today = timezone.localdate()
    overdue = RiskTreatment.objects.filter(
        risk__asset__is_active=True, due_date__lt=today,
        status__in=[RiskTreatment.Status.PLANNED, RiskTreatment.Status.IN_PROGRESS],
    ).count()
    expired = list(risks.filter(status=AssetRisk.Status.ACCEPTED, acceptance_review_date__lt=today))

    return Portfolio(
        total_assets=assets.count(),
        assessed_assets=assessed.count(),
        average_score=average,
        categories_in_use=assets.values("category").distinct().count(),
        exposed_assets=list(assessed.filter(security_score__lt=settings.CUSTARD_EXPOSURE_THRESHOLD)
                            .order_by("security_score", "name")),
        category_counts=list(assets.values("category__name").annotate(n=Count("id")).order_by("-n", "category__name")),
        open_risks_by_level={lvl: by_level.get(lvl, 0) for lvl in Level.values},
        heatmap=dict(heat),
        top_risks=list(unresolved.order_by("-inherent_score", "asset__name")[:top]),
        overdue_treatments=overdue,
        expired_acceptances=expired,
        status_counts=dict(Counter(risks.values_list("status", flat=True))),
    )
