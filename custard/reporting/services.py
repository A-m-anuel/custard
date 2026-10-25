from __future__ import annotations

import hashlib

from django.core.files.base import ContentFile
from django.db import transaction
from django.db.models import Prefetch
from django.utils import timezone

from custard.core import audit
from custard.core.models import AuditEvent
from custard.inventory.models import Asset
from custard.risk.models import AssetRisk, RiskTreatment

from . import metrics, pdf
from .models import Report


def report_queryset_risks():
    return (
        AssetRisk.objects.active_assets()
        .select_related("asset", "vulnerability", "owner", "asset__category")
        .prefetch_related(Prefetch("treatments", queryset=RiskTreatment.objects.select_related("mitigation", "owner")))
        .order_by("-inherent_score", "asset__name", "vulnerability__name")
    )


@transaction.atomic
def generate_report(*, actor=None, request=None) -> Report:
    previous = Report.objects.order_by("-created_at").first()
    since = previous.created_at if previous else None
    assets = list(Asset.objects.active().select_related("category", "owner").order_by("name"))
    new_assets = [a for a in assets if since is None or a.created_at > since]
    portfolio = metrics.portfolio()
    risks = list(report_queryset_risks())
    now = timezone.localtime()
    title = f"Cyber Risk Report {now:%Y-%m-%d %H:%M}"
    content = pdf.build_report(portfolio=portfolio, assets=assets, risks=risks, new_assets=new_assets,
                               generated_by=actor.get_username() if actor else None, title=title)
    report = Report(
        created_by=actor, title=title, sha256=hashlib.sha256(content).hexdigest(), size_bytes=len(content),
        new_assets=[a.name for a in new_assets],
        exposed_assets=[a.name for a in portfolio.exposed_assets],
        summary={
            "total_assets": portfolio.total_assets,
            "assessed_assets": portfolio.assessed_assets,
            "average_score": None if portfolio.average_score is None else str(portfolio.average_score),
            "unresolved_risks": portfolio.open_risks_by_level,
            "overdue_treatments": portfolio.overdue_treatments,
        },
    )
    report.file.save(f"custard-report-{now:%Y%m%d-%H%M%S}.pdf", ContentFile(content), save=False)
    report.save()
    audit.record(AuditEvent.Action.REPORT, request=request, actor=actor, obj=report,
                 changes={"sha256": report.sha256, "new_assets": len(new_assets),
                          "exposed_assets": len(portfolio.exposed_assets)})
    return report
