from __future__ import annotations

from django.conf import settings
from django.contrib import messages
from django.contrib.auth.decorators import login_required, permission_required
from django.core.paginator import Paginator
from django.http import FileResponse, Http404, HttpResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.utils import timezone
from django.views.decorators.http import require_POST

from custard.core import audit, svg
from custard.core.choices import Level
from custard.core.csvutil import rows_to_csv
from custard.core.models import AuditEvent
from custard.inventory.models import Asset

from . import metrics
from .models import Report
from .services import generate_report, report_queryset_risks

HEAT_ORDER = [Level.HIGH, Level.MEDIUM, Level.LOW]


@login_required
@permission_required("inventory.view_asset", raise_exception=True)
def dashboard(request):
    data = metrics.portfolio()
    threshold = settings.CUSTARD_EXPOSURE_THRESHOLD
    assets = Asset.objects.active().order_by("security_score", "name")
    rows = [(a.name, a.security_score,
             "unassessed" if a.security_score is None else "exposed" if a.security_score < threshold else "ok")
            for a in assets[:60]]
    heat_rows = [
        {"likelihood": Level(lk).label,
         "cells": [{"impact": Level(im).label, "count": data.heatmap.get((lk, im), 0),
                    "css": _heat_css(lk, im)} for im in reversed(HEAT_ORDER)]}
        for lk in HEAT_ORDER
    ]
    last_report = Report.objects.order_by("-created_at").first()
    new_since = Asset.objects.active().filter(created_at__gt=last_report.created_at).count() if last_report else None
    return render(request, "reporting/dashboard.html", {
        "nav": "dashboard",
        "p": data,
        "score_chart": svg.score_bar_chart(rows, threshold=float(threshold)),
        "chart_truncated": assets.count() > 60,
        "heat_rows": heat_rows,
        "impact_labels": [Level(im).label for im in reversed(HEAT_ORDER)],
        "last_report": last_report,
        "new_since_report": new_since,
    })


def _heat_css(likelihood, impact) -> str:
    from custard.risk.engine import assess

    return "lvl-" + assess(likelihood, impact)[1].lower()


@login_required
@permission_required("reporting.view_report", raise_exception=True)
def report_list(request):
    page = Paginator(Report.objects.select_related("created_by"), 25).get_page(request.GET.get("page"))
    return render(request, "reporting/report_list.html", {"page_obj": page, "nav": "reports"})


@login_required
@require_POST
@permission_required("reporting.generate_report", raise_exception=True)
def report_generate(request):
    report = generate_report(actor=request.user, request=request)
    messages.success(request, f"{report.title} generated.")
    return redirect("report_list")


@login_required
@permission_required("reporting.view_report", raise_exception=True)
def report_download(request, pk: int):
    report = get_object_or_404(Report, pk=pk)
    try:
        handle = report.file.open("rb")
    except (FileNotFoundError, ValueError) as exc:
        raise Http404("Report file is missing") from exc
    audit.record(AuditEvent.Action.DOWNLOAD, request=request, obj=report)
    filename = report.file.name.rsplit("/", 1)[-1]
    return FileResponse(handle, as_attachment=True, filename=filename, content_type="application/pdf")


def _csv_response(name: str, content: str) -> HttpResponse:
    response = HttpResponse(content, content_type="text/csv; charset=utf-8")
    response["Content-Disposition"] = f'attachment; filename="{name}-{timezone.localdate():%Y%m%d}.csv"'
    return response


@login_required
@permission_required("inventory.view_asset", raise_exception=True)
def export_assets(request):
    assets = Asset.objects.select_related("category__asset_type", "owner").order_by("name")
    header = ["name", "type", "category", "owner", "location", "confidentiality_impact", "integrity_impact",
              "availability_impact", "confidentiality_score", "integrity_score", "availability_score",
              "security_score", "exposed", "last_assessed_at", "active", "created_at"]
    rows = [[a.name, a.category.asset_type.name, a.category.name, a.owner.get_username() if a.owner else "",
             a.location, a.get_impact_confidentiality_display(), a.get_impact_integrity_display(),
             a.get_impact_availability_display(), a.confidentiality_score, a.integrity_score, a.availability_score,
             a.security_score, "yes" if a.is_exposed else "no",
             a.last_assessed_at.isoformat() if a.last_assessed_at else "", "yes" if a.is_active else "no",
             a.created_at.isoformat()] for a in assets]
    audit.record(AuditEvent.Action.EXPORT, request=request, object_repr="assets.csv", changes={"rows": len(rows)})
    return _csv_response("custard-assets", rows_to_csv(header, rows))


@login_required
@permission_required("risk.view_assetrisk", raise_exception=True)
def export_risks(request):
    risks = report_queryset_risks()
    header = ["asset", "category", "vulnerability", "likelihood", "impact", "inherent_score", "inherent_level",
              "residual_likelihood", "residual_score", "residual_level", "status", "owner", "treatments",
              "acceptance_review_date"]
    rows = [[r.asset.name, r.asset.category.name, r.vulnerability.name, r.get_likelihood_display(),
             r.get_impact_display(), r.inherent_score, r.get_inherent_level_display(),
             r.get_residual_likelihood_display() if r.residual_likelihood else "",
             r.residual_score if r.residual_score is not None else "",
             r.get_residual_level_display() if r.residual_level else "", r.get_status_display(),
             r.owner.get_username() if r.owner else "",
             "; ".join(f"{t.mitigation.name} [{t.get_status_display()}]" for t in r.treatments.all()),
             r.acceptance_review_date.isoformat() if r.acceptance_review_date else ""] for r in risks]
    audit.record(AuditEvent.Action.EXPORT, request=request, object_repr="risks.csv", changes={"rows": len(rows)})
    return _csv_response("custard-risk-register", rows_to_csv(header, rows))
