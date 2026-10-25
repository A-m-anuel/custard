from __future__ import annotations

from django.conf import settings
from django.http import Http404, JsonResponse

from custard.core.choices import Level
from custard.inventory.models import Asset
from custard.reporting import metrics
from custard.risk.models import AssetRisk

from .auth import api_view

MAX_LIMIT = 200


def _page(request, queryset, serialise):
    try:
        limit = max(1, min(int(request.GET.get("limit", 50)), MAX_LIMIT))
        offset = max(0, int(request.GET.get("offset", 0)))
    except ValueError:
        limit, offset = 50, 0
    total = queryset.count()
    items = [serialise(obj) for obj in queryset[offset:offset + limit]]
    return JsonResponse({"count": total, "limit": limit, "offset": offset, "results": items})


def _dec(value):
    return None if value is None else float(value)


def asset_json(a: Asset, detail: bool = False) -> dict:
    data = {
        "id": a.pk, "name": a.name, "type": a.category.asset_type.name, "category": a.category.name,
        "owner": a.owner.get_username() if a.owner else None, "location": a.location,
        "impact": {"confidentiality": a.impact_confidentiality, "integrity": a.impact_integrity,
                   "availability": a.impact_availability, "overall": a.impact},
        "scores": {"confidentiality": _dec(a.confidentiality_score), "integrity": _dec(a.integrity_score),
                   "availability": _dec(a.availability_score), "security": _dec(a.security_score)},
        "exposed": a.is_exposed, "active": a.is_active,
        "last_assessed_at": a.last_assessed_at.isoformat() if a.last_assessed_at else None,
        "created_at": a.created_at.isoformat(),
    }
    if detail:
        data["risks"] = [risk_json(r) for r in a.risks.select_related("vulnerability", "owner", "asset__category")]
    return data


def risk_json(r: AssetRisk) -> dict:
    return {
        "id": r.pk, "asset_id": r.asset_id, "asset": r.asset.name, "vulnerability": r.vulnerability.name,
        "likelihood": r.likelihood, "impact": r.impact, "inherent_score": r.inherent_score,
        "inherent_level": r.inherent_level, "residual_likelihood": r.residual_likelihood or None,
        "residual_score": r.residual_score, "residual_level": r.residual_level or None, "status": r.status,
        "owner": r.owner.get_username() if r.owner else None,
        "acceptance_review_date": r.acceptance_review_date.isoformat() if r.acceptance_review_date else None,
    }


@api_view("inventory.view_asset")
def summary(request):
    p = metrics.portfolio()
    return JsonResponse({
        "total_assets": p.total_assets, "assessed_assets": p.assessed_assets,
        "average_score": _dec(p.average_score), "exposure_threshold": float(settings.CUSTARD_EXPOSURE_THRESHOLD),
        "exposed_assets": [{"id": a.pk, "name": a.name, "score": _dec(a.security_score)} for a in p.exposed_assets],
        "unresolved_risks_by_level": p.open_risks_by_level, "overdue_treatments": p.overdue_treatments,
        "expired_acceptances": len(p.expired_acceptances),
    })


@api_view("inventory.view_asset")
def asset_list(request):
    qs = Asset.objects.active().select_related("category__asset_type", "owner").order_by("name")
    if request.GET.get("exposed") == "true":
        qs = qs.exposed()
    if request.GET.get("category"):
        qs = qs.filter(category__name__iexact=request.GET["category"])
    return _page(request, qs, asset_json)


@api_view("inventory.view_asset")
def asset_detail(request, pk: int):
    asset = Asset.objects.select_related("category__asset_type", "owner").filter(pk=pk).first()
    if asset is None:
        raise Http404
    return JsonResponse(asset_json(asset, detail=True))


@api_view("risk.view_assetrisk")
def risk_list(request):
    qs = AssetRisk.objects.active_assets().select_related("asset__category", "vulnerability", "owner") \
        .order_by("-inherent_score", "asset__name")
    level = request.GET.get("level", "").upper()
    if level in Level.values:
        qs = qs.filter(inherent_level=level)
    status = request.GET.get("status", "").upper()
    if status in AssetRisk.Status.values:
        qs = qs.filter(status=status)
    return _page(request, qs, risk_json)
