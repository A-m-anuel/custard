from __future__ import annotations

from django.conf import settings
from django.contrib import messages
from django.contrib.auth.decorators import login_required, permission_required
from django.core.paginator import Paginator
from django.db.models import Count, Q
from django.http import HttpResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.views.decorators.http import require_POST

from custard.catalog.models import AssetCategory, AssetType
from custard.core import audit
from custard.core.csvutil import rows_to_csv
from custard.core.models import AuditEvent
from custard.risk.models import AssetRisk

from . import importer, services
from .forms import AssessmentForm, AssetCreateForm, AssetForm, AssetImportForm
from .models import Asset

SORTS = {
    "name": ("name",), "-name": ("-name",),
    "score": ("security_score", "name"), "-score": ("-security_score", "name"),
    "created": ("created_at",), "-created": ("-created_at",),
}


def checklist_catalog() -> dict:
    """{category_id: [{"id", "text", "pillar"}]} for the registration page script."""
    data: dict[str, list] = {}
    for category in AssetCategory.objects.filter(is_active=True).prefetch_related("checklist_items"):
        data[str(category.pk)] = [
            {"id": i.pk, "text": i.text, "pillar": i.pillar}
            for i in category.checklist_items.all() if i.is_active
        ]
    return data


@login_required
@permission_required("inventory.view_asset", raise_exception=True)
def asset_list(request):
    assets = Asset.objects.select_related("category__asset_type", "owner").annotate(
        unresolved_risks=Count("risks", filter=Q(risks__status__in=[AssetRisk.Status.OPEN,
                                                                     AssetRisk.Status.IN_TREATMENT]))
    )
    q = request.GET.get("q", "").strip()
    type_id = request.GET.get("type", "")
    category_id = request.GET.get("category", "")
    status = request.GET.get("status", "")
    show_archived = request.GET.get("archived") == "1"

    assets = assets if show_archived else assets.filter(is_active=True)
    if q:
        assets = assets.filter(Q(name__icontains=q) | Q(description__icontains=q) | Q(location__icontains=q))
    if type_id.isdigit():
        assets = assets.filter(category__asset_type_id=int(type_id))
    if category_id.isdigit():
        assets = assets.filter(category_id=int(category_id))
    if status == "exposed":
        assets = assets.filter(security_score__lt=settings.CUSTARD_EXPOSURE_THRESHOLD)
    elif status == "secure":
        assets = assets.filter(security_score__gte=settings.CUSTARD_EXPOSURE_THRESHOLD)
    elif status == "unassessed":
        assets = assets.filter(security_score__isnull=True)
    elif status == "mine":
        assets = assets.filter(owner=request.user)
    sort = request.GET.get("sort", "name")
    assets = assets.order_by(*SORTS.get(sort, SORTS["name"]))

    page = Paginator(assets, 25).get_page(request.GET.get("page"))
    return render(request, "inventory/asset_list.html", {
        "page_obj": page, "q": q, "type_id": type_id, "category_id": category_id, "status": status,
        "show_archived": show_archived, "sort": sort, "types": AssetType.objects.all(),
        "categories": AssetCategory.objects.filter(is_active=True).select_related("asset_type"), "nav": "assets",
    })


@login_required
@permission_required("inventory.add_asset", raise_exception=True)
def asset_create(request):
    form = AssetCreateForm(request.POST or None)
    if request.method == "POST" and form.is_valid():
        asset = form.save(commit=False)
        services.register_asset(asset, implemented_item_ids=form.checklist_ids,
                                notes=form.cleaned_data.get("notes", ""), actor=request.user, request=request)
        mapped = asset.risks.count()
        if asset.is_assessed:
            messages.success(request, f"{asset} registered with security score {asset.security_score} "
                                      f"and {mapped} mapped risks.")
            return redirect(asset)
        messages.success(request, f"{asset} registered with {mapped} mapped risks. Complete the security checklist.")
        return redirect("asset_assess", pk=asset.pk) if asset.category.active_checklist().exists() else redirect(asset)
    return render(request, "inventory/asset_form.html", {
        "form": form, "checklists": checklist_catalog(), "creating": True, "nav": "assets",
    })


@login_required
@permission_required("inventory.view_asset", raise_exception=True)
def asset_detail(request, pk: int):
    asset = get_object_or_404(Asset.objects.select_related("category__asset_type", "owner", "created_by"), pk=pk)
    risks = asset.risks.select_related("vulnerability", "owner").prefetch_related("treatments")
    assessments = asset.assessments.select_related("assessed_by")[:10]
    latest = assessments[0] if assessments else None
    audit_trail = None
    if request.user.has_perm("core.view_auditevent"):
        audit_trail = AuditEvent.objects.filter(object_type=asset._meta.label, object_id=str(asset.pk))[:15]
    return render(request, "inventory/asset_detail.html", {
        "asset": asset, "risks": risks, "assessments": assessments, "latest": latest,
        "audit_trail": audit_trail, "nav": "assets",
    })


@login_required
@permission_required("inventory.change_asset", raise_exception=True)
def asset_edit(request, pk: int):
    asset = get_object_or_404(Asset, pk=pk)
    original = audit.snapshot(asset, services.AUDITED_FIELDS)
    form = AssetForm(request.POST or None, instance=asset)
    if request.method == "POST" and form.is_valid():
        changes = services.update_asset(form.save(commit=False), original, actor=request.user, request=request)
        if "category" in changes:
            messages.info(request, "Category changed: risks were re-mapped. Reassess the new checklist.")
        messages.success(request, "Asset updated.")
        return redirect(asset)
    return render(request, "inventory/asset_form.html", {"form": form, "asset": asset, "nav": "assets"})


@login_required
@permission_required("inventory.add_assessment", raise_exception=True)
def asset_assess(request, pk: int):
    asset = get_object_or_404(Asset.objects.select_related("category"), pk=pk)
    form = AssessmentForm(request.POST or None, asset=asset)
    if not form.items:
        messages.warning(request, "This category has no checklist yet. Add checklist items in the catalog.")
        return redirect(asset)
    latest = asset.assessments.first()
    checked = {r["item_id"] for r in latest.responses if r.get("implemented")} if latest and request.method == "GET" \
        else set(int(v) for v in request.POST.getlist("checklist") if v.isdigit())
    if request.method == "POST" and form.is_valid():
        try:
            assessment = services.assess(asset, implemented_item_ids=form.cleaned_data["checklist"],
                                         notes=form.cleaned_data["notes"], actor=request.user, request=request)
        except services.AssessmentError as exc:
            form.add_error(None, str(exc))
        else:
            messages.success(request, f"Assessment saved: security score {assessment.security_score} / 10.")
            return redirect(asset)
    return render(request, "inventory/assessment_form.html", {
        "asset": asset, "form": form, "groups": form.items_by_pillar(checked), "nav": "assets",
    })


@login_required
@require_POST
@permission_required("inventory.change_asset", raise_exception=True)
def asset_archive(request, pk: int):
    asset = get_object_or_404(Asset, pk=pk)
    restore = request.POST.get("restore") == "1"
    services.set_active(asset, restore, actor=request.user, request=request)
    messages.success(request, f"{asset} {'restored' if restore else 'archived'}.")
    return redirect(asset)


@login_required
@permission_required("inventory.import_assets", raise_exception=True)
def asset_import(request):
    form = AssetImportForm(request.POST or None, request.FILES or None)
    result = None
    if request.method == "POST" and form.is_valid():
        dry_run = form.cleaned_data["dry_run"]
        result = importer.parse_and_import(form.cleaned_data["file"], actor=request.user, request=request,
                                           dry_run=dry_run)
        if result.ok and not dry_run:
            messages.success(request, f"Imported {len(result.created)} assets. Default risks were mapped.")
            return redirect("asset_list")
        if result.ok:
            messages.info(request, "The file is valid. Untick 'Validate only' and upload again to import.")
    return render(request, "inventory/asset_import.html", {
        "form": form, "result": result, "columns": importer.TEMPLATE_HEADER, "nav": "assets",
    })


@login_required
@permission_required("inventory.import_assets", raise_exception=True)
def asset_import_template(request):
    example = [
        ["Mail server", "Email Servers and Clients", "Exchange Online tenant", "", "Cloud", "High", "High", "Medium"],
        ["Finance laptop 12", "Desktop computers", "", "", "London office", "High", "Medium", "Low"],
    ]
    response = HttpResponse(rows_to_csv(importer.TEMPLATE_HEADER, example), content_type="text/csv; charset=utf-8")
    response["Content-Disposition"] = 'attachment; filename="custard-asset-import-template.csv"'
    return response


@login_required
@require_POST
@permission_required("risk.add_assetrisk", raise_exception=True)
def asset_sync_risks(request, pk: int):
    from custard.risk.services import sync_default_risks

    asset = get_object_or_404(Asset, pk=pk)
    result = sync_default_risks(asset, actor=request.user, request=request)
    messages.success(request, f"Risk mapping refreshed: {result['created']} added, {result['removed']} removed.")
    return redirect(asset)
