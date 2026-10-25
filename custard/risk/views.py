from __future__ import annotations

from django.contrib import messages
from django.contrib.auth.decorators import login_required, permission_required
from django.core.paginator import Paginator
from django.db.models import Prefetch, Q
from django.shortcuts import get_object_or_404, redirect, render
from django.utils import timezone
from django.views.decorators.http import require_POST

from custard.catalog.models import AssetCategory, Vulnerability
from custard.core import audit
from custard.core.choices import Level
from custard.core.models import AuditEvent
from custard.inventory.models import Asset

from . import engine, graph, services
from .forms import AddRiskForm, AddTreatmentForm, RiskAcceptForm, RiskUpdateForm, TreatmentForm
from .models import AssetRisk, RiskTreatment

AUDITED = ["likelihood", "impact_override", "residual_likelihood", "owner", "status", "notes"]


@login_required
@permission_required("risk.view_assetrisk", raise_exception=True)
def risk_list(request):
    risks = AssetRisk.objects.active_assets().select_related("asset__category", "vulnerability", "owner")
    level = request.GET.get("level", "")
    status = request.GET.get("status", "unresolved")
    category_id = request.GET.get("category", "")
    q = request.GET.get("q", "").strip()
    flag = request.GET.get("flag", "")

    if level in Level.values:
        risks = risks.filter(inherent_level=level)
    if status == "unresolved":
        risks = risks.unresolved()
    elif status in AssetRisk.Status.values:
        risks = risks.filter(status=status)
    if category_id.isdigit():
        risks = risks.filter(asset__category_id=int(category_id))
    if q:
        risks = risks.filter(Q(asset__name__icontains=q) | Q(vulnerability__name__icontains=q))
    today = timezone.localdate()
    if flag == "mine":
        risks = risks.filter(owner=request.user)
    elif flag == "overdue":
        risks = risks.filter(treatments__due_date__lt=today,
                             treatments__status__in=[RiskTreatment.Status.PLANNED,
                                                     RiskTreatment.Status.IN_PROGRESS]).distinct()
    elif flag == "expired":
        risks = risks.filter(status=AssetRisk.Status.ACCEPTED, acceptance_review_date__lt=today)

    page = Paginator(risks.order_by("-inherent_score", "asset__name", "vulnerability__name"), 30) \
        .get_page(request.GET.get("page"))
    return render(request, "risk/risk_list.html", {
        "page_obj": page, "level": level, "status": status, "category_id": category_id, "q": q, "flag": flag,
        "levels": Level.choices, "statuses": AssetRisk.Status.choices,
        "categories": AssetCategory.objects.filter(is_active=True), "nav": "risks",
    })


@login_required
@permission_required("risk.view_assetrisk", raise_exception=True)
def risk_detail(request, pk: int):
    risk = get_object_or_404(
        AssetRisk.objects.select_related("asset__category", "vulnerability", "owner", "accepted_by")
        .prefetch_related(Prefetch("treatments", queryset=RiskTreatment.objects.select_related("mitigation", "owner"))),
        pk=pk,
    )
    can_change = request.user.has_perm("risk.change_assetrisk")
    form = RiskUpdateForm(request.POST or None, instance=risk) if can_change else None
    if request.method == "POST":
        if not can_change:
            return redirect(risk)
        original = audit.snapshot(risk, AUDITED)
        if form.is_valid():
            updated = form.save(commit=False)
            if updated.status != AssetRisk.Status.ACCEPTED and original["status"] == AssetRisk.Status.ACCEPTED:
                updated.accepted_by = updated.accepted_at = updated.acceptance_review_date = None
            updated.save()
            changes = audit.diff(updated, original, AUDITED)
            if changes:
                audit.record(AuditEvent.Action.UPDATE, request=request, obj=updated, changes=changes)
            messages.success(request, "Risk updated.")
            return redirect(risk)
    treatment_forms = [(t, TreatmentForm(instance=t, prefix=f"t{t.pk}")) for t in risk.treatments.all()] \
        if request.user.has_perm("risk.change_risktreatment") else [(t, None) for t in risk.treatments.all()]
    return render(request, "risk/risk_detail.html", {
        "risk": risk, "form": form, "treatment_forms": treatment_forms,
        "add_treatment_form": AddTreatmentForm(risk=risk) if request.user.has_perm("risk.add_risktreatment") else None,
        "accept_form": RiskAcceptForm() if request.user.has_perm("risk.accept_risk") else None,
        "matrix": _matrix(risk), "nav": "risks",
    })


def _matrix(risk: AssetRisk):
    """3x3 NIST matrix with the risk's cell highlighted."""
    rows = []
    for likelihood in (Level.HIGH, Level.MEDIUM, Level.LOW):
        cells = []
        for impact in (Level.LOW, Level.MEDIUM, Level.HIGH):
            score, level = engine.assess(likelihood, impact)
            cells.append({"score": score, "css": "lvl-" + level.lower(),
                          "current": likelihood == risk.likelihood and impact == risk.impact,
                          "residual": bool(risk.residual_likelihood) and likelihood == risk.residual_likelihood
                          and impact == risk.impact})
        rows.append({"label": Level(likelihood).label, "cells": cells})
    return rows


@login_required
@require_POST
@permission_required("risk.change_risktreatment", raise_exception=True)
def treatment_update(request, pk: int):
    treatment = get_object_or_404(RiskTreatment.objects.select_related("risk"), pk=pk)
    form = TreatmentForm(request.POST, instance=treatment, prefix=f"t{treatment.pk}")
    if form.is_valid():
        data = form.cleaned_data
        services.update_treatment(treatment, status=data["status"], owner=data["owner"], due_date=data["due_date"],
                                  notes=data["notes"], actor=request.user, request=request)
        messages.success(request, f"Treatment '{treatment.mitigation}' updated.")
    else:
        messages.error(request, "Treatment not saved: " + "; ".join(e for errs in form.errors.values() for e in errs))
    return redirect(treatment.risk)


@login_required
@require_POST
@permission_required("risk.add_risktreatment", raise_exception=True)
def treatment_add(request, pk: int):
    risk = get_object_or_404(AssetRisk, pk=pk)
    form = AddTreatmentForm(request.POST, risk=risk)
    if form.is_valid():
        mitigation = form.cleaned_data["mitigation"] or services.get_or_create_mitigation(
            form.cleaned_data["new_mitigation"])
        treatment, created = RiskTreatment.objects.get_or_create(
            risk=risk, mitigation=mitigation,
            defaults={"owner": form.cleaned_data["owner"], "due_date": form.cleaned_data["due_date"]},
        )
        if created:
            audit.record(AuditEvent.Action.CREATE, request=request, obj=treatment)
            services.apply_derived_status(risk, actor=request.user, request=request)
            messages.success(request, "Treatment added.")
        else:
            messages.info(request, "That mitigation is already planned for this risk.")
    else:
        messages.error(request, " ".join(form.non_field_errors()) or "Treatment not added.")
    return redirect(risk)


@login_required
@require_POST
@permission_required("risk.accept_risk", raise_exception=True)
def risk_accept(request, pk: int):
    risk = get_object_or_404(AssetRisk, pk=pk)
    form = RiskAcceptForm(request.POST)
    if form.is_valid():
        services.accept_risk(risk, justification=form.cleaned_data["justification"],
                             review_date=form.cleaned_data["review_date"], actor=request.user, request=request)
        messages.success(request, "Risk accepted. It will be flagged for review on the review date.")
    else:
        messages.error(request, "Risk not accepted: " + "; ".join(e for errs in form.errors.values() for e in errs))
    return redirect(risk)


@login_required
@require_POST
@permission_required("risk.accept_risk", raise_exception=True)
def risk_reopen(request, pk: int):
    risk = get_object_or_404(AssetRisk, pk=pk)
    services.reopen_risk(risk, actor=request.user, request=request)
    messages.success(request, "Risk acceptance withdrawn; the risk is open again.")
    return redirect(risk)


@login_required
@permission_required("risk.add_assetrisk", raise_exception=True)
def risk_add(request, asset_pk: int):
    asset = get_object_or_404(Asset, pk=asset_pk)
    form = AddRiskForm(request.POST or None, asset=asset)
    if request.method == "POST" and form.is_valid():
        vulnerability = form.cleaned_data["vulnerability"]
        if vulnerability is None:
            vulnerability, _ = Vulnerability.objects.get_or_create(
                name=form.cleaned_data["new_vulnerability"].strip()[:150])
        mitigations = [services.get_or_create_mitigation(n) for n in form.mitigation_names()]
        risk = services.add_manual_risk(asset, vulnerability=vulnerability, likelihood=form.cleaned_data["likelihood"],
                                        mitigations=mitigations, actor=request.user, request=request)
        messages.success(request, f"Risk '{vulnerability}' added to {asset}.")
        return redirect(risk)
    return render(request, "risk/risk_add.html", {"asset": asset, "form": form, "nav": "risks"})


@login_required
@permission_required("risk.view_assetrisk", raise_exception=True)
def dependency_map(request):
    risks = AssetRisk.objects.active_assets().select_related("asset__category", "vulnerability") \
        .prefetch_related(Prefetch("treatments", queryset=RiskTreatment.objects.select_related("mitigation")))
    category_id = request.GET.get("category", "")
    asset_id = request.GET.get("asset", "")
    scope = request.GET.get("scope", "unresolved")
    if scope == "unresolved":
        risks = risks.unresolved()
    if category_id.isdigit():
        risks = risks.filter(asset__category_id=int(category_id))
    if asset_id.isdigit():
        risks = risks.filter(asset_id=int(asset_id))
    risks = list(risks)
    asset_count = len({r.asset_id for r in risks})
    too_many = asset_count > 40 and not (category_id or asset_id)
    data = graph.build(risks[:0] if too_many else risks)
    return render(request, "risk/dependency_map.html", {
        "svg": graph.render_svg(data), "shared": graph.shared_mitigations(data),
        "categories": AssetCategory.objects.filter(is_active=True, assets__is_active=True).distinct(),
        "assets": Asset.objects.active().order_by("name"),
        "category_id": category_id, "asset_id": asset_id, "scope": scope,
        "too_many": too_many, "asset_count": asset_count, "nav": "dependencies",
    })
