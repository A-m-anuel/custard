from __future__ import annotations

from django.contrib import messages
from django.contrib.auth.decorators import login_required, permission_required
from django.db import transaction
from django.db.models import Count, Q
from django.shortcuts import get_object_or_404, redirect, render
from django.views.decorators.http import require_POST

from custard.core import audit
from custard.core.choices import Pillar
from custard.core.models import AuditEvent

from .forms import CategoryCreateForm, ChecklistItemForm, DefaultVulnerabilityForm
from .models import AssetCategory, AssetType, CategoryVulnerability, ChecklistItem, Mitigation, Vulnerability


@login_required
@permission_required("catalog.view_assetcategory", raise_exception=True)
def catalog_index(request):
    types = AssetType.objects.prefetch_related(
        _categories_with_counts()
    )
    return render(request, "catalog/index.html", {
        "types": types, "vulnerability_count": Vulnerability.objects.count(),
        "mitigation_count": Mitigation.objects.count(), "nav": "catalog",
    })


def _categories_with_counts():
    from django.db.models import Prefetch

    return Prefetch("categories", queryset=AssetCategory.objects.annotate(
        checks=Count("checklist_items", filter=Q(checklist_items__is_active=True), distinct=True),
        weaknesses=Count("default_vulnerabilities", distinct=True),
        asset_count=Count("assets", filter=Q(assets__is_active=True), distinct=True),
    ))


@login_required
@permission_required("catalog.view_assetcategory", raise_exception=True)
def category_detail(request, pk: int):
    category = get_object_or_404(AssetCategory.objects.select_related("asset_type"), pk=pk)
    checklist = []
    items = list(category.checklist_items.filter(is_active=True))
    for value, label in Pillar.choices:
        checklist.append((label, [i for i in items if i.pillar == value]))
    defaults = category.default_vulnerabilities.select_related("vulnerability").prefetch_related(
        "mitigations", "vulnerability__mitigations")
    return render(request, "catalog/category_detail.html", {
        "category": category, "checklist": checklist, "defaults": defaults,
        "item_form": ChecklistItemForm(category=category)
        if request.user.has_perm("catalog.add_checklistitem") else None,
        "vuln_form": DefaultVulnerabilityForm(category=category)
        if request.user.has_perm("catalog.add_categoryvulnerability") else None,
        "nav": "catalog",
    })


@login_required
@permission_required("catalog.add_assetcategory", raise_exception=True)
def category_create(request):
    form = CategoryCreateForm(request.POST or None)
    if request.method == "POST" and form.is_valid():
        with transaction.atomic():
            category = form.save(commit=False)
            category.is_custom = True
            category.save()
            ChecklistItem.objects.bulk_create([
                ChecklistItem(category=category, pillar=pillar, text=text, order=i)
                for i, (pillar, text) in enumerate(form.checklist())
            ])
            audit.record(AuditEvent.Action.CREATE, request=request, obj=category,
                         changes={"checklist_items": len(form.checklist())})
        messages.success(request, f"Category '{category}' created. Map its typical weaknesses next.")
        return redirect("category_detail", pk=category.pk)
    return render(request, "catalog/category_form.html", {"form": form, "nav": "catalog"})


@login_required
@require_POST
@permission_required("catalog.add_checklistitem", raise_exception=True)
def checklist_item_add(request, pk: int):
    category = get_object_or_404(AssetCategory, pk=pk)
    form = ChecklistItemForm(request.POST, category=category)
    if form.is_valid():
        item = form.save(commit=False)
        item.category = category
        item.order = (category.checklist_items.order_by("-order").values_list("order", flat=True).first() or 0) + 1
        item.save()
        audit.record(AuditEvent.Action.CREATE, request=request, obj=item)
        messages.success(request, "Checklist item added. Existing scores change only when assets are reassessed.")
    else:
        messages.error(request, "; ".join(e for errs in form.errors.values() for e in errs))
    return redirect("category_detail", pk=pk)


@login_required
@require_POST
@permission_required("catalog.add_categoryvulnerability", raise_exception=True)
def default_vulnerability_add(request, pk: int):
    category = get_object_or_404(AssetCategory, pk=pk)
    form = DefaultVulnerabilityForm(request.POST, category=category)
    if form.is_valid():
        with transaction.atomic():
            vuln = form.cleaned_data["vulnerability"]
            if vuln is None:
                vuln, _ = Vulnerability.objects.get_or_create(name=form.cleaned_data["new_vulnerability"].strip()[:150])
            link = CategoryVulnerability.objects.create(category=category, vulnerability=vuln,
                                                        likelihood=form.cleaned_data["likelihood"])
            link.mitigations.add(*[Mitigation.objects.get_or_create(name=n)[0] for n in form.mitigation_names()])
            audit.record(AuditEvent.Action.CREATE, request=request, obj=link)
        messages.success(request, f"'{vuln}' mapped to {category}. New assets in this category will get this risk; "
                                  "existing assets get it when re-synchronised from the asset page.")
    else:
        messages.error(request, "; ".join(e for errs in form.errors.values() for e in errs))
    return redirect("category_detail", pk=pk)
