"""Risk mapping and treatment workflow."""

from __future__ import annotations

import datetime

from django.db import transaction
from django.utils import timezone

from custard.catalog.models import Mitigation, Vulnerability
from custard.core import audit
from custard.core.choices import Level
from custard.core.models import AuditEvent

from .models import AssetRisk, RiskTreatment


@transaction.atomic
def sync_default_risks(asset, *, actor=None, request=None) -> dict[str, int]:
    """Map the asset's category to its default vulnerabilities and recommended mitigations
    (dissertation 3.4.4 "Risk Mapping View"). Safe to call repeatedly: existing risks are kept.

    When an asset moves to another category, automatically mapped risks that no longer apply and
    were never worked on (still OPEN, every treatment still PLANNED) are removed.
    """
    links = (
        asset.category.default_vulnerabilities.select_related("vulnerability")
        .prefetch_related("mitigations", "vulnerability__mitigations")
    )
    wanted = set()
    created = 0
    for link in links:
        wanted.add(link.vulnerability_id)
        risk, made = AssetRisk.objects.get_or_create(
            asset=asset,
            vulnerability=link.vulnerability,
            defaults={"likelihood": link.likelihood, "owner": asset.owner, "source": AssetRisk.Source.AUTO},
        )
        if made:
            created += 1
            RiskTreatment.objects.bulk_create(
                [RiskTreatment(risk=risk, mitigation=m, owner=asset.owner) for m in link.recommended_mitigations()]
            )
    stale = (
        AssetRisk.objects.filter(asset=asset, source=AssetRisk.Source.AUTO, status=AssetRisk.Status.OPEN)
        .exclude(vulnerability_id__in=wanted)
        .exclude(treatments__status__in=[RiskTreatment.Status.IN_PROGRESS, RiskTreatment.Status.IMPLEMENTED])
    )
    removed = 0
    for risk in stale:
        risk.delete()
        removed += 1
    if created or removed:
        audit.record(AuditEvent.Action.UPDATE, request=request, actor=actor, obj=asset,
                     changes={"risks_mapped": created, "risks_removed": removed})
    return {"created": created, "removed": removed}


def refresh_scores(asset) -> int:
    """Re-score every risk of an asset (call after the asset's CIA impact changes)."""
    count = 0
    for risk in asset.risks.all():
        risk.save()
        count += 1
    return count


@transaction.atomic
def add_manual_risk(asset, *, vulnerability: Vulnerability, likelihood: str, owner=None, mitigations=(),
                    actor=None, request=None) -> AssetRisk:
    risk = AssetRisk.objects.create(
        asset=asset, vulnerability=vulnerability, likelihood=likelihood, owner=owner or asset.owner,
        source=AssetRisk.Source.MANUAL,
    )
    for mitigation in mitigations:
        RiskTreatment.objects.get_or_create(risk=risk, mitigation=mitigation, defaults={"owner": risk.owner})
    for mitigation in vulnerability.mitigations.all():
        RiskTreatment.objects.get_or_create(risk=risk, mitigation=mitigation, defaults={"owner": risk.owner})
    audit.record(AuditEvent.Action.CREATE, request=request, actor=actor, obj=risk,
                 changes={"likelihood": likelihood, "source": "manual"})
    return risk


def derive_status(risk: AssetRisk) -> str:
    """Status implied by treatment progress. ACCEPTED and NOT_APPLICABLE are decisions, never derived."""
    if risk.status in (AssetRisk.Status.ACCEPTED, AssetRisk.Status.NOT_APPLICABLE):
        return risk.status
    statuses = [t.status for t in risk.treatments.all() if t.status != RiskTreatment.Status.NOT_APPLICABLE]
    if statuses and all(s == RiskTreatment.Status.IMPLEMENTED for s in statuses):
        return AssetRisk.Status.MITIGATED
    if any(s in (RiskTreatment.Status.IN_PROGRESS, RiskTreatment.Status.IMPLEMENTED) for s in statuses):
        return AssetRisk.Status.IN_TREATMENT
    return AssetRisk.Status.OPEN


@transaction.atomic
def update_treatment(treatment: RiskTreatment, *, status: str, owner=None, due_date: datetime.date | None = None,
                     notes: str = "", actor=None, request=None) -> RiskTreatment:
    before = audit.snapshot(treatment, ["status", "owner", "due_date", "notes"])
    treatment.status, treatment.owner, treatment.due_date, treatment.notes = status, owner, due_date, notes
    if status == RiskTreatment.Status.IMPLEMENTED and treatment.completed_at is None:
        treatment.completed_at = timezone.now()
    elif status != RiskTreatment.Status.IMPLEMENTED:
        treatment.completed_at = None
    treatment.save()
    changes = audit.diff(treatment, before, ["status", "owner", "due_date", "notes"])
    if changes:
        audit.record(AuditEvent.Action.UPDATE, request=request, actor=actor, obj=treatment, changes=changes)
    apply_derived_status(treatment.risk, actor=actor, request=request)
    return treatment


def apply_derived_status(risk: AssetRisk, *, actor=None, request=None) -> None:
    new_status = derive_status(risk)
    if new_status == risk.status:
        return
    old = risk.status
    risk.status = new_status
    fields = ["status"]
    # NIST SP 800-30 Table 3-4 defines Low likelihood as "controls are in place to prevent, or at
    # least significantly impede, the vulnerability from being exercised". Once every treatment is
    # implemented that definition applies, so Low is the default residual likelihood. Analysts can
    # override it on the risk page.
    if new_status == AssetRisk.Status.MITIGATED and not risk.residual_likelihood:
        risk.residual_likelihood = Level.LOW
        fields.append("residual_likelihood")
    elif old == AssetRisk.Status.MITIGATED and new_status != AssetRisk.Status.MITIGATED:
        risk.residual_likelihood = ""
        fields.append("residual_likelihood")
    risk.save(update_fields=fields)
    audit.record(AuditEvent.Action.UPDATE, request=request, actor=actor, obj=risk,
                 changes={"status": [old, new_status], "reason": "treatment progress"})


@transaction.atomic
def accept_risk(risk: AssetRisk, *, justification: str, review_date: datetime.date, actor, request=None) -> AssetRisk:
    old = risk.status
    risk.status = AssetRisk.Status.ACCEPTED
    risk.acceptance_justification = justification
    risk.acceptance_review_date = review_date
    risk.accepted_by = actor
    risk.accepted_at = timezone.now()
    risk.save()
    audit.record(AuditEvent.Action.ACCEPT, request=request, actor=actor, obj=risk,
                 changes={"status": [old, risk.status], "review_date": review_date.isoformat(),
                          "justification": justification})
    return risk


@transaction.atomic
def reopen_risk(risk: AssetRisk, *, actor, request=None) -> AssetRisk:
    old = risk.status
    risk.status = AssetRisk.Status.OPEN
    risk.accepted_by, risk.accepted_at, risk.acceptance_review_date = None, None, None
    risk.save()
    apply_derived_status(risk, actor=actor, request=request)
    audit.record(AuditEvent.Action.UPDATE, request=request, actor=actor, obj=risk,
                 changes={"status": [old, risk.status], "reason": "reopened"})
    return risk


def get_or_create_mitigation(name: str) -> Mitigation:
    obj, _ = Mitigation.objects.get_or_create(name=name.strip()[:255])
    return obj
