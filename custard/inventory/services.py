"""Asset registration, assessment and lifecycle."""

from __future__ import annotations

from django.db import transaction

from custard.core import audit
from custard.core.models import AuditEvent
from custard.risk import services as risk_services

from . import scoring
from .models import Assessment, Asset

AUDITED_FIELDS = [
    "name", "category", "description", "owner", "location",
    "impact_confidentiality", "impact_integrity", "impact_availability", "is_active",
]


class AssessmentError(ValueError):
    pass


@transaction.atomic
def register_asset(asset: Asset, *, implemented_item_ids=None, notes: str = "", actor=None, request=None) -> Asset:
    """Save a new asset, map its default risks and (optionally) record the first assessment.

    This is the dissertation's registration workflow (Figure 19/20): categorise, map vulnerabilities,
    risk levels and treatments, and score the security checklist - all in one step.
    """
    asset.created_by = actor
    asset.save()
    audit.record(AuditEvent.Action.CREATE, request=request, actor=actor, obj=asset,
                 changes=audit.snapshot(asset, AUDITED_FIELDS))
    risk_services.sync_default_risks(asset, actor=actor, request=request)
    if implemented_item_ids is not None and asset.category.active_checklist().exists():
        assess(asset, implemented_item_ids=implemented_item_ids, notes=notes, actor=actor, request=request)
    return asset


@transaction.atomic
def update_asset(asset: Asset, original: dict, *, actor=None, request=None) -> dict:
    changes = audit.diff(asset, original, AUDITED_FIELDS)
    asset.save()
    if changes:
        audit.record(AuditEvent.Action.UPDATE, request=request, actor=actor, obj=asset, changes=changes)
    if "category" in changes:
        risk_services.sync_default_risks(asset, actor=actor, request=request)
    if changes.keys() & {"impact_confidentiality", "impact_integrity", "impact_availability"}:
        risk_services.refresh_scores(asset)
    return changes


@transaction.atomic
def assess(asset: Asset, *, implemented_item_ids, notes: str = "", actor=None, request=None) -> Assessment:
    """Score the asset against its category checklist. The score is always computed on the server."""
    items = list(asset.category.active_checklist())
    if not items:
        raise AssessmentError("This category has no checklist items yet. Add some in the catalog first.")
    valid_ids = {item.pk for item in items}
    try:
        chosen = {int(i) for i in implemented_item_ids}
    except (TypeError, ValueError) as exc:
        raise AssessmentError("Invalid checklist submission.") from exc
    unknown = chosen - valid_ids
    if unknown:
        raise AssessmentError("The submitted checklist does not match the asset's category.")

    responses = [
        {"item_id": item.pk, "text": item.text, "pillar": item.pillar, "implemented": item.pk in chosen}
        for item in items
    ]
    result = scoring.calculate((r["pillar"], r["implemented"]) for r in responses)
    assessment = Assessment.objects.create(
        asset=asset, assessed_by=actor, responses=responses, notes=notes,
        confidentiality_score=result.confidentiality, integrity_score=result.integrity,
        availability_score=result.availability, security_score=result.overall,
    )
    previous = asset.security_score
    asset.confidentiality_score = result.confidentiality
    asset.integrity_score = result.integrity
    asset.availability_score = result.availability
    asset.security_score = result.overall
    asset.last_assessed_at = assessment.assessed_at
    asset.save(update_fields=[
        "confidentiality_score", "integrity_score", "availability_score", "security_score",
        "last_assessed_at", "updated_at",
    ])
    audit.record(AuditEvent.Action.ASSESS, request=request, actor=actor, obj=asset,
                 changes={"security_score": [_s(previous), _s(result.overall)],
                          "implemented": f"{len(chosen)}/{len(items)}"})
    return assessment


def set_active(asset: Asset, active: bool, *, actor=None, request=None) -> None:
    if asset.is_active == active:
        return
    asset.is_active = active
    asset.save(update_fields=["is_active", "updated_at"])
    audit.record(AuditEvent.Action.RESTORE if active else AuditEvent.Action.ARCHIVE,
                 request=request, actor=actor, obj=asset)


def _s(value):
    return None if value is None else str(value)
