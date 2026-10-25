from __future__ import annotations

import datetime

from django.conf import settings
from django.db import models
from django.urls import reverse
from django.utils import timezone

from custard.catalog.models import Mitigation, Vulnerability
from custard.core.choices import Level
from custard.inventory.models import Asset

from . import engine


class AssetRiskQuerySet(models.QuerySet):
    def active_assets(self):
        return self.filter(asset__is_active=True)

    def unresolved(self):
        return self.filter(status__in=[AssetRisk.Status.OPEN, AssetRisk.Status.IN_TREATMENT])


class AssetRisk(models.Model):
    """A weakness on a specific asset, scored with NIST SP 800-30. One row per asset/vulnerability."""

    class Status(models.TextChoices):
        OPEN = "OPEN", "Open"
        IN_TREATMENT = "IN_TREATMENT", "In treatment"
        MITIGATED = "MITIGATED", "Mitigated"
        ACCEPTED = "ACCEPTED", "Accepted"
        NOT_APPLICABLE = "NOT_APPLICABLE", "Not applicable"

    class Source(models.TextChoices):
        AUTO = "AUTO", "Category mapping"
        MANUAL = "MANUAL", "Added manually"

    asset = models.ForeignKey(Asset, on_delete=models.CASCADE, related_name="risks")
    vulnerability = models.ForeignKey(Vulnerability, on_delete=models.PROTECT, related_name="asset_risks")
    likelihood = models.CharField(max_length=6, choices=Level.choices)
    impact_override = models.CharField(
        max_length=6, choices=Level.choices, blank=True,
        help_text="Leave empty to use the asset's impact (highest of its CIA impacts).",
    )
    status = models.CharField(max_length=16, choices=Status.choices, default=Status.OPEN, db_index=True)
    owner = models.ForeignKey(
        settings.AUTH_USER_MODEL, null=True, blank=True, on_delete=models.SET_NULL, related_name="owned_risks",
        help_text="Risk owner accountable for treatment.",
    )
    residual_likelihood = models.CharField(
        max_length=6, choices=Level.choices, blank=True, help_text="Likelihood after controls are in place."
    )
    source = models.CharField(max_length=6, choices=Source.choices, default=Source.AUTO, editable=False)
    notes = models.TextField(blank=True)

    # Risk acceptance (requires the risk.accept_risk permission)
    acceptance_justification = models.TextField(blank=True)
    accepted_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, null=True, blank=True, on_delete=models.SET_NULL, related_name="+", editable=False
    )
    accepted_at = models.DateTimeField(null=True, blank=True, editable=False)
    acceptance_review_date = models.DateField(null=True, blank=True)

    # Denormalised NIST results, kept in sync by save(), so the register can sort and filter in SQL.
    inherent_score = models.PositiveSmallIntegerField(default=0, editable=False, db_index=True)
    inherent_level = models.CharField(max_length=6, choices=Level.choices, editable=False, db_index=True)
    residual_score = models.PositiveSmallIntegerField(null=True, blank=True, editable=False)
    residual_level = models.CharField(max_length=6, choices=Level.choices, blank=True, editable=False)

    created_at = models.DateTimeField(default=timezone.now, editable=False)
    updated_at = models.DateTimeField(auto_now=True)

    objects = AssetRiskQuerySet.as_manager()

    class Meta:
        ordering = ["-inherent_score", "asset__name", "vulnerability__name"]
        permissions = [("accept_risk", "Can formally accept a risk")]
        constraints = [models.UniqueConstraint(fields=["asset", "vulnerability"], name="risk_asset_vuln_unique")]

    def __str__(self) -> str:
        return f"{self.asset} - {self.vulnerability}"

    def save(self, *args, **kwargs):
        self.recalculate()
        update_fields = kwargs.get("update_fields")
        if update_fields is not None:
            kwargs["update_fields"] = set(update_fields) | {
                "inherent_score", "inherent_level", "residual_score", "residual_level", "updated_at"
            }
        super().save(*args, **kwargs)

    def get_absolute_url(self) -> str:
        return reverse("risk_detail", args=[self.pk])

    @property
    def impact(self) -> str:
        return self.impact_override or self.asset.impact

    def get_impact_display(self) -> str:
        return Level(self.impact).label

    def recalculate(self) -> None:
        self.inherent_score, self.inherent_level = engine.assess(self.likelihood, self.impact)
        if self.residual_likelihood:
            self.residual_score, self.residual_level = engine.assess(self.residual_likelihood, self.impact)
        else:
            self.residual_score, self.residual_level = None, ""

    @property
    def current_score(self) -> int:
        """Residual score once controls are in place, otherwise the inherent score."""
        return self.residual_score if self.residual_score is not None else self.inherent_score

    @property
    def current_level(self) -> str:
        return self.residual_level or self.inherent_level

    @property
    def recommended_action(self) -> str:
        return engine.ACTIONS[Level(self.current_level)]

    @property
    def acceptance_expired(self) -> bool:
        return (
            self.status == self.Status.ACCEPTED
            and self.acceptance_review_date is not None
            and self.acceptance_review_date < timezone.localdate()
        )


class RiskTreatment(models.Model):
    """A mitigation applied to a specific risk, with its own owner, due date and progress."""

    class Status(models.TextChoices):
        PLANNED = "PLANNED", "Planned"
        IN_PROGRESS = "IN_PROGRESS", "In progress"
        IMPLEMENTED = "IMPLEMENTED", "Implemented"
        NOT_APPLICABLE = "NOT_APPLICABLE", "Not applicable"

    risk = models.ForeignKey(AssetRisk, on_delete=models.CASCADE, related_name="treatments")
    mitigation = models.ForeignKey(Mitigation, on_delete=models.PROTECT, related_name="treatments")
    status = models.CharField(max_length=16, choices=Status.choices, default=Status.PLANNED, db_index=True)
    owner = models.ForeignKey(
        settings.AUTH_USER_MODEL, null=True, blank=True, on_delete=models.SET_NULL, related_name="owned_treatments"
    )
    due_date = models.DateField(null=True, blank=True)
    completed_at = models.DateTimeField(null=True, blank=True, editable=False)
    notes = models.TextField(blank=True)
    created_at = models.DateTimeField(default=timezone.now, editable=False)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["risk", "mitigation__name"]
        constraints = [models.UniqueConstraint(fields=["risk", "mitigation"], name="risk_treatment_unique")]

    def __str__(self) -> str:
        return f"{self.mitigation} ({self.get_status_display()})"

    @property
    def is_overdue(self) -> bool:
        return (
            self.due_date is not None
            and self.status in (self.Status.PLANNED, self.Status.IN_PROGRESS)
            and self.due_date < timezone.localdate()
        )

    @property
    def is_open(self) -> bool:
        return self.status in (self.Status.PLANNED, self.Status.IN_PROGRESS)


def default_review_date() -> datetime.date:
    return timezone.localdate() + datetime.timedelta(days=180)
