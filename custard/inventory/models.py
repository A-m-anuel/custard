from __future__ import annotations

from django.conf import settings
from django.db import models
from django.urls import reverse
from django.utils import timezone

from custard.catalog.models import AssetCategory
from custard.core.choices import LEVEL_ORDER, Level

SCORE_FIELD = dict(max_digits=4, decimal_places=2, null=True, blank=True)


class AssetQuerySet(models.QuerySet):
    def active(self):
        return self.filter(is_active=True)

    def assessed(self):
        return self.filter(security_score__isnull=False)

    def exposed(self):
        return self.filter(security_score__lt=settings.CUSTARD_EXPOSURE_THRESHOLD)


class Asset(models.Model):
    """An organisational asset (hardware, software or information) - dissertation section 3.3."""

    name = models.CharField(max_length=200, unique=True)
    category = models.ForeignKey(AssetCategory, on_delete=models.PROTECT, related_name="assets")
    description = models.TextField(blank=True)
    owner = models.ForeignKey(
        settings.AUTH_USER_MODEL, null=True, blank=True, on_delete=models.SET_NULL, related_name="owned_assets",
        help_text="Person accountable for this asset.",
    )
    location = models.CharField(max_length=200, blank=True)
    # Asset value expressed as the impact a compromise would have on each CIA objective.
    impact_confidentiality = models.CharField("confidentiality impact", max_length=6, choices=Level.choices,
                                              default=Level.MEDIUM)
    impact_integrity = models.CharField("integrity impact", max_length=6, choices=Level.choices, default=Level.MEDIUM)
    impact_availability = models.CharField("availability impact", max_length=6, choices=Level.choices,
                                           default=Level.MEDIUM)
    is_active = models.BooleanField(default=True, help_text="Archived assets are hidden from dashboards and reports.")

    # Results of the latest checklist assessment (denormalised for fast dashboards and sorting).
    confidentiality_score = models.DecimalField(**SCORE_FIELD)
    integrity_score = models.DecimalField(**SCORE_FIELD)
    availability_score = models.DecimalField(**SCORE_FIELD)
    security_score = models.DecimalField(**SCORE_FIELD)
    last_assessed_at = models.DateTimeField(null=True, blank=True)

    created_at = models.DateTimeField(default=timezone.now, editable=False, db_index=True)
    updated_at = models.DateTimeField(auto_now=True)
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, null=True, blank=True, on_delete=models.SET_NULL, related_name="+", editable=False
    )

    objects = AssetQuerySet.as_manager()

    class Meta:
        ordering = ["name"]
        permissions = [("import_assets", "Can bulk-import assets from CSV")]
        indexes = [models.Index(fields=["security_score"], name="inventory_asset_score_idx")]

    def __str__(self) -> str:
        return self.name

    def get_absolute_url(self) -> str:
        return reverse("asset_detail", args=[self.pk])

    @property
    def asset_type(self):
        return self.category.asset_type

    @property
    def impact(self) -> str:
        """Overall impact as the high-water mark of the CIA impacts (FIPS 199 convention)."""
        levels = [self.impact_confidentiality, self.impact_integrity, self.impact_availability]
        return max(levels, key=lambda lvl: LEVEL_ORDER[lvl])

    def get_impact_display(self) -> str:
        return Level(self.impact).label

    @property
    def is_assessed(self) -> bool:
        return self.security_score is not None

    @property
    def is_exposed(self) -> bool:
        return self.security_score is not None and self.security_score < settings.CUSTARD_EXPOSURE_THRESHOLD


class Assessment(models.Model):
    """A dated checklist evaluation. History is kept so posture can be tracked over time."""

    asset = models.ForeignKey(Asset, on_delete=models.CASCADE, related_name="assessments")
    assessed_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, null=True, blank=True, on_delete=models.SET_NULL, related_name="+"
    )
    assessed_at = models.DateTimeField(default=timezone.now, db_index=True)
    # Snapshot of every checklist item as answered, so later catalog edits do not rewrite history:
    # [{"item_id": 1, "text": "...", "pillar": "C", "implemented": true}, ...]
    responses = models.JSONField(default=list)
    confidentiality_score = models.DecimalField(**SCORE_FIELD)
    integrity_score = models.DecimalField(**SCORE_FIELD)
    availability_score = models.DecimalField(**SCORE_FIELD)
    security_score = models.DecimalField(max_digits=4, decimal_places=2)
    notes = models.TextField(blank=True)

    class Meta:
        ordering = ["-assessed_at", "-id"]
        get_latest_by = "assessed_at"

    def __str__(self) -> str:
        return f"{self.asset} - {self.security_score} ({self.assessed_at:%Y-%m-%d})"

    @property
    def implemented_count(self) -> int:
        return sum(1 for r in self.responses if r.get("implemented"))
