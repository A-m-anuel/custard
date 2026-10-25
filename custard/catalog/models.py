"""Knowledge base: asset taxonomy, CIA security checklists, vulnerabilities and mitigations.

In the 2023 prototype all of this was hard-coded in views.py and a template. It is now data,
seeded by `manage.py load_catalog` and editable by analysts, which addresses the limitation the
dissertation identified: "asset categories are limited to those predefined" (section 4.5, test 6).
"""

from __future__ import annotations

from django.db import models

from custard.core.choices import Level, Pillar


class AssetType(models.Model):
    """Top-level classification (Hardware, Software, Information) - dissertation Table 4."""

    name = models.CharField(max_length=60, unique=True)
    description = models.TextField(blank=True)
    order = models.PositiveSmallIntegerField(default=0)

    class Meta:
        ordering = ["order", "name"]

    def __str__(self) -> str:
        return self.name


class AssetCategory(models.Model):
    asset_type = models.ForeignKey(AssetType, on_delete=models.PROTECT, related_name="categories")
    name = models.CharField(max_length=150, unique=True)
    description = models.TextField(blank=True)
    is_custom = models.BooleanField(default=False, help_text="Created by users rather than shipped with CuSTaRD.")
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["asset_type__order", "asset_type__name", "name"]
        verbose_name_plural = "asset categories"

    def __str__(self) -> str:
        return self.name

    def active_checklist(self):
        return self.checklist_items.filter(is_active=True).order_by("order", "id")


class ChecklistItem(models.Model):
    """One security control check, assigned to a CIA pillar for scoring (dissertation 3.4.4)."""

    category = models.ForeignKey(AssetCategory, on_delete=models.CASCADE, related_name="checklist_items")
    text = models.CharField(max_length=255)
    pillar = models.CharField(max_length=1, choices=Pillar.choices)
    order = models.PositiveSmallIntegerField(default=0)
    guidance = models.TextField(blank=True)
    reference = models.CharField(
        max_length=255, blank=True, help_text="Source standard or vendor guide, e.g. 'CIS Benchmark 1.1.1'."
    )
    is_active = models.BooleanField(default=True)

    class Meta:
        ordering = ["category", "order", "id"]
        constraints = [models.UniqueConstraint(fields=["category", "text"], name="catalog_checklist_unique_text")]

    def __str__(self) -> str:
        return f"{self.category}: {self.text}"


class Mitigation(models.Model):
    name = models.CharField(max_length=255, unique=True)
    description = models.TextField(blank=True)
    reference = models.CharField(
        max_length=255, blank=True, help_text="Control reference, e.g. 'ISO/IEC 27001:2022 A.8.8'."
    )

    class Meta:
        ordering = ["name"]

    def __str__(self) -> str:
        return self.name


class Vulnerability(models.Model):
    name = models.CharField(max_length=150, unique=True)
    description = models.TextField(blank=True)
    reference = models.CharField(max_length=255, blank=True, help_text="e.g. CWE, MITRE ATT&CK or OWASP reference.")
    mitigations = models.ManyToManyField(
        Mitigation, blank=True, related_name="vulnerabilities",
        help_text="General mitigations that apply wherever this weakness occurs.",
    )
    source = models.CharField(max_length=255, blank=True, editable=False)

    class Meta:
        ordering = ["name"]
        verbose_name_plural = "vulnerabilities"

    def __str__(self) -> str:
        return self.name


class CategoryVulnerability(models.Model):
    """Default risk mapping: a weakness typical for a category, with its likelihood (NIST step 5)."""

    category = models.ForeignKey(AssetCategory, on_delete=models.CASCADE, related_name="default_vulnerabilities")
    vulnerability = models.ForeignKey(Vulnerability, on_delete=models.PROTECT, related_name="category_links")
    likelihood = models.CharField(max_length=6, choices=Level.choices, default=Level.MEDIUM)
    mitigations = models.ManyToManyField(
        Mitigation, blank=True, related_name="category_links",
        help_text="Mitigations recommended specifically for this category.",
    )

    class Meta:
        ordering = ["category", "vulnerability__name"]
        verbose_name = "default category vulnerability"
        constraints = [
            models.UniqueConstraint(fields=["category", "vulnerability"], name="catalog_category_vuln_unique")
        ]

    def __str__(self) -> str:
        return f"{self.category} → {self.vulnerability} ({self.get_likelihood_display()})"

    def recommended_mitigations(self) -> list[Mitigation]:
        """Category-specific mitigations first, then the weakness's general ones, without duplicates."""
        seen, result = set(), []
        for mitigation in list(self.mitigations.all()) + list(self.vulnerability.mitigations.all()):
            if mitigation.pk not in seen:
                seen.add(mitigation.pk)
                result.append(mitigation)
        return result
