"""Load the knowledge base from JSON (the dissertation's "data seeding" step, section 3.4.4)."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

from django.db import transaction

from custard.core.choices import Level, Pillar

from .models import AssetCategory, AssetType, CategoryVulnerability, ChecklistItem, Mitigation, Vulnerability

DEFAULT_CATALOG = Path(__file__).resolve().parent / "data" / "catalog.json"


@dataclass
class LoadResult:
    created: dict[str, int] = field(default_factory=dict)
    updated: dict[str, int] = field(default_factory=dict)

    def bump(self, bucket: str, model: str) -> None:
        target = self.created if bucket == "created" else self.updated
        target[model] = target.get(model, 0) + 1

    def summary(self) -> str:
        made = ", ".join(f"{v} {k}" for k, v in sorted(self.created.items())) or "nothing new"
        upd = ", ".join(f"{v} {k}" for k, v in sorted(self.updated.items()))
        return f"created {made}" + (f"; updated {upd}" if upd else "")


class CatalogError(ValueError):
    pass


def _validate(data: dict) -> None:
    if not isinstance(data.get("asset_types"), list) or not isinstance(data.get("vulnerabilities"), list):
        raise CatalogError("catalog must contain 'asset_types' and 'vulnerabilities' lists")
    for t in data["asset_types"]:
        for c in t.get("categories", []):
            for item in c.get("checklist", []):
                if item.get("pillar") not in Pillar.values:
                    raise CatalogError(f"{c.get('name')}: invalid pillar {item.get('pillar')!r}")
            for v in c.get("vulnerabilities", []):
                if v.get("likelihood") not in Level.values:
                    raise CatalogError(f"{c.get('name')}: invalid likelihood {v.get('likelihood')!r}")


@transaction.atomic
def load_catalog(path: Path | str = DEFAULT_CATALOG, *, update: bool = False) -> LoadResult:
    """Create missing catalog entries. Existing rows are left untouched unless update=True,
    so local edits made by analysts survive a re-run."""
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    _validate(data)
    result = LoadResult()

    def mitigation(name: str) -> Mitigation:
        obj, created = Mitigation.objects.get_or_create(name=name.strip()[:255])
        if created:
            result.bump("created", "mitigations")
        return obj

    for entry in data["vulnerabilities"]:
        vuln, created = Vulnerability.objects.get_or_create(
            name=entry["name"].strip(), defaults={"source": entry.get("source", "")[:255]}
        )
        if created:
            result.bump("created", "vulnerabilities")
        if created or update:
            vuln.mitigations.add(*[mitigation(m) for m in entry.get("mitigations", [])])

    for t_order, t in enumerate(data["asset_types"]):
        asset_type, created = AssetType.objects.get_or_create(name=t["name"], defaults={"order": t_order})
        if created:
            result.bump("created", "asset types")
        for c in t.get("categories", []):
            category, created = AssetCategory.objects.get_or_create(
                name=c["name"], defaults={"asset_type": asset_type, "description": c.get("description", "")}
            )
            if created:
                result.bump("created", "categories")
            for order, item in enumerate(c.get("checklist", [])):
                obj, made = ChecklistItem.objects.get_or_create(
                    category=category, text=item["text"], defaults={"pillar": item["pillar"], "order": order}
                )
                if made:
                    result.bump("created", "checklist items")
                elif update and (obj.pillar, obj.order) != (item["pillar"], order):
                    obj.pillar, obj.order = item["pillar"], order
                    obj.save(update_fields=["pillar", "order"])
                    result.bump("updated", "checklist items")
            for v in c.get("vulnerabilities", []):
                vuln, _ = Vulnerability.objects.get_or_create(name=v["name"].strip())
                link, made = CategoryVulnerability.objects.get_or_create(
                    category=category, vulnerability=vuln, defaults={"likelihood": v["likelihood"]}
                )
                if made:
                    result.bump("created", "default risk mappings")
                elif update and link.likelihood != v["likelihood"]:
                    link.likelihood = v["likelihood"]
                    link.save(update_fields=["likelihood"])
                    result.bump("updated", "default risk mappings")
                if made or update:
                    link.mitigations.add(*[mitigation(m) for m in v.get("mitigations", [])])
    return result
