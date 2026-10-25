"""Bulk asset import from CSV - the migration path away from risk spreadsheets (dissertation 1.1).

Expected header (case-insensitive; only name and category are required):
    name,category,description,owner,location,confidentiality_impact,integrity_impact,availability_impact
owner is a username or e-mail address. Impacts are High, Medium or Low (default Medium).
"""

from __future__ import annotations

import csv
import io
from dataclasses import dataclass, field

from django.contrib.auth import get_user_model
from django.db import transaction
from django.db.models import Q

from custard.catalog.models import AssetCategory
from custard.core import audit
from custard.core.choices import Level
from custard.core.models import AuditEvent

from .models import Asset
from .services import register_asset

MAX_ROWS = 5000
REQUIRED = ("name", "category")
OPTIONAL = ("description", "owner", "location", "confidentiality_impact", "integrity_impact", "availability_impact")
TEMPLATE_HEADER = list(REQUIRED + OPTIONAL)


@dataclass
class ImportResult:
    created: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.errors


def _level(value: str, row: int, column: str, errors: list[str]) -> str:
    value = (value or "").strip()
    if not value:
        return Level.MEDIUM
    for level in Level:
        if value.lower() == level.label.lower() or value.upper() == level.value:
            return level.value
    errors.append(f"Row {row}: {column} must be High, Medium or Low (got {value!r}).")
    return Level.MEDIUM


def parse_and_import(uploaded_file, *, actor=None, request=None, dry_run: bool = False) -> ImportResult:
    result = ImportResult()
    try:
        text = uploaded_file.read().decode("utf-8-sig")
    except UnicodeDecodeError:
        result.errors.append("The file must be UTF-8 encoded CSV.")
        return result
    reader = csv.DictReader(io.StringIO(text))
    if reader.fieldnames is None:
        result.errors.append("The file is empty.")
        return result
    header = {h.strip().lower(): h for h in reader.fieldnames if h}
    missing = [c for c in REQUIRED if c not in header]
    if missing:
        result.errors.append(f"Missing required column(s): {', '.join(missing)}.")
        return result

    categories = {c.name.lower(): c for c in AssetCategory.objects.filter(is_active=True)}
    existing = {n.lower() for n in Asset.objects.values_list("name", flat=True)}
    User = get_user_model()
    pending: list[Asset] = []
    seen: set[str] = set()

    for row_number, raw in enumerate(reader, start=2):
        if row_number - 1 > MAX_ROWS:
            result.errors.append(f"Too many rows; the limit is {MAX_ROWS}.")
            break
        row = {key: (raw.get(original) or "").strip() for key, original in header.items()}
        if not any(row.values()):
            continue
        name, category_name = row.get("name", ""), row.get("category", "")
        if not name:
            result.errors.append(f"Row {row_number}: name is required.")
            continue
        if len(name) > 200:
            result.errors.append(f"Row {row_number}: name is longer than 200 characters.")
            continue
        if name.lower() in existing or name.lower() in seen:
            result.errors.append(f"Row {row_number}: an asset named {name!r} already exists.")
            continue
        category = categories.get(category_name.lower())
        if category is None:
            result.errors.append(f"Row {row_number}: unknown category {category_name!r}.")
            continue
        owner = None
        if row.get("owner"):
            owner = User.objects.filter(Q(username__iexact=row["owner"]) | Q(email__iexact=row["owner"])).first()
            if owner is None:
                result.errors.append(f"Row {row_number}: no user matches owner {row['owner']!r}.")
                continue
        asset = Asset(
            name=name, category=category, description=row.get("description", ""), owner=owner,
            location=row.get("location", "")[:200],
            impact_confidentiality=_level(row.get("confidentiality_impact"), row_number, "confidentiality_impact",
                                          result.errors),
            impact_integrity=_level(row.get("integrity_impact"), row_number, "integrity_impact", result.errors),
            impact_availability=_level(row.get("availability_impact"), row_number, "availability_impact",
                                       result.errors),
        )
        seen.add(name.lower())
        pending.append(asset)

    if result.errors or dry_run:
        return result  # all-or-nothing: nothing is written if any row is invalid
    with transaction.atomic():
        for asset in pending:
            register_asset(asset, actor=actor, request=request)
            result.created.append(asset.name)
        audit.record(AuditEvent.Action.IMPORT, request=request, actor=actor,
                     object_repr=f"{len(result.created)} assets from CSV", changes={"assets": result.created[:100]})
    return result
