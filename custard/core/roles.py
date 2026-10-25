"""Role-based access control.

The dissertation names two actors, IT administrators and security analysts (use case diagram,
section 3.4.3). Enterprises also need read-only access for management and auditors, so CuSTaRD
ships three roles as Django groups. Groups are kept in sync after every `migrate` and with
`manage.py sync_roles`. Assign users to a group in the admin site.
"""

from __future__ import annotations

from django.contrib.auth.models import Group, Permission

ADMINISTRATOR = "Administrator"
SECURITY_ANALYST = "Security Analyst"
VIEWER = "Viewer"

_VIEW = [
    "catalog.view_assettype", "catalog.view_assetcategory", "catalog.view_checklistitem",
    "catalog.view_vulnerability", "catalog.view_mitigation", "catalog.view_categoryvulnerability",
    "inventory.view_asset", "inventory.view_assessment",
    "risk.view_assetrisk", "risk.view_risktreatment",
    "reporting.view_report",
]

_ANALYST = _VIEW + [
    "catalog.add_assetcategory", "catalog.change_assetcategory",
    "catalog.add_checklistitem", "catalog.change_checklistitem",
    "catalog.add_vulnerability", "catalog.change_vulnerability",
    "catalog.add_mitigation", "catalog.change_mitigation",
    "catalog.add_categoryvulnerability", "catalog.change_categoryvulnerability",
    "inventory.add_asset", "inventory.change_asset", "inventory.import_assets",
    "inventory.add_assessment",
    "risk.add_assetrisk", "risk.change_assetrisk",
    "risk.add_risktreatment", "risk.change_risktreatment",
    "reporting.generate_report",
]

_ADMINISTRATOR_APPS = ["catalog", "inventory", "risk", "reporting", "core", "api"]
_ADMINISTRATOR_EXTRA = [
    "auth.view_user", "auth.add_user", "auth.change_user", "auth.delete_user",
    "auth.view_group", "auth.change_group",
]

ROLE_PERMISSIONS: dict[str, list[str]] = {VIEWER: _VIEW, SECURITY_ANALYST: _ANALYST}


def _permissions(codes: list[str]) -> list[Permission]:
    perms = []
    for code in codes:
        app_label, codename = code.split(".", 1)
        perm = Permission.objects.filter(content_type__app_label=app_label, codename=codename).first()
        if perm is None:
            raise LookupError(f"Permission {code} does not exist; check roles.py")
        perms.append(perm)
    return perms


def ensure_roles() -> dict[str, int]:
    """Create or update the three role groups. Returns {role: number of permissions}."""
    result = {}
    for role, codes in ROLE_PERMISSIONS.items():
        group, _ = Group.objects.get_or_create(name=role)
        group.permissions.set(_permissions(codes))
        result[role] = len(codes)
    admin_perms = list(Permission.objects.filter(content_type__app_label__in=_ADMINISTRATOR_APPS))
    admin_perms += _permissions(_ADMINISTRATOR_EXTRA)
    group, _ = Group.objects.get_or_create(name=ADMINISTRATOR)
    group.permissions.set(admin_perms)
    result[ADMINISTRATOR] = len(admin_perms)
    return result


def ensure_roles_on_migrate(sender, **kwargs) -> None:
    """post_migrate fires once per app; permissions of later apps do not exist yet on the
    early calls, so keep trying until every referenced permission is present."""
    try:
        ensure_roles()
    except LookupError:
        return
