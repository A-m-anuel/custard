from __future__ import annotations

from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group

from custard.catalog.loader import load_catalog
from custard.catalog.models import AssetCategory
from custard.core import roles
from custard.inventory.models import Asset
from custard.inventory.services import register_asset

PASSWORD = "Test-Password-1234"


class CatalogMixin:
    """Loads the shipped knowledge base and the three role users once per TestCase class."""

    @classmethod
    def setUpTestData(cls):
        load_catalog()
        roles.ensure_roles()
        User = get_user_model()
        cls.admin = User.objects.create_user("admin", password=PASSWORD, is_staff=True)
        cls.admin.groups.add(Group.objects.get(name=roles.ADMINISTRATOR))
        cls.analyst = User.objects.create_user("analyst", password=PASSWORD, email="analyst@example.com")
        cls.analyst.groups.add(Group.objects.get(name=roles.SECURITY_ANALYST))
        cls.viewer = User.objects.create_user("viewer", password=PASSWORD)
        cls.viewer.groups.add(Group.objects.get(name=roles.VIEWER))

    @staticmethod
    def category(name: str) -> AssetCategory:
        return AssetCategory.objects.get(name=name)

    def make_asset(self, name="Asset", category="Operating Systems", implemented=None, actor=None, **kwargs) -> Asset:
        cat = self.category(category)
        asset = Asset(name=name, category=cat, **kwargs)
        items = list(cat.active_checklist())
        ids = None if implemented is None else [i.pk for i in items[:implemented]] if isinstance(implemented, int) \
            else implemented
        register_asset(asset, implemented_item_ids=ids, actor=actor or self.analyst)
        asset.refresh_from_db()
        return asset
