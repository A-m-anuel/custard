import json
import tempfile

from django.core.management import call_command
from django.test import TestCase

from custard.catalog.loader import CatalogError, load_catalog
from custard.catalog.models import AssetCategory, CategoryVulnerability, ChecklistItem, Mitigation, Vulnerability


class CatalogLoadTests(TestCase):
    def test_full_prototype_knowledge_base_is_loaded(self):
        load_catalog()
        self.assertEqual(AssetCategory.objects.count(), 29)
        self.assertEqual(ChecklistItem.objects.count(), 290)
        self.assertEqual(CategoryVulnerability.objects.count(), 116)
        self.assertEqual(Mitigation.objects.count(), 268)
        for category in AssetCategory.objects.all():
            self.assertEqual(category.default_vulnerabilities.count(), 4, category.name)
            pillars = list(category.active_checklist().values_list("pillar", flat=True))
            self.assertEqual(pillars, ["C"] * 4 + ["I"] * 3 + ["A"] * 3, category.name)

    def test_prototype_firewall_naming_bug_is_fixed(self):
        # The prototype keyed the risk mapping as "Firewall" but offered "Firewalls" in the form,
        # so firewalls never received risks. They must have their four mappings now.
        load_catalog()
        names = set(AssetCategory.objects.get(name="Firewalls").default_vulnerabilities
                    .values_list("vulnerability__name", flat=True))
        self.assertEqual(names, {"Misconfigurations", "Unauthorized Access", "Outdated Rulesets", "Bypass Attacks"})

    def test_mitigation_with_comma_inside_parentheses_kept_whole(self):
        load_catalog()
        self.assertTrue(Mitigation.objects.filter(name="Secure protocols (e.g., SSH, SFTP)").exists())

    def test_idempotent_and_preserves_local_edits(self):
        load_catalog()
        link = CategoryVulnerability.objects.first()
        link.likelihood = "LOW" if link.likelihood != "LOW" else "HIGH"
        link.save()
        result = load_catalog()
        self.assertEqual(result.created, {})
        link.refresh_from_db()
        self.assertIn(link.likelihood, ("LOW", "HIGH"))
        self.assertEqual(Vulnerability.objects.filter(name=link.vulnerability.name).count(), 1)

    def test_invalid_file_rejected(self):
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as fh:
            json.dump({"asset_types": [{"name": "T", "categories": [
                {"name": "C", "checklist": [{"text": "x", "pillar": "Z"}], "vulnerabilities": []}]}],
                "vulnerabilities": []}, fh)
        with self.assertRaises(CatalogError):
            load_catalog(fh.name)
        self.assertFalse(AssetCategory.objects.exists())

    def test_management_command(self):
        call_command("load_catalog", verbosity=0)
        self.assertEqual(AssetCategory.objects.count(), 29)
