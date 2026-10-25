import datetime

from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import TestCase
from django.urls import reverse
from django.utils import timezone

from custard.api.models import APIToken
from custard.inventory.models import Asset

from .helpers import CatalogMixin

HEADER = "name,category,description,owner,location,confidentiality_impact,integrity_impact,availability_impact\n"


def csv_file(body: str) -> SimpleUploadedFile:
    return SimpleUploadedFile("assets.csv", (HEADER + body).encode("utf-8"), content_type="text/csv")


class ImportTests(CatalogMixin, TestCase):
    def setUp(self):
        self.client.force_login(self.analyst)

    def test_valid_import_maps_risks(self):
        body = "Mail,Email Servers and Clients,,analyst@example.com,Cloud,High,High,Medium\n" \
               "Laptop 7,desktop computers,,,,,,\n"
        response = self.client.post(reverse("asset_import"), {"file": csv_file(body)})
        self.assertRedirects(response, reverse("asset_list"))
        mail = Asset.objects.get(name="Mail")
        self.assertEqual((mail.owner, mail.impact_confidentiality), (self.analyst, "HIGH"))
        self.assertEqual(mail.risks.count(), 4)
        self.assertEqual(Asset.objects.get(name="Laptop 7").impact_availability, "MEDIUM")

    def test_invalid_rows_import_nothing(self):
        body = "Good,CCTV,,,,,,\nBad,Unknown Category,,,,,,\nWorse,CCTV,,,,Extreme,,\n"
        response = self.client.post(reverse("asset_import"), {"file": csv_file(body)})
        self.assertContains(response, "unknown category")
        self.assertContains(response, "must be High, Medium or Low")
        self.assertFalse(Asset.objects.exists())

    def test_dry_run_writes_nothing(self):
        response = self.client.post(reverse("asset_import"), {"file": csv_file("Good,CCTV,,,,,,\n"), "dry_run": "on"})
        self.assertContains(response, "The file is valid")
        self.assertFalse(Asset.objects.exists())

    def test_duplicates_rejected(self):
        self.make_asset("Existing", "CCTV")
        response = self.client.post(reverse("asset_import"), {"file": csv_file("existing,CCTV,,,,,,\n")})
        self.assertContains(response, "already exists")

    def test_viewer_cannot_import(self):
        self.client.force_login(self.viewer)
        self.assertEqual(self.client.get(reverse("asset_import")).status_code, 403)


class ApiTests(CatalogMixin, TestCase):
    def setUp(self):
        self.asset = self.make_asset("Core Router", "Switches/Routers/Hubs", implemented=2)
        self.token, self.raw = APIToken.issue(self.viewer, "SIEM")

    def get(self, url, token=None):
        headers = {"HTTP_AUTHORIZATION": f"Bearer {token}"} if token else {}
        return self.client.get(url, **headers)

    def test_requires_authentication(self):
        response = self.get(reverse("api_assets"))
        self.assertEqual(response.status_code, 401)
        self.assertIn("Bearer", response["WWW-Authenticate"])

    def test_token_access(self):
        data = self.get(reverse("api_assets"), self.raw).json()
        self.assertEqual(data["count"], 1)
        item = data["results"][0]
        self.assertEqual((item["name"], item["exposed"]), ("Core Router", True))
        detail = self.get(reverse("api_asset_detail", args=[self.asset.pk]), self.raw).json()
        self.assertEqual(len(detail["risks"]), 4)
        risks = self.get(reverse("api_risks") + "?level=high", self.raw).json()
        self.assertTrue(all(r["inherent_level"] == "HIGH" for r in risks["results"]))
        self.token.refresh_from_db()
        self.assertIsNotNone(self.token.last_used_at)

    def test_only_hash_stored(self):
        self.assertNotIn(self.raw, self.token.token_hash)
        self.assertEqual(len(self.token.token_hash), 64)

    def test_revoked_and_expired_tokens_rejected(self):
        self.token.revoked = True
        self.token.save()
        self.assertEqual(self.get(reverse("api_summary"), self.raw).status_code, 401)
        token, raw = APIToken.issue(self.viewer, "old")
        token.expires_at = timezone.now() - datetime.timedelta(seconds=1)
        token.save()
        self.assertEqual(self.get(reverse("api_summary"), raw).status_code, 401)
        self.assertEqual(self.get(reverse("api_summary"), "cst_not-a-real-token").status_code, 401)

    def test_permission_enforced(self):
        from django.contrib.auth import get_user_model

        nobody = get_user_model().objects.create_user("nobody")
        _, raw = APIToken.issue(nobody, "x")
        self.assertEqual(self.get(reverse("api_summary"), raw).status_code, 403)

    def test_read_only(self):
        response = self.client.post(reverse("api_assets"), HTTP_AUTHORIZATION=f"Bearer {self.raw}")
        self.assertEqual(response.status_code, 405)

    def test_summary(self):
        data = self.get(reverse("api_summary"), self.raw).json()
        self.assertEqual(data["total_assets"], 1)
        self.assertEqual(data["exposure_threshold"], 5.0)
