import datetime

from django.test import TestCase
from django.urls import reverse
from django.utils import timezone

from custard.catalog.models import AssetCategory
from custard.inventory.models import Asset
from custard.risk.models import AssetRisk

from .helpers import PASSWORD, CatalogMixin


class AccessControlTests(CatalogMixin, TestCase):
    def setUp(self):
        self.asset = self.make_asset("Mail", "Email Servers and Clients")
        self.risk = self.asset.risks.first()

    def login(self, user):
        self.client.force_login(user)

    def test_every_page_requires_login(self):
        # The prototype served the asset list, dashboard, reports and files without authentication.
        for url in [reverse("dashboard"), reverse("asset_list"), reverse("asset_detail", args=[self.asset.pk]),
                    reverse("risk_list"), reverse("dependency_map"), reverse("report_list"),
                    reverse("export_assets"), reverse("catalog_index")]:
            response = self.client.get(url)
            self.assertEqual(response.status_code, 302, url)
            self.assertIn(reverse("login"), response["Location"])

    def test_user_without_role_is_denied(self):
        from django.contrib.auth import get_user_model

        nobody = get_user_model().objects.create_user("nobody", password=PASSWORD)
        self.login(nobody)
        self.assertEqual(self.client.get(reverse("asset_list")).status_code, 403)

    def test_viewer_is_read_only(self):
        self.login(self.viewer)
        self.assertEqual(self.client.get(reverse("asset_detail", args=[self.asset.pk])).status_code, 200)
        self.assertEqual(self.client.get(reverse("asset_create")).status_code, 403)
        self.assertEqual(self.client.post(reverse("report_generate")).status_code, 403)
        self.assertEqual(self.client.get(reverse("audit_log")).status_code, 403)
        response = self.client.post(reverse("risk_detail", args=[self.risk.pk]), {"likelihood": "LOW"})
        self.assertEqual(response.status_code, 302)
        self.risk.refresh_from_db()
        self.assertNotEqual(self.risk.likelihood, "LOW")

    def test_only_administrators_accept_risk(self):
        data = {"justification": "Business accepts this for the pilot period only.",
                "review_date": (timezone.localdate() + datetime.timedelta(days=30)).isoformat()}
        self.login(self.analyst)
        self.assertEqual(self.client.post(reverse("risk_accept", args=[self.risk.pk]), data).status_code, 403)
        self.login(self.admin)
        self.client.post(reverse("risk_accept", args=[self.risk.pk]), data)
        self.risk.refresh_from_db()
        self.assertEqual(self.risk.status, AssetRisk.Status.ACCEPTED)

    def test_acceptance_review_date_capped_at_one_year(self):
        self.login(self.admin)
        data = {"justification": "Long-term acceptance that should be rejected.",
                "review_date": (timezone.localdate() + datetime.timedelta(days=500)).isoformat()}
        self.client.post(reverse("risk_accept", args=[self.risk.pk]), data)
        self.risk.refresh_from_db()
        self.assertNotEqual(self.risk.status, AssetRisk.Status.ACCEPTED)

    def test_logout_requires_post(self):
        self.login(self.viewer)
        self.assertEqual(self.client.get(reverse("logout")).status_code, 405)
        self.assertEqual(self.client.post(reverse("logout")).status_code, 302)

    def test_prototype_unauthenticated_file_route_is_gone(self):
        # Prototype: /protected_media/<path> served any file, unauthenticated, with path traversal.
        self.login(self.admin)
        self.assertEqual(self.client.get("/protected_media/../../config/settings.py").status_code, 404)


class RegistrationViewTests(CatalogMixin, TestCase):
    def setUp(self):
        self.client.force_login(self.analyst)
        self.cat = AssetCategory.objects.get(name="Email Servers and Clients")
        self.items = list(self.cat.active_checklist())

    def post(self, **extra):
        data = {"name": "Email Servers", "category": self.cat.pk, "impact_confidentiality": "HIGH",
                "impact_integrity": "HIGH", "impact_availability": "MEDIUM", "checklist_submitted": "1",
                "checklist": [str(self.items[0].pk), str(self.items[4].pk)]}
        data.update(extra)
        return self.client.post(reverse("asset_create"), data)

    def test_register_with_checklist(self):
        # Dissertation test 1.1
        response = self.post()
        asset = Asset.objects.get(name="Email Servers")
        self.assertRedirects(response, asset.get_absolute_url())
        self.assertEqual(str(asset.security_score), "1.94")  # C 2.5, I 3.33, A 0 -> 1.94
        self.assertEqual(asset.risks.count(), 4)
        self.assertEqual(asset.created_by, self.analyst)

    def test_client_supplied_score_is_ignored(self):
        # The prototype stored request.POST['score'] verbatim.
        self.post(score="10", security_score="10")
        self.assertEqual(str(Asset.objects.get(name="Email Servers").security_score), "1.94")

    def test_duplicate_name_rejected_case_insensitively(self):
        # Dissertation test 1.2
        self.post()
        response = self.post(name="email servers")
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "already exists")
        self.assertEqual(Asset.objects.count(), 1)

    def test_category_required(self):
        # Dissertation test 2.2
        response = self.post(category="")
        self.assertEqual(response.status_code, 200)
        self.assertFalse(Asset.objects.exists())

    def test_checklist_of_other_category_rejected(self):
        other = AssetCategory.objects.get(name="CCTV").active_checklist().first()
        response = self.post(checklist=[str(other.pk)])
        self.assertEqual(response.status_code, 200)
        self.assertFalse(Asset.objects.exists())

    def test_without_checklist_redirects_to_assessment(self):
        response = self.post(checklist_submitted="0", checklist=[])
        asset = Asset.objects.get(name="Email Servers")
        self.assertRedirects(response, reverse("asset_assess", args=[asset.pk]))
        self.assertIsNone(asset.security_score)

    def test_reassessment_page(self):
        self.post()
        asset = Asset.objects.get()
        response = self.client.post(reverse("asset_assess", args=[asset.pk]),
                                    {"checklist": [str(i.pk) for i in self.items]})
        self.assertRedirects(response, asset.get_absolute_url())
        asset.refresh_from_db()
        self.assertEqual(str(asset.security_score), "10.00")


class CustomCategoryTests(CatalogMixin, TestCase):
    def test_user_can_add_category(self):
        # Dissertation test 6 ("Websites and domains") failed in the prototype.
        self.client.force_login(self.analyst)
        response = self.client.post(reverse("category_create"), {
            "asset_type": AssetCategory.objects.get(name="Application Software").asset_type_id,
            "name": "Websites and domains", "confidentiality": "TLS everywhere\nHSTS enabled",
            "integrity": "DNSSEC", "availability": "",
        })
        category = AssetCategory.objects.get(name="Websites and domains")
        self.assertRedirects(response, reverse("category_detail", args=[category.pk]))
        self.assertTrue(category.is_custom)
        self.assertEqual(list(category.active_checklist().values_list("pillar", flat=True)), ["C", "C", "I"])
        self.client.post(reverse("default_vulnerability_add", args=[category.pk]),
                         {"new_vulnerability": "Domain hijacking", "likelihood": "MEDIUM",
                          "mitigations": "Registrar lock\nMFA on registrar account"})
        asset = self.make_asset("example.com", "Websites and domains", implemented=2)
        self.assertEqual(str(asset.security_score), "5.00")  # C 10, I 0, A n/a
        self.assertEqual(asset.risks.get().treatments.count(), 2)

    def test_viewer_cannot_add_category(self):
        self.client.force_login(self.viewer)
        self.assertEqual(self.client.get(reverse("category_create")).status_code, 403)


class SecurityHeaderTests(CatalogMixin, TestCase):
    def test_headers(self):
        self.client.force_login(self.viewer)
        response = self.client.get(reverse("dashboard"))
        self.assertEqual(response["X-Content-Type-Options"], "nosniff")  # the dissertation's ZAP finding
        self.assertEqual(response["X-Frame-Options"], "DENY")
        self.assertIn("script-src 'self'", response["Content-Security-Policy"])
        self.assertNotIn("unsafe-inline", response["Content-Security-Policy"])
        self.assertEqual(response["Cache-Control"], "no-store")

    def test_healthz(self):
        response = self.client.get(reverse("healthz"))
        self.assertEqual(response.json(), {"status": "ok"})


class UrlProtectionTests(CatalogMixin, TestCase):
    """Every URL except sign-in and the health check must reject anonymous users."""

    PUBLIC = {"login", "healthz"}

    def test_no_view_is_accidentally_public(self):
        from django.urls import get_resolver

        asset = self.make_asset("Probe", "CCTV")
        kwargs_for = {"pk": asset.pk, "asset_pk": asset.pk}
        checked = 0
        for pattern in get_resolver().url_patterns:
            for name, url in _named_urls(pattern, kwargs_for):
                if name in self.PUBLIC or url.startswith("/admin"):
                    continue
                for method in ("get", "post"):
                    status = getattr(self.client, method)(url).status_code
                    self.assertIn(status, (302, 401, 405), f"{method.upper()} {url} returned {status}")
                checked += 1
        self.assertGreater(checked, 25)


def _named_urls(pattern, kwargs_for, prefix=""):
    from django.urls import URLPattern, URLResolver, reverse

    if isinstance(pattern, URLResolver):
        if pattern.app_name == "admin":
            return
        for sub in pattern.url_patterns:
            yield from _named_urls(sub, kwargs_for, prefix)
    elif isinstance(pattern, URLPattern) and pattern.name:
        params = {k: kwargs_for[k] for k in pattern.pattern.converters}
        yield pattern.name, reverse(pattern.name, kwargs=params)
