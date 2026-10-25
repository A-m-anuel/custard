from django.test import TestCase
from django.urls import reverse

from custard.reporting.models import Report
from custard.reporting.services import generate_report
from custard.risk import graph
from custard.risk.models import AssetRisk

from .helpers import CatalogMixin


class ReportTests(CatalogMixin, TestCase):
    def test_report_tracks_new_and_exposed_assets(self):
        self.make_asset("Weak <b>Printer</b> & Co", "Printer", implemented=1)  # markup must be escaped in the PDF
        first = generate_report(actor=self.analyst)
        self.assertEqual(first.new_assets, ["Weak <b>Printer</b> & Co"])
        self.assertEqual(first.exposed_assets, ["Weak <b>Printer</b> & Co"])
        with first.file.open("rb") as fh:
            content = fh.read()
        self.assertTrue(content.startswith(b"%PDF"))
        import hashlib

        self.assertEqual(hashlib.sha256(content).hexdigest(), first.sha256)

        self.make_asset("Strong Firewall", "Firewalls", implemented=10)
        second = generate_report(actor=self.analyst)
        self.assertEqual(second.new_assets, ["Strong Firewall"])
        self.assertEqual(second.exposed_assets, ["Weak <b>Printer</b> & Co"])

    def test_report_files_are_private(self):
        report = generate_report(actor=self.analyst)
        self.client.force_login(self.viewer)
        response = self.client.get(reverse("report_download", args=[report.pk]))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response["Content-Type"], "application/pdf")
        self.client.logout()
        self.assertEqual(self.client.get(reverse("report_download", args=[report.pk])).status_code, 302)

    def test_generate_via_view(self):
        self.client.force_login(self.analyst)
        self.assertEqual(self.client.get(reverse("report_generate")).status_code, 405)
        self.client.post(reverse("report_generate"))
        self.assertEqual(Report.objects.count(), 1)

    def test_csv_exports(self):
        self.make_asset("=Evil()", "CCTV")
        self.client.force_login(self.viewer)
        assets = self.client.get(reverse("export_assets")).content.decode()
        self.assertIn("'=Evil()", assets)
        risks = self.client.get(reverse("export_risks")).content.decode()
        self.assertIn("Unauthorized Access", risks)


class GraphTests(CatalogMixin, TestCase):
    def test_shared_weaknesses_and_mitigations_collapse(self):
        self.make_asset("Cam 1", "CCTV")
        self.make_asset("Cam 2", "CCTV")
        risks = AssetRisk.objects.select_related("asset__category", "vulnerability").prefetch_related(
            "treatments__mitigation")
        data = graph.build(risks)
        assets = [n for n in data["nodes"].values() if n.column == 0]
        weaknesses = [n for n in data["nodes"].values() if n.column == 1]
        self.assertEqual(len(assets), 2)
        self.assertEqual(len(weaknesses), 4)  # same four CCTV weaknesses, shown once
        svg = graph.render_svg(data)
        self.assertIn("<svg", svg)
        self.assertNotIn("<script", svg)

    def test_labels_escaped(self):
        self.make_asset("<script>alert(1)</script>", "CCTV")
        risks = AssetRisk.objects.select_related("asset__category", "vulnerability").prefetch_related(
            "treatments__mitigation")
        svg = graph.render_svg(graph.build(risks))
        self.assertNotIn("<script>", svg)
        self.assertIn("&lt;script&gt;", svg)

    def test_dependency_view(self):
        self.make_asset("Cam 1", "CCTV")
        self.client.force_login(self.viewer)
        response = self.client.get(reverse("dependency_map"))
        self.assertContains(response, "depgraph")
