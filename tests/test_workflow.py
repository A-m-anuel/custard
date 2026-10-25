import datetime
from decimal import Decimal

from django.test import TestCase
from django.utils import timezone

from custard.catalog.models import Vulnerability
from custard.core.models import AuditEvent
from custard.inventory import services
from custard.risk import services as risk_services
from custard.risk.models import AssetRisk, RiskTreatment

from .helpers import CatalogMixin


class RegistrationTests(CatalogMixin, TestCase):
    def test_registration_maps_category_risks_with_treatments(self):
        asset = self.make_asset("Laptop", "Desktop computers", impact_confidentiality="HIGH")
        risks = {r.vulnerability.name: r for r in asset.risks.all()}
        self.assertEqual(set(risks), {"Unpatched Software", "Weak or No Password Protection",
                                      "Unencrypted Sensitive Data", "Outdated Antivirus/Antimalware"})
        unpatched = risks["Unpatched Software"]
        self.assertEqual(unpatched.likelihood, "HIGH")
        self.assertEqual((unpatched.inherent_score, unpatched.inherent_level), (100, "HIGH"))
        mitigations = set(unpatched.treatments.values_list("mitigation__name", flat=True))
        self.assertIn("Regularly update and patch all software", mitigations)          # category-specific
        self.assertIn("Implement automated patch management systems", mitigations)     # general
        self.assertTrue(AuditEvent.objects.filter(action=AuditEvent.Action.CREATE, object_id=str(asset.pk)).exists())

    def test_assessment_score_computed_server_side(self):
        cat = self.category("Operating Systems")
        items = list(cat.active_checklist())
        asset = self.make_asset("Server", implemented=[items[0].pk, items[1].pk, items[4].pk])
        self.assertEqual(asset.confidentiality_score, Decimal("5.00"))
        self.assertEqual(asset.integrity_score, Decimal("3.33"))
        self.assertEqual(asset.availability_score, Decimal("0.00"))
        self.assertEqual(asset.security_score, Decimal("2.78"))
        self.assertTrue(asset.is_exposed)
        self.assertEqual(asset.assessments.count(), 1)
        self.assertEqual(asset.assessments.first().implemented_count, 3)

    def test_checklist_from_another_category_rejected(self):
        asset = self.make_asset("Server")
        foreign = self.category("CCTV").active_checklist().first()
        with self.assertRaises(services.AssessmentError):
            services.assess(asset, implemented_item_ids=[foreign.pk], actor=self.analyst)

    def test_assessment_history_is_kept(self):
        asset = self.make_asset("Server", implemented=2)
        services.assess(asset, implemented_item_ids=[i.pk for i in asset.category.active_checklist()],
                        actor=self.analyst)
        asset.refresh_from_db()
        self.assertEqual(asset.security_score, Decimal("10.00"))
        self.assertEqual(asset.assessments.count(), 2)

    def test_impact_change_rescores_risks(self):
        asset = self.make_asset("Printer 1", "Printer", impact_confidentiality="LOW", impact_integrity="LOW",
                                impact_availability="LOW")
        risk = asset.risks.get(vulnerability__name="Unauthorized Access")
        self.assertEqual((risk.likelihood, risk.inherent_score), ("MEDIUM", 5))
        original = {f: getattr(asset, f) for f in services.AUDITED_FIELDS}
        original["category"] = str(asset.category)
        asset.impact_confidentiality = "HIGH"
        services.update_asset(asset, original, actor=self.analyst)
        risk.refresh_from_db()
        self.assertEqual((risk.inherent_score, risk.inherent_level), (50, "MEDIUM"))

    def test_category_change_resyncs_but_keeps_worked_risks(self):
        asset = self.make_asset("Box", "Printer")
        worked = asset.risks.get(vulnerability__name="Firmware Vulnerabilities")
        treatment = worked.treatments.first()
        risk_services.update_treatment(treatment, status=RiskTreatment.Status.IN_PROGRESS, actor=self.analyst)
        original = {f: getattr(asset, f) for f in services.AUDITED_FIELDS}
        original["category"] = str(asset.category)
        asset.category = self.category("CCTV")
        services.update_asset(asset, original, actor=self.analyst)
        names = set(asset.risks.values_list("vulnerability__name", flat=True))
        self.assertIn("Firmware Vulnerabilities", names)       # in progress: kept
        self.assertNotIn("Print Job Interception", names)      # untouched printer risk: removed
        self.assertIn("Outdated Firmware", names)              # CCTV risk: added

    def test_sync_is_idempotent(self):
        asset = self.make_asset("Idem")
        self.assertEqual(risk_services.sync_default_risks(asset), {"created": 0, "removed": 0})
        self.assertEqual(asset.risks.count(), 4)


class TreatmentWorkflowTests(CatalogMixin, TestCase):
    def setUp(self):
        self.asset = self.make_asset("FW", "Firewalls", impact_integrity="HIGH")
        self.risk = self.asset.risks.get(vulnerability__name="Misconfigurations")

    def test_progress_moves_status_and_full_implementation_mitigates(self):
        treatments = list(self.risk.treatments.all())
        risk_services.update_treatment(treatments[0], status=RiskTreatment.Status.IN_PROGRESS, actor=self.analyst)
        self.risk.refresh_from_db()
        self.assertEqual(self.risk.status, AssetRisk.Status.IN_TREATMENT)
        for t in treatments:
            risk_services.update_treatment(t, status=RiskTreatment.Status.IMPLEMENTED, actor=self.analyst)
        self.risk.refresh_from_db()
        self.assertEqual(self.risk.status, AssetRisk.Status.MITIGATED)
        self.assertEqual(self.risk.residual_likelihood, "LOW")
        self.assertEqual((self.risk.residual_score, self.risk.residual_level), (10, "LOW"))
        # Reopening one treatment takes the risk back into treatment and clears the residual.
        risk_services.update_treatment(treatments[0], status=RiskTreatment.Status.IN_PROGRESS, actor=self.analyst)
        self.risk.refresh_from_db()
        self.assertEqual(self.risk.status, AssetRisk.Status.IN_TREATMENT)
        self.assertEqual(self.risk.residual_likelihood, "")

    def test_not_applicable_treatments_ignored(self):
        treatments = list(self.risk.treatments.all())
        for t in treatments[1:]:
            risk_services.update_treatment(t, status=RiskTreatment.Status.NOT_APPLICABLE, actor=self.analyst)
        risk_services.update_treatment(treatments[0], status=RiskTreatment.Status.IMPLEMENTED, actor=self.analyst)
        self.risk.refresh_from_db()
        self.assertEqual(self.risk.status, AssetRisk.Status.MITIGATED)

    def test_acceptance_and_reopen(self):
        review = timezone.localdate() + datetime.timedelta(days=90)
        risk_services.accept_risk(self.risk, justification="Compensating network segmentation in place.",
                                  review_date=review, actor=self.admin)
        self.risk.refresh_from_db()
        self.assertEqual(self.risk.status, AssetRisk.Status.ACCEPTED)
        self.assertFalse(self.risk.acceptance_expired)
        # Treatment progress never overrides a formal acceptance.
        risk_services.update_treatment(self.risk.treatments.first(), status=RiskTreatment.Status.IN_PROGRESS,
                                       actor=self.analyst)
        self.risk.refresh_from_db()
        self.assertEqual(self.risk.status, AssetRisk.Status.ACCEPTED)
        risk_services.reopen_risk(self.risk, actor=self.admin)
        self.risk.refresh_from_db()
        self.assertEqual(self.risk.status, AssetRisk.Status.IN_TREATMENT)
        self.assertIsNone(self.risk.accepted_by)

    def test_expired_acceptance_flagged(self):
        self.risk.status = AssetRisk.Status.ACCEPTED
        self.risk.acceptance_review_date = timezone.localdate() - datetime.timedelta(days=1)
        self.risk.save()
        self.assertTrue(self.risk.acceptance_expired)

    def test_manual_risk(self):
        vuln = Vulnerability.objects.create(name="Exposed admin panel")
        risk = risk_services.add_manual_risk(self.asset, vulnerability=vuln, likelihood="HIGH",
                                             mitigations=[risk_services.get_or_create_mitigation("Restrict by IP")],
                                             actor=self.analyst)
        self.assertEqual(risk.source, AssetRisk.Source.MANUAL)
        self.assertEqual(risk.inherent_score, 100)
        self.assertEqual(risk.treatments.count(), 1)
