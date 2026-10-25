from django.test import SimpleTestCase

from custard.risk.engine import assess, risk_level

# NIST SP 800-30 (2002) Table 3-6, as published.
NIST_TABLE = {
    ("HIGH", "LOW"): (10, "LOW"), ("HIGH", "MEDIUM"): (50, "MEDIUM"), ("HIGH", "HIGH"): (100, "HIGH"),
    ("MEDIUM", "LOW"): (5, "LOW"), ("MEDIUM", "MEDIUM"): (25, "MEDIUM"), ("MEDIUM", "HIGH"): (50, "MEDIUM"),
    ("LOW", "LOW"): (1, "LOW"), ("LOW", "MEDIUM"): (5, "LOW"), ("LOW", "HIGH"): (10, "LOW"),
}


class NistMatrixTests(SimpleTestCase):
    def test_all_nine_cells_match_nist_table(self):
        for (likelihood, impact), expected in NIST_TABLE.items():
            with self.subTest(likelihood=likelihood, impact=impact):
                self.assertEqual(assess(likelihood, impact), expected)

    def test_scale_boundaries(self):
        # "High (>50 to 100); Medium (>10 to 50); Low (1 to 10)"
        self.assertEqual(risk_level(51), "HIGH")
        self.assertEqual(risk_level(50), "MEDIUM")
        self.assertEqual(risk_level(11), "MEDIUM")
        self.assertEqual(risk_level(10), "LOW")
        self.assertEqual(risk_level(1), "LOW")

    def test_invalid_level(self):
        with self.assertRaises(ValueError):
            assess("EXTREME", "HIGH")
