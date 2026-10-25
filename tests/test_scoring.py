from decimal import Decimal

from django.test import SimpleTestCase

from custard.inventory.scoring import NoChecklistError, calculate


def responses(c, i, a):
    """c/i/a = (implemented, total) per pillar."""
    out = []
    for pillar, (done, total) in (("C", c), ("I", i), ("A", a)):
        out += [(pillar, n < done) for n in range(total)]
    return out


class ScoringTests(SimpleTestCase):
    def test_dissertation_example_two_of_four(self):
        # Dissertation 3.4.4: "if 2 of 4 confidentiality checklists are selected ... (2/4) * 10 = 5"
        result = calculate(responses((2, 4), (0, 3), (0, 3)))
        self.assertEqual(result.confidentiality, Decimal("5.00"))

    def test_overall_is_cia_sum_over_30_times_10(self):
        result = calculate(responses((2, 4), (1, 3), (0, 3)))
        expected = (Decimal(5) + Decimal(10) / 3 + 0) / 30 * 10
        self.assertEqual(result.overall, expected.quantize(Decimal("0.01")))
        self.assertEqual(result.overall, Decimal("2.78"))

    def test_all_and_nothing(self):
        self.assertEqual(calculate(responses((4, 4), (3, 3), (3, 3))).overall, Decimal("10.00"))
        self.assertEqual(calculate(responses((0, 4), (0, 3), (0, 3))).overall, Decimal("0.00"))

    def test_pillars_weigh_equally_not_items(self):
        # 4/4 confidentiality only: C=10, I=0, A=0 -> 3.33 (an item-count average would give 4.0)
        self.assertEqual(calculate(responses((4, 4), (0, 3), (0, 3))).overall, Decimal("3.33"))

    def test_missing_pillar_is_not_applicable(self):
        result = calculate(responses((1, 2), (0, 0), (1, 1)))
        self.assertIsNone(result.integrity)
        self.assertEqual(result.overall, Decimal("7.50"))

    def test_rounding_happens_once_at_the_end(self):
        result = calculate(responses((1, 3), (1, 3), (1, 3)))
        self.assertEqual(result.overall, Decimal("3.33"))
        self.assertEqual(calculate(responses((2, 3), (2, 3), (2, 3))).overall, Decimal("6.67"))

    def test_no_items_raises(self):
        with self.assertRaises(NoChecklistError):
            calculate([])

    def test_unknown_pillar_rejected(self):
        with self.assertRaises(ValueError):
            calculate([("X", True)])
