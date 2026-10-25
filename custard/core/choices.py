"""Shared vocabularies.

Likelihood and impact follow NIST SP 800-30 (Stoneburner, Goguen & Feringa, 2002), section 3.7:
"The probability assigned for each threat likelihood level is 1.0 for High, 0.5 for Medium,
0.1 for Low" and "The value assigned for each impact level is 100 for High, 50 for Medium,
and 10 for Low" (Table 3-6, Risk-Level Matrix).
"""

from django.db import models


class Level(models.TextChoices):
    HIGH = "HIGH", "High"
    MEDIUM = "MEDIUM", "Medium"
    LOW = "LOW", "Low"


class Pillar(models.TextChoices):
    CONFIDENTIALITY = "C", "Confidentiality"
    INTEGRITY = "I", "Integrity"
    AVAILABILITY = "A", "Availability"


LEVEL_ORDER = {Level.LOW: 1, Level.MEDIUM: 2, Level.HIGH: 3}
