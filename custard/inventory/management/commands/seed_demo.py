"""Create demonstration data (users, assets, assessments, treatments). Never run this in production."""

import random

from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group
from django.core.management.base import BaseCommand, CommandError

from custard.catalog.models import AssetCategory
from custard.core import roles
from custard.core.choices import Level
from custard.inventory.models import Asset
from custard.inventory.services import register_asset
from custard.risk.models import RiskTreatment
from custard.risk.services import update_treatment

DEMO_ASSETS = [
    # name, category, (C, I, A) impact, share of checklist implemented
    ("Email Servers", "Email Servers and Clients", ("HIGH", "HIGH", "HIGH"), 0.8),
    ("Employee Desktop", "Desktop computers", ("MEDIUM", "MEDIUM", "LOW"), 0.4),
    ("Customer Data", "Customer Data", ("HIGH", "HIGH", "MEDIUM"), 0.7),
    ("Core Router", "Switches/Routers/Hubs", ("MEDIUM", "HIGH", "HIGH"), 0.3),
    ("Perimeter Firewall", "Firewalls", ("MEDIUM", "HIGH", "HIGH"), 0.9),
    ("Finance ERP", "Business Applications", ("HIGH", "HIGH", "MEDIUM"), 0.6),
    ("Payroll Records", "Employee Data", ("HIGH", "MEDIUM", "LOW"), 0.5),
    ("Office Wi-Fi", "Access Points", ("MEDIUM", "LOW", "MEDIUM"), 0.2),
    ("File Server OS", "Operating Systems", ("HIGH", "HIGH", "HIGH"), 0.6),
    ("Reception CCTV", "CCTV", ("LOW", "MEDIUM", "MEDIUM"), 0.3),
    ("Backup Platform", "Backup and Recovery Software", ("HIGH", "HIGH", "HIGH"), 0.9),
    ("Floor 2 Printer", "Printer", ("MEDIUM", "LOW", "LOW"), 0.1),
]


class Command(BaseCommand):
    help = "Load demonstration users and assets (for evaluation and screenshots only)."

    def add_arguments(self, parser):
        parser.add_argument("--password", default=None, help="password for the demo users (required)")

    def handle(self, *args, password, **options):
        if not password or len(password) < 12:
            raise CommandError("Pass --password with at least 12 characters for the demo users.")
        if not AssetCategory.objects.exists():
            raise CommandError("Run `manage.py load_catalog` first.")
        roles.ensure_roles()
        User = get_user_model()
        users = {}
        for username, role, staff in (("admin", roles.ADMINISTRATOR, True), ("analyst", roles.SECURITY_ANALYST, False),
                                      ("viewer", roles.VIEWER, False)):
            user, created = User.objects.get_or_create(username=username, defaults={"is_staff": staff})
            if created:
                user.set_password(password)
                user.save()
            user.groups.add(Group.objects.get(name=role))
            users[username] = user
        rng = random.Random(2023)
        made = 0
        for name, category_name, (c, i, a), share in DEMO_ASSETS:
            if Asset.objects.filter(name=name).exists():
                continue
            category = AssetCategory.objects.get(name=category_name)
            items = list(category.active_checklist())
            chosen = [item.pk for item in items if rng.random() < share]
            asset = Asset(name=name, category=category, owner=users["analyst"], impact_confidentiality=Level(c),
                          impact_integrity=Level(i), impact_availability=Level(a))
            register_asset(asset, implemented_item_ids=chosen, actor=users["analyst"])
            for treatment in RiskTreatment.objects.filter(risk__asset=asset):
                roll = rng.random()
                if roll < share * 0.5:
                    update_treatment(treatment, status=RiskTreatment.Status.IMPLEMENTED, owner=users["analyst"],
                                     actor=users["analyst"])
                elif roll < share:
                    update_treatment(treatment, status=RiskTreatment.Status.IN_PROGRESS, owner=users["analyst"],
                                     actor=users["analyst"])
            made += 1
        self.stdout.write(self.style.SUCCESS(f"Demo data ready: {made} assets; users admin/analyst/viewer."))
