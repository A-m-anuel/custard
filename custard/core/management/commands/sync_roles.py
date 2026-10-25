from django.core.management.base import BaseCommand

from custard.core.roles import ensure_roles


class Command(BaseCommand):
    help = "Create or update the Administrator, Security Analyst and Viewer groups and their permissions."

    def handle(self, *args, **options):
        for role, count in ensure_roles().items():
            self.stdout.write(f"{role}: {count} permissions")
        self.stdout.write(self.style.SUCCESS("Roles synchronised."))
