from django.conf import settings
from django.contrib.auth import get_user_model
from django.core.management.base import BaseCommand, CommandError

from custard.api.models import APIToken
from custard.core import audit
from custard.core.models import AuditEvent


class Command(BaseCommand):
    help = "Issue a read-only API token for a user. The token is printed once and cannot be recovered."

    def add_arguments(self, parser):
        parser.add_argument("username")
        parser.add_argument("name", help="purpose of the token, e.g. 'SIEM integration'")
        parser.add_argument("--days", type=int, default=settings.CUSTARD_API_TOKEN_DEFAULT_DAYS,
                            help="lifetime in days (0 = no expiry)")

    def handle(self, *args, username, name, days, **options):
        user = get_user_model().objects.filter(username=username, is_active=True).first()
        if user is None:
            raise CommandError(f"No active user {username!r}")
        token, raw = APIToken.issue(user, name, days=days or None)
        audit.record(AuditEvent.Action.TOKEN, actor=None, obj=token, changes={"user": username, "days": days})
        self.stdout.write(self.style.SUCCESS(f"Token for {username} ({name}):"))
        self.stdout.write(raw)
        self.stdout.write("Store it now; only its hash is kept. Send it as 'Authorization: Bearer <token>'.")
