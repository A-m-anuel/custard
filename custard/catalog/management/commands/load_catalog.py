from django.core.management.base import BaseCommand, CommandError

from custard.catalog.loader import DEFAULT_CATALOG, CatalogError, load_catalog
from custard.core import audit
from custard.core.models import AuditEvent


class Command(BaseCommand):
    help = "Seed the knowledge base (asset categories, checklists, vulnerabilities, mitigations). Idempotent."

    def add_arguments(self, parser):
        parser.add_argument("path", nargs="?", default=str(DEFAULT_CATALOG), help="catalog JSON file")
        parser.add_argument("--update", action="store_true",
                            help="also overwrite pillars/likelihoods of existing entries with the file's values")

    def handle(self, *args, path, update, **options):
        try:
            result = load_catalog(path, update=update)
        except (OSError, CatalogError, ValueError, KeyError) as exc:
            raise CommandError(f"Could not load catalog: {exc}") from exc
        audit.record(AuditEvent.Action.CATALOG, object_repr=f"catalog {path}"[:255],
                     changes={"result": result.summary()})
        self.stdout.write(self.style.SUCCESS(f"Catalog loaded: {result.summary()}"))
