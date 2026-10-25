from django.core.cache import cache
from django.test import SimpleTestCase, TestCase, override_settings
from django.urls import reverse

from config.settings import parse_database_url
from custard.core.csvutil import rows_to_csv, safe_cell
from custard.core.models import AuditEvent

from .helpers import PASSWORD, CatalogMixin


@override_settings(CUSTARD_LOGIN_MAX_ATTEMPTS=3)
class LoginThrottleTests(CatalogMixin, TestCase):
    def setUp(self):
        cache.clear()

    def attempt(self, password):
        return self.client.post(reverse("login"), {"username": "viewer", "password": password})

    def test_lockout_after_repeated_failures(self):
        for _ in range(3):
            self.assertEqual(self.attempt("wrong-password").status_code, 200)
        response = self.attempt(PASSWORD)  # correct password, but locked out
        self.assertContains(response, "Too many failed sign-in attempts")
        self.assertNotIn("_auth_user_id", self.client.session)
        self.assertEqual(AuditEvent.objects.filter(action=AuditEvent.Action.LOGIN_FAILED).count(), 3)

    def test_success_resets_counter(self):
        self.attempt("wrong-password")
        response = self.attempt(PASSWORD)
        self.assertRedirects(response, reverse("dashboard"))
        self.assertTrue(AuditEvent.objects.filter(action=AuditEvent.Action.LOGIN, actor=self.viewer).exists())


class CsvInjectionTests(SimpleTestCase):
    def test_formula_prefixes_neutralised(self):
        for value in ("=HYPERLINK(\"http://x\")", "+1+1", "-2+3", "@SUM(A1)"):
            self.assertTrue(safe_cell(value).startswith("'"), value)
        self.assertEqual(safe_cell("Mail server"), "Mail server")
        self.assertIn("'=cmd", rows_to_csv(["a"], [["=cmd"]]))


class DatabaseUrlTests(SimpleTestCase):
    def test_postgres(self):
        cfg = parse_database_url("postgres://user:p%40ss@db.internal:5433/custard")
        self.assertEqual((cfg["ENGINE"], cfg["NAME"], cfg["USER"], cfg["PASSWORD"], cfg["HOST"], cfg["PORT"]),
                         ("django.db.backends.postgresql", "custard", "user", "p@ss", "db.internal", "5433"))

    def test_sqlite(self):
        self.assertTrue(parse_database_url("sqlite:///data/custard.db")["NAME"].endswith("data/custard.db"))
        self.assertEqual(parse_database_url("sqlite:////var/lib/custard.db")["NAME"], "/var/lib/custard.db")

    def test_unsupported(self):
        from django.core.exceptions import ImproperlyConfigured

        with self.assertRaises(ImproperlyConfigured):
            parse_database_url("mysql://x")
