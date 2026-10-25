from django.conf import settings
from django.db import models
from django.utils import timezone


class AuditEvent(models.Model):
    """Append-only record of security-relevant actions (who did what, to which object, when)."""

    class Action(models.TextChoices):
        CREATE = "create", "Created"
        UPDATE = "update", "Updated"
        DELETE = "delete", "Deleted"
        ARCHIVE = "archive", "Archived"
        RESTORE = "restore", "Restored"
        ASSESS = "assess", "Assessed"
        ACCEPT = "accept", "Risk accepted"
        IMPORT = "import", "Imported"
        EXPORT = "export", "Exported"
        REPORT = "report", "Report generated"
        DOWNLOAD = "download", "Report downloaded"
        LOGIN = "login", "Signed in"
        LOGIN_FAILED = "login_failed", "Failed sign-in"
        LOGOUT = "logout", "Signed out"
        TOKEN = "token", "API token issued"
        CATALOG = "catalog", "Catalog loaded"

    timestamp = models.DateTimeField(default=timezone.now, db_index=True)
    actor = models.ForeignKey(
        settings.AUTH_USER_MODEL, null=True, blank=True, on_delete=models.SET_NULL, related_name="+"
    )
    actor_repr = models.CharField(max_length=150, blank=True)
    action = models.CharField(max_length=32, choices=Action.choices)
    object_type = models.CharField(max_length=100, blank=True)
    object_id = models.CharField(max_length=64, blank=True)
    object_repr = models.CharField(max_length=255, blank=True)
    changes = models.JSONField(default=dict, blank=True)
    ip_address = models.GenericIPAddressField(null=True, blank=True)

    class Meta:
        ordering = ["-timestamp", "-id"]
        indexes = [models.Index(fields=["object_type", "object_id"], name="core_audit_object_idx")]

    def __str__(self) -> str:
        actor = self.actor_repr or "system"
        return f"{self.timestamp:%Y-%m-%d %H:%M} {actor} {self.get_action_display()} {self.object_repr}"
