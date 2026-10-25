from django.conf import settings
from django.core.files.storage import FileSystemStorage
from django.db import models
from django.urls import reverse
from django.utils import timezone


def private_storage():
    """Reports are stored outside every web-served directory and returned only by the download view."""
    return FileSystemStorage(location=settings.CUSTARD_PRIVATE_STORAGE_ROOT, base_url=None)


class Report(models.Model):
    """A generated PDF report, tracked for administrators (dissertation Figure 39/40)."""

    created_at = models.DateTimeField(default=timezone.now, db_index=True)
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, null=True, blank=True, on_delete=models.SET_NULL, related_name="+"
    )
    title = models.CharField(max_length=200)
    file = models.FileField(storage=private_storage, upload_to="reports/%Y/%m/", max_length=255)
    sha256 = models.CharField(max_length=64, editable=False)
    size_bytes = models.PositiveIntegerField(default=0, editable=False)
    new_assets = models.JSONField(default=list, blank=True, help_text="Assets registered since the previous report.")
    exposed_assets = models.JSONField(default=list, blank=True, help_text="Assets below the exposure threshold.")
    summary = models.JSONField(default=dict, blank=True)

    class Meta:
        ordering = ["-created_at", "-id"]
        get_latest_by = "created_at"
        permissions = [("generate_report", "Can generate reports")]

    def __str__(self) -> str:
        return self.title

    def get_download_url(self) -> str:
        return reverse("report_download", args=[self.pk])
