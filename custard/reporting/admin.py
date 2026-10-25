from django.contrib import admin
from django.utils.html import format_html, format_html_join
from django.utils.safestring import mark_safe

from .models import Report


@admin.register(Report)
class ReportAdmin(admin.ModelAdmin):
    """Administrator report tracking (dissertation Figure 39): new and exposed assets per report."""

    list_display = ("title", "created_at", "created_by", "new_assets_column", "exposed_assets_column", "download")
    list_filter = ("created_at",)
    search_fields = ("title",)
    readonly_fields = ("title", "created_at", "created_by", "file", "sha256", "size_bytes", "new_assets",
                       "exposed_assets", "summary")

    def has_add_permission(self, request):
        return False  # reports are generated from the application

    @admin.display(description="New assets")
    def new_assets_column(self, obj):
        return format_html_join(mark_safe("<br>"), "{}", ((n,) for n in obj.new_assets)) or "-"  # nosec B308 B703 - constant markup

    @admin.display(description="Exposed assets")
    def exposed_assets_column(self, obj):
        return format_html_join(mark_safe("<br>"), "{}", ((n,) for n in obj.exposed_assets)) or "-"  # nosec B308 B703 - constant markup

    @admin.display(description="File")
    def download(self, obj):
        return format_html('<a href="{}">Download PDF</a>', obj.get_download_url())
