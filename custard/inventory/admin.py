from django.conf import settings
from django.contrib import admin

from .models import Assessment, Asset


class ExposureFilter(admin.SimpleListFilter):
    title = "exposure"
    parameter_name = "exposure"

    def lookups(self, request, model_admin):
        return [("exposed", "Exposed"), ("secure", "At or above threshold"), ("unassessed", "Not assessed")]

    def queryset(self, request, queryset):
        threshold = settings.CUSTARD_EXPOSURE_THRESHOLD
        if self.value() == "exposed":
            return queryset.filter(security_score__lt=threshold)
        if self.value() == "secure":
            return queryset.filter(security_score__gte=threshold)
        if self.value() == "unassessed":
            return queryset.filter(security_score__isnull=True)
        return queryset


class AssessmentInline(admin.TabularInline):
    model = Assessment
    extra = 0
    can_delete = False
    fields = ("assessed_at", "assessed_by", "confidentiality_score", "integrity_score", "availability_score",
              "security_score")
    readonly_fields = fields
    show_change_link = True

    def has_add_permission(self, request, obj=None):
        return False


@admin.register(Asset)
class AssetAdmin(admin.ModelAdmin):
    """Real-time asset tracking for administrators: newest and exposed assets (dissertation 3.4.4)."""

    list_display = ("name", "category", "owner", "security_score", "is_exposed_flag", "is_active", "created_at")
    list_filter = (ExposureFilter, "is_active", "category__asset_type", "category")
    search_fields = ("name", "description", "location")
    date_hierarchy = "created_at"
    ordering = ("-created_at",)
    readonly_fields = ("confidentiality_score", "integrity_score", "availability_score", "security_score",
                       "last_assessed_at", "created_at", "created_by", "updated_at")
    autocomplete_fields = ("owner",)
    inlines = [AssessmentInline]

    @admin.display(boolean=True, description="Exposed")
    def is_exposed_flag(self, obj):
        return obj.is_exposed if obj.is_assessed else None


@admin.register(Assessment)
class AssessmentAdmin(admin.ModelAdmin):
    list_display = ("asset", "assessed_at", "assessed_by", "security_score")
    list_filter = ("assessed_at",)
    search_fields = ("asset__name",)
    readonly_fields = [f.name for f in Assessment._meta.fields]

    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False
