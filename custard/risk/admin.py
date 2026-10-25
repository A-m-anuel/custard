from django.contrib import admin

from .models import AssetRisk, RiskTreatment


class RiskTreatmentInline(admin.TabularInline):
    model = RiskTreatment
    extra = 0
    autocomplete_fields = ("mitigation", "owner")
    fields = ("mitigation", "status", "owner", "due_date", "completed_at")
    readonly_fields = ("completed_at",)


@admin.register(AssetRisk)
class AssetRiskAdmin(admin.ModelAdmin):
    list_display = ("asset", "vulnerability", "likelihood", "inherent_score", "inherent_level", "status", "owner")
    list_filter = ("inherent_level", "status", "source", "asset__category__asset_type")
    search_fields = ("asset__name", "vulnerability__name")
    autocomplete_fields = ("asset", "vulnerability", "owner")
    readonly_fields = ("inherent_score", "inherent_level", "residual_score", "residual_level", "source",
                       "accepted_by", "accepted_at", "created_at", "updated_at")
    inlines = [RiskTreatmentInline]


@admin.register(RiskTreatment)
class RiskTreatmentAdmin(admin.ModelAdmin):
    list_display = ("mitigation", "risk", "status", "owner", "due_date")
    list_filter = ("status",)
    search_fields = ("mitigation__name", "risk__asset__name", "risk__vulnerability__name")
    autocomplete_fields = ("risk", "mitigation", "owner")
