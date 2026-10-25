from django.contrib import admin

from .models import AssetCategory, AssetType, CategoryVulnerability, ChecklistItem, Mitigation, Vulnerability


class ChecklistInline(admin.TabularInline):
    model = ChecklistItem
    extra = 0
    fields = ("order", "text", "pillar", "reference", "is_active")


class CategoryVulnerabilityInline(admin.TabularInline):
    model = CategoryVulnerability
    extra = 0
    autocomplete_fields = ("vulnerability",)
    filter_horizontal = ("mitigations",)


@admin.register(AssetType)
class AssetTypeAdmin(admin.ModelAdmin):
    list_display = ("name", "order")


@admin.register(AssetCategory)
class AssetCategoryAdmin(admin.ModelAdmin):
    list_display = ("name", "asset_type", "is_custom", "is_active")
    list_filter = ("asset_type", "is_custom", "is_active")
    search_fields = ("name",)
    inlines = [ChecklistInline, CategoryVulnerabilityInline]


@admin.register(Vulnerability)
class VulnerabilityAdmin(admin.ModelAdmin):
    list_display = ("name", "reference")
    search_fields = ("name", "description", "reference")
    filter_horizontal = ("mitigations",)
    readonly_fields = ("source",)


@admin.register(Mitigation)
class MitigationAdmin(admin.ModelAdmin):
    list_display = ("name", "reference")
    search_fields = ("name", "description", "reference")


@admin.register(CategoryVulnerability)
class CategoryVulnerabilityAdmin(admin.ModelAdmin):
    list_display = ("category", "vulnerability", "likelihood")
    list_filter = ("likelihood", "category__asset_type")
    search_fields = ("category__name", "vulnerability__name")
    autocomplete_fields = ("category", "vulnerability")
    filter_horizontal = ("mitigations",)
