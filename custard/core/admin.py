from django.contrib import admin

from .models import AuditEvent


@admin.register(AuditEvent)
class AuditEventAdmin(admin.ModelAdmin):
    list_display = ("timestamp", "actor_repr", "action", "object_type", "object_repr", "ip_address")
    list_filter = ("action", "object_type")
    search_fields = ("actor_repr", "object_repr", "object_id")
    date_hierarchy = "timestamp"
    readonly_fields = [f.name for f in AuditEvent._meta.fields]

    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False

    def has_delete_permission(self, request, obj=None):
        return False
