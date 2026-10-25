from django.contrib import admin

from .models import APIToken


@admin.register(APIToken)
class APITokenAdmin(admin.ModelAdmin):
    """Tokens are issued with `manage.py create_api_token` (the secret is shown once); revoke them here."""

    list_display = ("name", "user", "prefix", "created_at", "expires_at", "last_used_at", "revoked")
    list_filter = ("revoked",)
    search_fields = ("name", "user__username", "prefix")
    readonly_fields = ("user", "name", "prefix", "created_at", "last_used_at")
    fields = ("user", "name", "prefix", "created_at", "expires_at", "last_used_at", "revoked")

    def has_add_permission(self, request):
        return False
