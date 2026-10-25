from django.conf import settings
from django.contrib import admin
from django.urls import include, path

from custard.core import views as core_views

admin.site.site_header = "CuSTaRD administration"
admin.site.site_title = "CuSTaRD admin"
admin.site.index_title = "Asset, risk and report tracking"

urlpatterns = [
    path("", include("custard.reporting.urls")),
    path("accounts/", include("custard.core.urls")),
    path("assets/", include("custard.inventory.urls")),
    path("", include("custard.risk.urls")),
    path("catalog/", include("custard.catalog.urls")),
    path("api/v1/", include("custard.api.urls")),
    path("healthz", core_views.healthz, name="healthz"),
    path(settings.ADMIN_URL, admin.site.urls),
]

handler403 = "custard.core.views.permission_denied"
handler404 = "custard.core.views.page_not_found"
handler500 = "custard.core.views.server_error"
