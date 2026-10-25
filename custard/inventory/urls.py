from django.urls import path

from . import views

urlpatterns = [
    path("", views.asset_list, name="asset_list"),
    path("new/", views.asset_create, name="asset_create"),
    path("import/", views.asset_import, name="asset_import"),
    path("import/template.csv", views.asset_import_template, name="asset_import_template"),
    path("<int:pk>/", views.asset_detail, name="asset_detail"),
    path("<int:pk>/edit/", views.asset_edit, name="asset_edit"),
    path("<int:pk>/assess/", views.asset_assess, name="asset_assess"),
    path("<int:pk>/archive/", views.asset_archive, name="asset_archive"),
    path("<int:pk>/sync-risks/", views.asset_sync_risks, name="asset_sync_risks"),
]
