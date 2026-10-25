from django.urls import path

from . import views

urlpatterns = [
    path("", views.dashboard, name="dashboard"),
    path("reports/", views.report_list, name="report_list"),
    path("reports/generate/", views.report_generate, name="report_generate"),
    path("reports/<int:pk>/download/", views.report_download, name="report_download"),
    path("exports/assets.csv", views.export_assets, name="export_assets"),
    path("exports/risks.csv", views.export_risks, name="export_risks"),
]
