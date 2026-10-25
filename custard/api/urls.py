from django.urls import path

from . import views

urlpatterns = [
    path("summary/", views.summary, name="api_summary"),
    path("assets/", views.asset_list, name="api_assets"),
    path("assets/<int:pk>/", views.asset_detail, name="api_asset_detail"),
    path("risks/", views.risk_list, name="api_risks"),
]
