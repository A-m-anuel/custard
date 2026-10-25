from django.urls import path

from . import views

urlpatterns = [
    path("risks/", views.risk_list, name="risk_list"),
    path("risks/<int:pk>/", views.risk_detail, name="risk_detail"),
    path("risks/<int:pk>/accept/", views.risk_accept, name="risk_accept"),
    path("risks/<int:pk>/reopen/", views.risk_reopen, name="risk_reopen"),
    path("risks/<int:pk>/treatments/new/", views.treatment_add, name="treatment_add"),
    path("treatments/<int:pk>/", views.treatment_update, name="treatment_update"),
    path("assets/<int:asset_pk>/risks/new/", views.risk_add, name="risk_add"),
    path("dependencies/", views.dependency_map, name="dependency_map"),
]
