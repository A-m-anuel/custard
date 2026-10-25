from django.urls import path

from . import views

urlpatterns = [
    path("", views.catalog_index, name="catalog_index"),
    path("categories/new/", views.category_create, name="category_create"),
    path("categories/<int:pk>/", views.category_detail, name="category_detail"),
    path("categories/<int:pk>/checklist/", views.checklist_item_add, name="checklist_item_add"),
    path("categories/<int:pk>/vulnerabilities/", views.default_vulnerability_add, name="default_vulnerability_add"),
]
