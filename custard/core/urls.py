from django.contrib.auth import views as auth_views
from django.urls import path

from . import views

urlpatterns = [
    path("login/", views.LoginView.as_view(), name="login"),
    path("logout/", views.logout_view, name="logout"),
    path(
        "password/",
        auth_views.PasswordChangeView.as_view(template_name="accounts/password_change.html"),
        name="password_change",
    ),
    path(
        "password/done/",
        auth_views.PasswordChangeDoneView.as_view(template_name="accounts/password_change_done.html"),
        name="password_change_done",
    ),
    path("audit/", views.audit_log, name="audit_log"),
]
