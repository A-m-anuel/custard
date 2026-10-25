from django.conf import settings
from django.contrib.auth import logout
from django.contrib.auth import views as auth_views
from django.contrib.auth.decorators import login_required, permission_required
from django.core.paginator import Paginator
from django.db import connection
from django.http import JsonResponse
from django.shortcuts import redirect, render
from django.views.decorators.cache import never_cache
from django.views.decorators.http import require_GET, require_POST

from .forms import ThrottledAuthenticationForm
from .models import AuditEvent


class LoginView(auth_views.LoginView):
    template_name = "accounts/login.html"
    authentication_form = ThrottledAuthenticationForm
    redirect_authenticated_user = True


@require_POST
def logout_view(request):
    """Logout is POST-only (CSRF-protected) on every supported Django version."""
    logout(request)
    return redirect(settings.LOGOUT_REDIRECT_URL)


@require_GET
@never_cache
def healthz(request):
    try:
        with connection.cursor() as cursor:
            cursor.execute("SELECT 1")
        return JsonResponse({"status": "ok"})
    except Exception:  # pragma: no cover - depends on infrastructure
        return JsonResponse({"status": "error"}, status=503)


@login_required
@permission_required("core.view_auditevent", raise_exception=True)
def audit_log(request):
    events = AuditEvent.objects.select_related("actor")
    action = request.GET.get("action", "")
    actor = request.GET.get("actor", "").strip()
    if action in AuditEvent.Action.values:
        events = events.filter(action=action)
    if actor:
        events = events.filter(actor_repr__icontains=actor)
    page = Paginator(events, 50).get_page(request.GET.get("page"))
    return render(request, "core/audit_log.html", {
        "page_obj": page, "actions": AuditEvent.Action.choices, "action": action, "actor": actor,
        "nav": "audit",
    })


def permission_denied(request, exception=None):
    return render(request, "errors/403.html", status=403)


def page_not_found(request, exception=None):
    return render(request, "errors/404.html", status=404)


def server_error(request):
    return render(request, "errors/500.html", status=500)
