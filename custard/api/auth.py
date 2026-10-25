"""Authentication for the read-only JSON API: session cookie or `Authorization: Bearer <token>`."""

from __future__ import annotations

from functools import wraps

from django.http import JsonResponse
from django.utils import timezone

from .models import APIToken, hash_token


def _token_user(request):
    header = request.META.get("HTTP_AUTHORIZATION", "")
    scheme, _, raw = header.partition(" ")
    if scheme.lower() != "bearer" or not raw.strip():
        return None, False
    token = APIToken.objects.select_related("user").filter(token_hash=hash_token(raw.strip())).first()
    if token is None or not token.is_valid:
        return None, True
    APIToken.objects.filter(pk=token.pk).update(last_used_at=timezone.now())
    return token.user, True


def api_view(permission: str):
    def decorator(view):
        @wraps(view)
        def wrapper(request, *args, **kwargs):
            if request.method != "GET":
                return JsonResponse({"error": "method not allowed"}, status=405)
            user, used_token = _token_user(request)
            if user is None and not used_token and request.user.is_authenticated:
                user = request.user
            if user is None:
                response = JsonResponse({"error": "authentication required"}, status=401)
                response["WWW-Authenticate"] = 'Bearer realm="custard"'
                return response
            if not user.has_perm(permission):
                return JsonResponse({"error": "permission denied"}, status=403)
            request.api_user = user
            return view(request, *args, **kwargs)
        return wrapper
    return decorator
