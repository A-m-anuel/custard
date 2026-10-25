from django.conf import settings


class SecurityHeadersMiddleware:
    """Adds headers Django does not set itself: CSP, Permissions-Policy and COOP."""

    def __init__(self, get_response):
        self.get_response = get_response
        self.csp = getattr(settings, "CUSTARD_CONTENT_SECURITY_POLICY", "")

    def __call__(self, request):
        response = self.get_response(request)
        path = request.path
        # The Django admin uses inline scripts/styles; keep strict CSP for the application itself.
        is_admin = path.startswith("/" + settings.ADMIN_URL.lstrip("/"))
        if self.csp and not is_admin and "Content-Security-Policy" not in response:
            response["Content-Security-Policy"] = self.csp
        response.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=()")
        response.setdefault("Cross-Origin-Opener-Policy", "same-origin")
        user = getattr(request, "user", None)
        if user is not None and user.is_authenticated:
            # Pages contain confidential risk data: never let shared caches or the browser store them.
            response.setdefault("Cache-Control", "no-store")
        return response
