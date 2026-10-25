from __future__ import annotations

import hashlib

from django import forms
from django.conf import settings
from django.contrib.auth.forms import AuthenticationForm
from django.core.cache import cache

from .audit import client_ip


class ThrottledAuthenticationForm(AuthenticationForm):
    """Locks a username/IP pair out for a while after repeated failures (brute-force protection)."""

    error_messages = {
        **AuthenticationForm.error_messages,
        "locked": "Too many failed sign-in attempts. Try again in %(minutes)d minutes.",
    }

    def _key(self) -> str:
        username = (self.data.get("username") or "").strip().lower()
        raw = f"{username}|{client_ip(self.request) or '-'}"
        return "custard:login-fail:" + hashlib.sha256(raw.encode()).hexdigest()

    def clean(self):
        key = self._key()
        limit = settings.CUSTARD_LOGIN_MAX_ATTEMPTS
        if cache.get(key, 0) >= limit:
            raise forms.ValidationError(
                self.error_messages["locked"],
                code="locked",
                params={"minutes": max(1, settings.CUSTARD_LOGIN_LOCKOUT_SECONDS // 60)},
            )
        try:
            cleaned = super().clean()
        except forms.ValidationError:
            # get+set (not incr) so the lockout window always uses the configured timeout
            cache.set(key, cache.get(key, 0) + 1, settings.CUSTARD_LOGIN_LOCKOUT_SECONDS)
            raise
        cache.delete(key)
        return cleaned
