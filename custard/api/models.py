from __future__ import annotations

import datetime
import hashlib
import secrets

from django.conf import settings
from django.db import models
from django.utils import timezone


def hash_token(raw: str) -> str:
    return hashlib.sha256(raw.encode()).hexdigest()


class APIToken(models.Model):
    """Read-only API credential. Only a SHA-256 hash is stored; the token is shown once at creation."""

    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="api_tokens")
    name = models.CharField(max_length=100, help_text="What the token is for, e.g. 'SIEM integration'.")
    prefix = models.CharField(max_length=12, editable=False, db_index=True)
    token_hash = models.CharField(max_length=64, unique=True, editable=False)
    created_at = models.DateTimeField(default=timezone.now, editable=False)
    expires_at = models.DateTimeField(null=True, blank=True)
    last_used_at = models.DateTimeField(null=True, blank=True, editable=False)
    revoked = models.BooleanField(default=False)

    class Meta:
        ordering = ["-created_at"]
        verbose_name = "API token"

    def __str__(self) -> str:
        return f"{self.name} ({self.prefix}…)"

    @classmethod
    def issue(cls, user, name: str, days: int | None = None) -> tuple[APIToken, str]:
        raw = "cst_" + secrets.token_urlsafe(32)
        expires = timezone.now() + datetime.timedelta(days=days) if days else None
        token = cls.objects.create(user=user, name=name, prefix=raw[:12], token_hash=hash_token(raw),
                                   expires_at=expires)
        return token, raw

    @property
    def is_valid(self) -> bool:
        return not self.revoked and (self.expires_at is None or self.expires_at > timezone.now()) \
            and self.user.is_active
