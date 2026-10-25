"""Helpers for writing audit events."""

from __future__ import annotations

from typing import Any

from django.conf import settings
from django.db import models

from .models import AuditEvent


def client_ip(request) -> str | None:
    if request is None:
        return None
    if getattr(settings, "CUSTARD_TRUST_X_FORWARDED_FOR", False):
        forwarded = request.META.get("HTTP_X_FORWARDED_FOR", "")
        if forwarded:
            return forwarded.split(",")[0].strip() or None
    return request.META.get("REMOTE_ADDR") or None


def record(
    action: str,
    *,
    request=None,
    actor=None,
    obj: models.Model | None = None,
    object_repr: str | None = None,
    changes: dict[str, Any] | None = None,
) -> AuditEvent:
    if actor is None and request is not None and getattr(request, "user", None) is not None:
        actor = request.user if request.user.is_authenticated else None
    event = AuditEvent(
        action=action,
        actor=actor,
        actor_repr=(actor.get_username() if actor is not None else "")[:150],
        changes=changes or {},
        ip_address=client_ip(request),
    )
    if obj is not None:
        event.object_type = obj._meta.label
        event.object_id = str(obj.pk)
        event.object_repr = str(obj)[:255]
    if object_repr is not None:
        event.object_repr = object_repr[:255]
    event.save()
    return event


def diff(instance: models.Model, original: dict[str, Any], fields: list[str]) -> dict[str, list]:
    """Return {field: [old, new]} for fields whose value changed."""
    changes = {}
    for name in fields:
        old, new = original.get(name), getattr(instance, name)
        if hasattr(new, "pk"):
            new = str(new)
        if old != new:
            changes[name] = [_jsonable(old), _jsonable(new)]
    return changes


def snapshot(instance: models.Model, fields: list[str]) -> dict[str, Any]:
    data = {}
    for name in fields:
        value = getattr(instance, name)
        data[name] = str(value) if hasattr(value, "pk") else value
    return data


def _jsonable(value):
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    return str(value)
