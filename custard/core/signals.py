from django.contrib.auth.signals import user_logged_in, user_logged_out, user_login_failed
from django.dispatch import receiver

from . import audit
from .models import AuditEvent


@receiver(user_logged_in)
def _logged_in(sender, request, user, **kwargs):
    audit.record(AuditEvent.Action.LOGIN, request=request, actor=user, object_repr=user.get_username())


@receiver(user_logged_out)
def _logged_out(sender, request, user, **kwargs):
    if user is not None:
        audit.record(AuditEvent.Action.LOGOUT, request=request, actor=user, object_repr=user.get_username())


@receiver(user_login_failed)
def _login_failed(sender, credentials, request=None, **kwargs):
    username = str(credentials.get("username", ""))[:150]
    audit.record(AuditEvent.Action.LOGIN_FAILED, request=request, actor=None, object_repr=username)
