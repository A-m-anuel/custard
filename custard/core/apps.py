from django.apps import AppConfig


class CoreConfig(AppConfig):
    name = "custard.core"
    label = "core"
    verbose_name = "Core and audit"

    def ready(self) -> None:
        from django.db.models.signals import post_migrate

        from . import roles, signals  # noqa: F401  (signal registration)

        post_migrate.connect(roles.ensure_roles_on_migrate, dispatch_uid="custard_ensure_roles")
