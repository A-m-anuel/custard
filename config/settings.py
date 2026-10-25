"""
CuSTaRD settings.

All deployment-specific values come from environment variables (12-factor). A local ``.env`` file
is read if present, so developers do not need to export variables by hand. Nothing secret has a
production default: the app refuses to start without ``CUSTARD_SECRET_KEY`` unless DEBUG is on.
"""

from __future__ import annotations

import os
import sys
from decimal import Decimal
from pathlib import Path
from urllib.parse import unquote, urlparse

import django
from django.core.exceptions import ImproperlyConfigured

BASE_DIR = Path(__file__).resolve().parent.parent


def _load_dotenv(path: Path) -> None:
    """Minimal .env loader (KEY=VALUE lines); real environment variables always win."""
    if not path.is_file():
        return
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        os.environ.setdefault(key.strip(), value.strip().strip("'\""))


_load_dotenv(BASE_DIR / ".env")


def env(name: str, default: str | None = None) -> str | None:
    return os.environ.get(name, default)


def env_bool(name: str, default: bool = False) -> bool:
    value = os.environ.get(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def env_int(name: str, default: int) -> int:
    value = os.environ.get(name)
    return default if value in (None, "") else int(value)


def env_list(name: str, default: str = "") -> list[str]:
    return [item.strip() for item in os.environ.get(name, default).split(",") if item.strip()]


def parse_database_url(url: str) -> dict:
    """Support sqlite:///relative.db, sqlite:////abs/path.db and postgres://user:pass@host:5432/db."""
    parsed = urlparse(url)
    if parsed.scheme == "sqlite":
        path = parsed.path[1:] if parsed.path.startswith("/") else parsed.path
        name = path if path.startswith("/") else str(BASE_DIR / path) if path else ":memory:"
        return {"ENGINE": "django.db.backends.sqlite3", "NAME": name}
    if parsed.scheme in {"postgres", "postgresql", "pgsql"}:
        return {
            "ENGINE": "django.db.backends.postgresql",
            "NAME": unquote(parsed.path.lstrip("/")),
            "USER": unquote(parsed.username or ""),
            "PASSWORD": unquote(parsed.password or ""),
            "HOST": parsed.hostname or "",
            "PORT": str(parsed.port or ""),
            "CONN_MAX_AGE": env_int("CUSTARD_DB_CONN_MAX_AGE", 60),
        }
    raise ImproperlyConfigured(f"Unsupported DATABASE_URL scheme: {parsed.scheme!r}")


# --------------------------------------------------------------------------- core

TESTING = len(sys.argv) > 1 and sys.argv[1] == "test"
DEBUG = env_bool("CUSTARD_DEBUG", False)

SECRET_KEY = env("CUSTARD_SECRET_KEY")
if not SECRET_KEY:
    if DEBUG:
        SECRET_KEY = "dev-only-insecure-key-do-not-use-in-production"  # noqa: S105 (DEBUG only)
    else:
        raise ImproperlyConfigured("Set CUSTARD_SECRET_KEY (or CUSTARD_DEBUG=true for local development).")

ALLOWED_HOSTS = env_list("CUSTARD_ALLOWED_HOSTS", "localhost,127.0.0.1" if DEBUG else "")
CSRF_TRUSTED_ORIGINS = env_list("CUSTARD_CSRF_TRUSTED_ORIGINS")

INSTALLED_APPS = [
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "custard.core",
    "custard.catalog",
    "custard.inventory",
    "custard.risk",
    "custard.reporting",
    "custard.api",
]

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "whitenoise.middleware.WhiteNoiseMiddleware",
    "custard.core.middleware.SecurityHeadersMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
]

ROOT_URLCONF = "config.urls"
WSGI_APPLICATION = "config.wsgi.application"
ASGI_APPLICATION = "config.asgi.application"

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [BASE_DIR / "templates"],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.debug",
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
                "custard.core.context_processors.custard",
            ],
        },
    }
]

DATABASES = {"default": parse_database_url(env("DATABASE_URL", "sqlite:///db.sqlite3"))}
DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

# Database-backed cache: shared by all worker processes with no extra infrastructure.
# It holds login-throttling counters. Run `manage.py createcachetable` once (the Docker entrypoint does).
CACHES = {
    "default": {
        "BACKEND": "django.core.cache.backends.db.DatabaseCache",
        "LOCATION": "custard_cache",
    }
}

# --------------------------------------------------------------------------- auth

AUTH_PASSWORD_VALIDATORS = [
    {"NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator"},
    {"NAME": "django.contrib.auth.password_validation.MinimumLengthValidator", "OPTIONS": {"min_length": 12}},
    {"NAME": "django.contrib.auth.password_validation.CommonPasswordValidator"},
    {"NAME": "django.contrib.auth.password_validation.NumericPasswordValidator"},
]
LOGIN_URL = "login"
LOGIN_REDIRECT_URL = "dashboard"
LOGOUT_REDIRECT_URL = "login"

SESSION_COOKIE_AGE = env_int("CUSTARD_SESSION_AGE_SECONDS", 8 * 60 * 60)
SESSION_EXPIRE_AT_BROWSER_CLOSE = True
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = "Lax"
CSRF_COOKIE_SAMESITE = "Lax"

# Failed-login throttling (per username + client IP)
CUSTARD_LOGIN_MAX_ATTEMPTS = env_int("CUSTARD_LOGIN_MAX_ATTEMPTS", 5)
CUSTARD_LOGIN_LOCKOUT_SECONDS = env_int("CUSTARD_LOGIN_LOCKOUT_SECONDS", 15 * 60)
# Only enable behind a trusted reverse proxy that overwrites X-Forwarded-For.
CUSTARD_TRUST_X_FORWARDED_FOR = env_bool("CUSTARD_TRUST_X_FORWARDED_FOR", False)

# --------------------------------------------------------------------------- security headers

SECURE_CONTENT_TYPE_NOSNIFF = True  # fixes the only ZAP finding reported in the dissertation (4.4.1)
SECURE_REFERRER_POLICY = "same-origin"
X_FRAME_OPTIONS = "DENY"
SECURE_PROXY_SSL_HEADER = ("HTTP_X_FORWARDED_PROTO", "https") if env_bool("CUSTARD_BEHIND_TLS_PROXY") else None

if not DEBUG:
    SECURE_SSL_REDIRECT = env_bool("CUSTARD_SSL_REDIRECT", not TESTING)
    SESSION_COOKIE_SECURE = True
    CSRF_COOKIE_SECURE = True
    SECURE_HSTS_SECONDS = env_int("CUSTARD_HSTS_SECONDS", 31536000)
    SECURE_HSTS_INCLUDE_SUBDOMAINS = env_bool("CUSTARD_HSTS_INCLUDE_SUBDOMAINS", True)
    SECURE_HSTS_PRELOAD = env_bool("CUSTARD_HSTS_PRELOAD", False)
    SECURE_REDIRECT_EXEMPT = [r"^healthz$"]
    if env_bool("CUSTARD_INSECURE_COOKIES_FOR_LOCAL_HTTP"):
        # Only for evaluating the container on http://localhost. Never enable on a real deployment.
        SESSION_COOKIE_SECURE = CSRF_COOKIE_SECURE = False
        SECURE_HSTS_SECONDS = 0

# Every script and stylesheet is served from this origin, so the policy needs no 'unsafe-inline'.
CUSTARD_CONTENT_SECURITY_POLICY = env(
    "CUSTARD_CONTENT_SECURITY_POLICY",
    "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; "
    "connect-src 'self'; object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'",
)

# --------------------------------------------------------------------------- i18n / time

LANGUAGE_CODE = "en-gb"
TIME_ZONE = env("CUSTARD_TIME_ZONE", "Europe/London")
USE_I18N = True
USE_TZ = True

# --------------------------------------------------------------------------- files

STATIC_URL = "/static/"
STATIC_ROOT = Path(env("CUSTARD_STATIC_ROOT", str(BASE_DIR / "staticfiles")))
STATICFILES_DIRS = [BASE_DIR / "static"]

# Generated reports are confidential: they live outside any web-served directory and are only
# returned through an authenticated, permission-checked view.
CUSTARD_PRIVATE_STORAGE_ROOT = Path(env("CUSTARD_PRIVATE_STORAGE_ROOT", str(BASE_DIR / "var" / "private")))
MEDIA_ROOT = CUSTARD_PRIVATE_STORAGE_ROOT
MEDIA_URL = "/unused-media/"  # nothing is served from MEDIA_ROOT
FILE_UPLOAD_MAX_MEMORY_SIZE = 2 * 1024 * 1024
DATA_UPLOAD_MAX_MEMORY_SIZE = 5 * 1024 * 1024

_static_backend = (
    "whitenoise.storage.CompressedManifestStaticFilesStorage"
    if env_bool("CUSTARD_MANIFEST_STATIC", not DEBUG and not TESTING)
    else "django.contrib.staticfiles.storage.StaticFilesStorage"
)
if django.VERSION >= (4, 2):
    STORAGES = {
        "default": {"BACKEND": "django.core.files.storage.FileSystemStorage"},
        "staticfiles": {"BACKEND": _static_backend},
    }
else:  # pragma: no cover - legacy setting names
    STATICFILES_STORAGE = _static_backend

# --------------------------------------------------------------------------- CuSTaRD

ADMIN_URL = env("CUSTARD_ADMIN_URL", "admin/")
# Dissertation 3.4.4: "Assets under five are considered exposed and often demand immediate intervention".
CUSTARD_EXPOSURE_THRESHOLD = Decimal(env("CUSTARD_EXPOSURE_THRESHOLD", "5.0"))
CUSTARD_ORGANISATION_NAME = env("CUSTARD_ORGANISATION_NAME", "Your organisation")
CUSTARD_API_TOKEN_DEFAULT_DAYS = env_int("CUSTARD_API_TOKEN_DEFAULT_DAYS", 90)

# --------------------------------------------------------------------------- logging

LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {"plain": {"format": "%(asctime)s %(levelname)s %(name)s %(message)s"}},
    "handlers": {"console": {"class": "logging.StreamHandler", "formatter": "plain"}},
    "root": {"handlers": ["console"], "level": env("CUSTARD_LOG_LEVEL", "INFO")},
    "loggers": {"django.security": {"handlers": ["console"], "level": "WARNING", "propagate": False}},
}
