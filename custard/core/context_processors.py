from django.conf import settings

from . import __version__


def custard(request):
    return {
        "custard_version": __version__,
        "organisation_name": settings.CUSTARD_ORGANISATION_NAME,
        "exposure_threshold": settings.CUSTARD_EXPOSURE_THRESHOLD,
        "admin_url": "/" + settings.ADMIN_URL.lstrip("/"),
    }
