from django import template

from custard.core import svg

register = template.Library()

LEVEL_CSS = {"HIGH": "lvl-high", "MEDIUM": "lvl-medium", "LOW": "lvl-low"}


@register.filter
def level_css(level) -> str:
    return LEVEL_CSS.get(str(level), "")


@register.filter
def score_css(asset_or_score) -> str:
    from django.conf import settings

    value = getattr(asset_or_score, "security_score", asset_or_score)
    if value is None:
        return "unassessed"
    return "exposed" if value < settings.CUSTARD_EXPOSURE_THRESHOLD else "ok"


@register.simple_tag
def minibar(value, css=""):
    return svg.mini_bar(value, css=css)


@register.simple_tag(takes_context=True)
def query(context, **kwargs) -> str:
    """Return the current querystring with some keys replaced (None removes a key)."""
    params = context["request"].GET.copy()
    for key, value in kwargs.items():
        if value is None or value == "":
            params.pop(key, None)
        else:
            params[key] = value
    encoded = params.urlencode()
    return "?" + encoded if encoded else "?"


@register.filter
def get_item(mapping, key):
    try:
        return mapping.get(key)
    except AttributeError:
        return None


@register.simple_tag(takes_context=True)
def has_perm(context, perm: str) -> bool:
    user = context["request"].user
    return user.is_authenticated and user.has_perm(perm)




@register.filter
def changes_text(changes) -> str:
    """Render an audit 'changes' dict readably: field: old → new; key: value."""
    if not isinstance(changes, dict):
        return str(changes)
    parts = []
    for key, value in changes.items():
        label = str(key).replace("_", " ")
        if isinstance(value, list) and len(value) == 2:
            old, new = ("—" if v in (None, "") else v for v in value)
            parts.append(f"{label}: {old} → {new}")
        else:
            parts.append(f"{label}: {value}")
    return "; ".join(parts)
