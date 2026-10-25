"""Server-rendered SVG charts.

Rendering charts on the server keeps the UI free of third-party JavaScript, so the strict
Content-Security-Policy (script-src 'self') holds and nothing is loaded from a CDN.
"""

from __future__ import annotations

from decimal import Decimal
from xml.sax.saxutils import escape

from django.utils.safestring import SafeString, mark_safe


def _e(text) -> str:
    return escape(str(text), {'"': "&quot;"})


def _truncate(text: str, limit: int) -> str:
    return text if len(text) <= limit else text[: limit - 1] + "…"


def score_bar_chart(rows: list[tuple[str, Decimal | float | None, str]], *, maximum: float = 10.0,
                    threshold: float | None = None, label_width: int = 220, width: int = 760,
                    bar_height: int = 18, gap: int = 8, title: str = "Security score by asset") -> SafeString:
    """Horizontal bar chart. rows = [(label, value or None, css_class)]."""
    if not rows:
        return mark_safe("")  # nosec B308 B703 - constant markup
    plot_w = width - label_width - 60
    top, axis_h = 8, 26
    height = top + len(rows) * (bar_height + gap) + axis_h
    x0 = label_width
    parts = [
        f'<svg class="chart" role="img" viewBox="0 0 {width} {height}" width="100%" '
        f'aria-label="{_e(title)}" xmlns="http://www.w3.org/2000/svg"><title>{_e(title)}</title>'
    ]
    for tick in range(0, int(maximum) + 1, 1 if maximum <= 10 else int(maximum // 10)):
        x = x0 + plot_w * tick / maximum
        parts.append(f'<line class="grid" x1="{x:.1f}" y1="{top}" x2="{x:.1f}" y2="{height - axis_h}"/>')
        parts.append(f'<text class="tick" x="{x:.1f}" y="{height - 8}" text-anchor="middle">{tick}</text>')
    if threshold is not None:
        x = x0 + plot_w * float(threshold) / maximum
        parts.append(f'<line class="threshold" x1="{x:.1f}" y1="{top - 4}" x2="{x:.1f}" y2="{height - axis_h}"/>')
    for i, (label, value, css) in enumerate(rows):
        y = top + i * (bar_height + gap)
        parts.append(
            f'<text class="label" x="{x0 - 10}" y="{y + bar_height * 0.72:.1f}" text-anchor="end">'
            f'<title>{_e(label)}</title>{_e(_truncate(label, 30))}</text>'
        )
        if value is None:
            parts.append(f'<text class="muted" x="{x0 + 6}" y="{y + bar_height * 0.72:.1f}">not assessed</text>')
            continue
        w = max(plot_w * float(value) / maximum, 2)
        parts.append(f'<rect class="bar {_e(css)}" x="{x0}" y="{y}" width="{w:.1f}" height="{bar_height}" rx="3"/>')
        parts.append(f'<text class="value" x="{x0 + w + 6:.1f}" y="{y + bar_height * 0.72:.1f}">'
                     f'{float(value):.1f}</text>')
    parts.append("</svg>")
    return mark_safe("".join(parts))  # noqa: S308  # nosec B308 B703 - every interpolated value is escaped with _e() or numeric


def mini_bar(value: Decimal | float | None, *, maximum: float = 10.0, css: str = "") -> SafeString:
    """Small inline progress bar used in tables."""
    if value is None:
        return mark_safe('<span class="muted">—</span>')  # nosec B308 B703 - constant markup
    pct = max(0.0, min(100.0, float(value) / maximum * 100))
    markup = (
        f'<svg class="minibar" viewBox="0 0 100 8" preserveAspectRatio="none" aria-hidden="true">'
        f'<rect class="track" x="0" y="0" width="100" height="8" rx="4"/>'
        f'<rect class="bar {_e(css)}" x="0" y="0" width="{pct:.1f}" height="8" rx="4"/></svg>'
    )
    return mark_safe(markup)  # noqa: S308  # nosec B308 B703 - only an escaped CSS class and a number are interpolated
