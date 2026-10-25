"""PDF cyber-risk report (dissertation 3.4.4 "Report View", Figure 38), built with ReportLab."""

from __future__ import annotations

import io
from xml.sax.saxutils import escape

from django.conf import settings
from django.utils import timezone
from reportlab.graphics.charts.barcharts import HorizontalBarChart
from reportlab.graphics.shapes import Drawing, Line, String
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4, landscape
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import KeepTogether, PageBreak, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

from custard.core.choices import Level

INK = colors.HexColor("#1f2933")
MUTED = colors.HexColor("#616e7c")
RULE = colors.HexColor("#d9dee5")
HEAD = colors.HexColor("#243b53")
LEVEL_FILL = {
    Level.HIGH: colors.HexColor("#f8d4d4"),
    Level.MEDIUM: colors.HexColor("#fde9c4"),
    Level.LOW: colors.HexColor("#d6f0dc"),
}
EXPOSED = colors.HexColor("#c0392b")
SECURE = colors.HexColor("#2f855a")
CHART_CHUNK = 25

_styles = getSampleStyleSheet()
H1 = ParagraphStyle("H1", parent=_styles["Title"], fontSize=22, textColor=INK, alignment=0, spaceAfter=4)
H2 = ParagraphStyle("H2", parent=_styles["Heading2"], textColor=HEAD, spaceBefore=10, spaceAfter=6)
BODY = ParagraphStyle("Body", parent=_styles["BodyText"], fontSize=8.5, leading=11, textColor=INK)
SMALL = ParagraphStyle("Small", parent=BODY, fontSize=8, textColor=MUTED)
CELL = ParagraphStyle("Cell", parent=BODY, fontSize=8, leading=10)
CELL_HEAD = ParagraphStyle("CellHead", parent=CELL, textColor=colors.white, fontName="Helvetica-Bold")


def p(text, style=CELL) -> Paragraph:
    """Paragraph with user text escaped (ReportLab parses a mini markup language)."""
    return Paragraph(escape("" if text is None else str(text)), style)


def _table(header, rows, widths, level_col: int | None = None, levels=None) -> Table:
    data = [[p(h, CELL_HEAD) for h in header]] + [[c if isinstance(c, Paragraph) else p(c) for c in r] for r in rows]
    table = Table(data, colWidths=widths, repeatRows=1)
    style = [
        ("BACKGROUND", (0, 0), (-1, 0), HEAD),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LINEBELOW", (0, 0), (-1, -1), 0.25, RULE),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f7f9fb")]),
        ("TOPPADDING", (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
    ]
    if level_col is not None and levels:
        for i, level in enumerate(levels, start=1):
            if level in LEVEL_FILL:
                style.append(("BACKGROUND", (level_col, i), (level_col, i), LEVEL_FILL[level]))
    table.setStyle(TableStyle(style))
    return table


def _score_chart(assets, width: float) -> Drawing:
    names = [a.name if len(a.name) <= 34 else a.name[:33] + "…" for a in assets]
    values = [float(a.security_score) for a in assets]
    row_h = 14
    height = max(80, len(assets) * row_h + 40)
    drawing = Drawing(width, height)
    chart = HorizontalBarChart()
    chart.x, chart.y = 170, 25
    chart.width, chart.height = width - 200, height - 40
    chart.data = [values]
    chart.categoryAxis.categoryNames = names
    chart.categoryAxis.reverseDirection = True
    chart.categoryAxis.labels.fontSize = 7
    chart.categoryAxis.labels.boxAnchor = "e"
    chart.valueAxis.valueMin, chart.valueAxis.valueMax, chart.valueAxis.valueStep = 0, 10, 1
    chart.valueAxis.labels.fontSize = 7
    chart.barWidth = 9
    threshold = float(settings.CUSTARD_EXPOSURE_THRESHOLD)
    for i, value in enumerate(values):
        chart.bars[(0, i)].fillColor = EXPOSED if value < threshold else SECURE
        chart.bars[(0, i)].strokeColor = None
    drawing.add(chart)
    x = chart.x + chart.width * threshold / 10
    drawing.add(Line(x, chart.y, x, chart.y + chart.height, strokeColor=MUTED, strokeDashArray=[3, 2]))
    drawing.add(String(x + 3, chart.y + chart.height + 4, f"exposure threshold {threshold:g}", fontSize=7,
                       fillColor=MUTED))
    return drawing


def build_report(*, portfolio, assets, risks, new_assets, generated_by, title: str) -> bytes:
    buffer = io.BytesIO()
    page = landscape(A4)
    generated = timezone.localtime()

    def footer(canvas, doc):
        canvas.saveState()
        canvas.setFont("Helvetica", 7)
        canvas.setFillColor(MUTED)
        canvas.drawString(15 * mm, 8 * mm, f"CuSTaRD · {settings.CUSTARD_ORGANISATION_NAME} · CONFIDENTIAL")
        canvas.drawRightString(page[0] - 15 * mm, 8 * mm, f"Generated {generated:%d %b %Y %H:%M} · page {doc.page}")
        canvas.restoreState()

    doc = SimpleDocTemplate(buffer, pagesize=page, leftMargin=15 * mm, rightMargin=15 * mm, topMargin=14 * mm,
                            bottomMargin=15 * mm, title=title, author="CuSTaRD")
    width = page[0] - 30 * mm
    story = [
        Paragraph(escape(title), H1),
        p(f"{settings.CUSTARD_ORGANISATION_NAME} · generated {generated:%d %B %Y %H:%M} by "
          f"{generated_by or 'system'}", SMALL),
        Spacer(1, 8),
    ]

    lv = portfolio.open_risks_by_level
    summary = [
        ["Registered assets", portfolio.total_assets, "Unresolved high risks", lv.get(Level.HIGH, 0)],
        ["Assessed assets", portfolio.assessed_assets, "Unresolved medium risks", lv.get(Level.MEDIUM, 0)],
        ["Average security score",
         "-" if portfolio.average_score is None else f"{portfolio.average_score} / 10",
         "Unresolved low risks", lv.get(Level.LOW, 0)],
        [f"Exposed assets (score < {settings.CUSTARD_EXPOSURE_THRESHOLD:g})", len(portfolio.exposed_assets),
         "Overdue treatments", portfolio.overdue_treatments],
        ["Asset categories in use", portfolio.categories_in_use, "Expired risk acceptances",
         len(portfolio.expired_acceptances)],
    ]
    t = Table([[p(a), p(b), p(c), p(d)] for a, b, c, d in summary], colWidths=[width * 0.3, width * 0.2] * 2)
    t.setStyle(TableStyle([("LINEBELOW", (0, 0), (-1, -1), 0.25, RULE), ("TOPPADDING", (0, 0), (-1, -1), 4)]))
    story += [Paragraph("Summary", H2), t]

    story.append(Paragraph("Exposed assets", H2))
    if portfolio.exposed_assets:
        story.append(_table(["Asset", "Category", "Score", "C", "I", "A", "Owner"], [
            [a.name, a.category.name, a.security_score, a.confidentiality_score, a.integrity_score,
             a.availability_score, a.owner or "-"] for a in portfolio.exposed_assets
        ], [width * w for w in (0.28, 0.24, 0.08, 0.06, 0.06, 0.06, 0.22)]))
    else:
        story.append(p("No assessed asset is below the exposure threshold.", BODY))

    story.append(Paragraph("Assets registered since the previous report", H2))
    story.append(p(", ".join(a.name for a in new_assets) if new_assets else "None.", BODY))

    assessed = [a for a in assets if a.security_score is not None]
    if assessed:
        story += [PageBreak(), Paragraph("Security score by asset", H2),
                  p("Score 0-10 from the CIA security checklist: (C + I + A) / 30 × 10. Red bars are exposed.", SMALL)]
        for start in range(0, len(assessed), CHART_CHUNK):
            story.append(KeepTogether(_score_chart(assessed[start:start + CHART_CHUNK], width)))

    story += [PageBreak(), Paragraph("Risk register", H2),
              p("Risk = likelihood × impact (NIST SP 800-30, Table 3-6). High > 50, Medium > 10, Low ≤ 10.", SMALL),
              Spacer(1, 4)]
    if risks:
        story.append(_table(
            ["Asset", "Vulnerability", "Likelihood", "Impact", "Risk", "Residual", "Status", "Owner"],
            [[r.asset.name, r.vulnerability.name, r.get_likelihood_display(), r.get_impact_display(),
              f"{r.inherent_score} {r.get_inherent_level_display()}",
              f"{r.residual_score} {r.get_residual_level_display()}" if r.residual_level else "-",
              r.get_status_display(), r.owner or "-"]
             for r in risks],
            [width * w for w in (0.17, 0.23, 0.08, 0.07, 0.1, 0.1, 0.11, 0.14)],
            level_col=4, levels=[r.inherent_level for r in risks],
        ))
        story += [PageBreak(), Paragraph("Treatment plan", H2)]
        rows = []
        for r in risks:
            for tr in r.treatments.all():
                rows.append([f"{r.asset.name} - {r.vulnerability.name}", tr.mitigation.name, tr.get_status_display(),
                             tr.owner or "-", tr.due_date.isoformat() if tr.due_date else "-"])
        story.append(_table(["Risk", "Mitigation", "Status", "Owner", "Due"], rows,
                            [width * w for w in (0.3, 0.36, 0.11, 0.13, 0.1)]) if rows else p("No treatments.", BODY))
    else:
        story.append(p("No risks recorded.", BODY))

    doc.build(story, onFirstPage=footer, onLaterPages=footer)
    return buffer.getvalue()
