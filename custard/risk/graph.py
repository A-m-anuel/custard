"""Dependency map: assets → weaknesses → mitigations (dissertation 3.4.4 "Risk dependency").

The prototype used GoJS, a commercial library that needs a paid licence for production use and is
loaded from a CDN. This module lays the graph out on the server and returns plain SVG instead:
three columns, with nodes ordered by the barycentre heuristic to reduce edge crossings.
Shared weaknesses and shared mitigations collapse into a single node, which shows where one
control removes several risks - the cost-effectiveness argument made in the dissertation.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from xml.sax.saxutils import escape

from django.urls import reverse
from django.utils.safestring import SafeString, mark_safe

from custard.core.choices import LEVEL_ORDER

NODE_H, GAP, COL_W, COL_GAP, PAD, TOP = 30, 10, 250, 120, 12, 34


@dataclass
class Node:
    key: str
    label: str
    column: int
    css: str = ""
    url: str = ""
    detail: str = ""
    links: set = field(default_factory=set)
    y: float = 0.0


def _e(text: str) -> str:
    return escape(str(text), {'"': "&quot;"})


def _short(text: str, n: int = 34) -> str:
    return text if len(text) <= n else text[: n - 1] + "…"


def build(risks) -> dict:
    """Return {"nodes": {...}, "edges": [(a, b, css)]} from AssetRisk objects with prefetched treatments."""
    nodes: dict[str, Node] = {}
    edges: set[tuple[str, str, str]] = set()
    vuln_level: dict[str, str] = {}
    mitigation_risks: dict[str, set[int]] = defaultdict(set)

    for risk in risks:
        a_key, v_key = f"a{risk.asset_id}", f"v{risk.vulnerability_id}"
        if a_key not in nodes:
            nodes[a_key] = Node(a_key, risk.asset.name, 0, css="asset",
                                url=reverse("asset_detail", args=[risk.asset_id]),
                                detail=risk.asset.category.name)
        if v_key not in nodes:
            nodes[v_key] = Node(v_key, risk.vulnerability.name, 1)
        level = risk.current_level
        if LEVEL_ORDER.get(level, 0) > LEVEL_ORDER.get(vuln_level.get(v_key, ""), 0):
            vuln_level[v_key] = level
        edges.add((a_key, v_key, "lvl-" + level.lower()))
        nodes[a_key].links.add(v_key)
        nodes[v_key].links.add(a_key)
        for treatment in risk.treatments.all():
            m_key = f"m{treatment.mitigation_id}"
            if m_key not in nodes:
                nodes[m_key] = Node(m_key, treatment.mitigation.name, 2, css="mitigation")
            mitigation_risks[m_key].add(risk.pk)
            css = "done" if treatment.status == "IMPLEMENTED" else "todo"
            edges.add((v_key, m_key, css))
            nodes[v_key].links.add(m_key)
            nodes[m_key].links.add(v_key)

    for key, level in vuln_level.items():
        nodes[key].css = "vuln lvl-" + level.lower()
    for key, risk_ids in mitigation_risks.items():
        nodes[key].detail = f"addresses {len(risk_ids)} risk{'s' if len(risk_ids) != 1 else ''}"
    return {"nodes": nodes, "edges": sorted(edges)}


def _layout(nodes: dict[str, Node]) -> list[list[Node]]:
    columns: list[list[Node]] = [[], [], []]
    for node in nodes.values():
        columns[node.column].append(node)
    columns[0].sort(key=lambda n: n.label.lower())
    for col in (1, 2):
        prev = {n.key: i for i, n in enumerate(columns[col - 1])}

        def barycentre(n, prev=prev):
            positions = [prev[k] for k in n.links if k in prev]
            return (sum(positions) / len(positions)) if positions else 0, n.label.lower()

        columns[col].sort(key=barycentre)
    step = NODE_H + GAP
    for i, node in enumerate(columns[0]):
        node.y = TOP + i * step
    # Place each later node level with the nodes it connects to, then push down to avoid overlap.
    for col in (1, 2):
        prev = {n.key: n.y for n in columns[col - 1]}
        cursor = TOP
        for node in columns[col]:
            linked = [prev[k] for k in node.links if k in prev]
            desired = sum(linked) / len(linked) if linked else cursor
            node.y = max(desired, cursor)
            cursor = node.y + step
    return columns


def render_svg(graph: dict) -> SafeString:
    nodes: dict[str, Node] = graph["nodes"]
    if not nodes:
        return mark_safe("")  # nosec B308 B703 - constant markup
    columns = _layout(nodes)
    height = max(n.y for n in nodes.values()) + NODE_H + PAD
    width = 3 * COL_W + 2 * COL_GAP + 2 * PAD
    x_of = [PAD + i * (COL_W + COL_GAP) for i in range(3)]
    out = [
        f'<svg class="depgraph" viewBox="0 0 {width} {height}" width="{width}" height="{height}" role="img" '
        f'aria-label="Dependency map of assets, weaknesses and mitigations" xmlns="http://www.w3.org/2000/svg">'
    ]
    for i, title in enumerate(("Assets", "Security weaknesses", "Risk mitigations")):
        out.append(f'<text class="col-title" x="{x_of[i]}" y="18">{title}</text>')
    for a, b, css in graph["edges"]:
        na, nb = nodes[a], nodes[b]
        x1, y1 = x_of[na.column] + COL_W, na.y + NODE_H / 2
        x2, y2 = x_of[nb.column], nb.y + NODE_H / 2
        mid = (x1 + x2) / 2
        out.append(f'<path class="edge {css}" d="M{x1:.0f},{y1:.0f} C{mid:.0f},{y1:.0f} {mid:.0f},{y2:.0f} '
                   f'{x2:.0f},{y2:.0f}"/>')
    for column in columns:
        for n in column:
            x = x_of[n.column]
            tip = n.label + (f" ({n.detail})" if n.detail else "")
            body = (f'<g class="node {n.css}"><title>{_e(tip)}</title>'
                    f'<rect x="{x}" y="{n.y:.0f}" width="{COL_W}" height="{NODE_H}" rx="6"/>'
                    f'<text x="{x + 10}" y="{n.y + 19:.0f}">{_e(_short(n.label))}</text></g>')
            out.append(f'<a href="{_e(n.url)}">{body}</a>' if n.url else body)
    out.append("</svg>")
    return mark_safe("".join(out))  # noqa: S308  # nosec B308 B703 - labels and URLs are escaped with _e()


def shared_mitigations(graph: dict, limit: int = 15) -> list[dict]:
    """Mitigations that address more than one weakness, ranked (one control, many risks)."""
    nodes = graph["nodes"]
    ranked = []
    for node in nodes.values():
        if node.column == 2:
            weaknesses = sorted(nodes[k].label for k in node.links)
            if len(weaknesses) < 2:
                continue
            ranked.append({"name": node.label, "detail": node.detail, "weaknesses": weaknesses,
                           "count": len(weaknesses)})
    ranked.sort(key=lambda r: (-r["count"], r["name"].lower()))
    return ranked[:limit]
