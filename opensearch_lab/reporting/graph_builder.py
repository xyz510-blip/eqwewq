"""Entity-relationship graph builder using NetworkX and PyVis."""

from __future__ import annotations

import html
from pathlib import Path
from typing import Any

import networkx as nx
from pyvis.network import Network

from opensearch_lab.core.models import InvestigationReport

ENTITY_COLORS: dict[str, str] = {
    "profile": "#06b6d4",       # Cyan
    "domain": "#a855f7",        # Purple
    "ip": "#f97316",            # Orange
    "port": "#fbbf24",          # Amber
    "cve": "#dc2626",           # Crimson
    "email": "#10b981",         # Emerald
    "phone": "#22c55e",         # Green
    "crypto_wallet": "#eab308", # Gold
    "organization": "#3b82f6",  # Blue
    "username": "#38bdf8",      # Sky
    "url": "#f43f5e",           # Rose
    "full_name": "#818cf8",     # Indigo
    "image_file": "#14b8a6",    # Teal
}


def build_graph_json(report: InvestigationReport) -> dict[str, Any]:
    """Build a JSON-serializable graph dict with degree metrics for the Web UI."""
    g = nx.DiGraph()
    for node in report.entities:
        g.add_node(node.id)
    for edge in report.edges:
        g.add_edge(edge.source, edge.target, relation=edge.relation)

    nodes_out: list[dict[str, Any]] = []
    for node in report.entities:
        is_root = bool(node.metadata.get("is_root"))
        color = "#ef4444" if is_root else ENTITY_COLORS.get(node.entity_type, "#94a3b8")
        deg = g.degree(node.id) if node.id in g else 0
        nodes_out.append(
            {
                "id": node.id,
                "label": node.label,
                "entity_type": node.entity_type,
                "is_root": is_root,
                "color": color,
                "size": 26 if is_root else min(22, 11 + deg * 2),
                "metadata": node.metadata,
            }
        )

    edges_out = [
        {
            "source": e.source,
            "target": e.target,
            "relation": e.relation,
            "weight": e.weight,
        }
        for e in report.edges
    ]
    return {"nodes": nodes_out, "edges": edges_out}


def build_pyvis_html(report: InvestigationReport, output_path: Path | str) -> Path:
    """Generate a standalone interactive dark-mode PyVis HTML entity graph."""
    out = Path(output_path)
    out.parent.mkdir(parents=True, exist_ok=True)

    graph_data = build_graph_json(report)
    net = Network(
        height="760px",
        width="100%",
        directed=True,
        bgcolor="#070d19",
        font_color="#e2e8f0",
        cdn_resources="in_line",
        heading=f"OpenSearch Entity Graph — {html.escape(report.query)} ({report.case_id})",
    )
    net.barnes_hut(gravity=-18000, central_gravity=0.35, spring_length=140, spring_strength=0.05)

    for n in graph_data["nodes"]:
        title_parts = [
            f"<b>{html.escape(str(n['label']))}</b>",
            f"Type: {html.escape(str(n['entity_type']))}",
        ]
        url_meta = (n.get("metadata") or {}).get("url")
        if url_meta:
            title_parts.append(f"URL: {html.escape(str(url_meta))}")
        net.add_node(
            n["id"],
            label=str(n["label"])[:40],
            title="<br>".join(title_parts),
            color=n["color"],
            size=n["size"],
            shape="star" if n["is_root"] else "dot",
            borderWidth=2,
        )

    for e in graph_data["edges"]:
        net.add_edge(
            e["source"],
            e["target"],
            label=str(e["relation"]),
            color="#475569",
            arrows="to",
            font={"size": 10, "color": "#94a3b8", "strokeWidth": 0},
        )

    net.write_html(str(out))
    return out
