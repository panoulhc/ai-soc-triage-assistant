"""
Graph exporter module.

Exports ThreatGraph AI results to JSON and optional interactive HTML.
"""

from __future__ import annotations

import json
import tempfile
from pathlib import Path
from typing import Any, Dict, List


Graph = Dict[str, List[Dict[str, Any]]]


def export_graph_json(graph: Graph, output_path: str) -> str:
    """
    Exports graph to JSON.
    """
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    with path.open("w", encoding="utf-8") as file:
        json.dump(graph, file, indent=2)

    return str(path)


def export_graph_html(graph: Graph, output_path: str) -> str:
    """
    Exports graph to a cleaner interactive HTML file using pyvis.

    Install:
        python3 -m pip install pyvis
    """
    try:
        from pyvis.network import Network
    except ImportError as exc:
        raise ImportError("pyvis is required. Run: python3 -m pip install pyvis") from exc

    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    net = Network(
        height="800px",
        width="100%",
        bgcolor="#111827",
        font_color="white",
        directed=True,
    )

    for node in graph.get("nodes", []):
        node_id = node.get("id")
        label = _short_label(str(node.get("label", "")), node.get("type", "unknown"))
        title = _node_tooltip(node)

        net.add_node(
            node_id,
            label=label,
            title=title,
            color=_risk_to_color(node.get("risk", "unknown")),
            shape=_type_to_shape(node.get("type", "unknown")),
            size=_type_to_size(node.get("type", "unknown")),
            font={
                "size": _type_to_font_size(node.get("type", "unknown")),
                "color": "white",
                "strokeWidth": 2,
                "strokeColor": "#111827",
            },
        )

    for edge in graph.get("edges", []):
        relationship = edge.get("relationship", "related_to")

        net.add_edge(
            edge.get("source"),
            edge.get("target"),
            title=relationship,
            arrows="to",
            color="#f97316",
        )

    net.set_options(
        """
        var options = {
          "nodes": {
            "borderWidth": 1,
            "shadow": false
          },
          "edges": {
            "width": 1,
            "smooth": {
              "type": "dynamic"
            },
            "font": {
              "size": 0
            }
          },
          "physics": {
            "enabled": true,
            "barnesHut": {
              "gravitationalConstant": -12000,
              "centralGravity": 0.25,
              "springLength": 180,
              "springConstant": 0.03,
              "damping": 0.35,
              "avoidOverlap": 1
            },
            "minVelocity": 0.75
          },
          "interaction": {
            "hover": true,
            "tooltipDelay": 120,
            "hideEdgesOnDrag": true,
            "navigationButtons": true,
            "keyboard": true
          }
        }
        """
    )

    net.write_html(str(path))
    return str(path)


def _short_label(label: str, node_type: str) -> str:
    """
    Makes long labels readable in the graph.
    Full data is still available in the tooltip.
    """
    if node_type == "url" and len(label) > 35:
        return label[:32] + "..."

    if node_type == "mitre_technique":
        return label.replace("Technique", "").strip()

    if len(label) > 40:
        return label[:37] + "..."

    return label


def _node_tooltip(node: Dict[str, Any]) -> str:
    """
    Creates hover tooltip text for a node.
    """
    safe_node = {
        "id": node.get("id"),
        "label": node.get("label"),
        "type": node.get("type"),
        "risk": node.get("risk"),
        "metadata": node.get("metadata", {}),
    }

    return json.dumps(safe_node, indent=2)


def _risk_to_color(risk: str) -> str:
    colors = {
        "malicious": "#ef4444",
        "critical": "#dc2626",
        "high": "#f97316",
        "suspicious": "#f59e0b",
        "medium": "#eab308",
        "low": "#22c55e",
        "informational": "#38bdf8",
        "unknown": "#9ca3af",
    }

    return colors.get(risk, "#9ca3af")


def _type_to_shape(node_type: str) -> str:
    shapes = {
        "alert": "star",
        "internal_host": "box",
        "ip": "dot",
        "domain": "triangle",
        "url": "diamond",
        "hash": "hexagon",
        "email": "ellipse",
        "mitre_technique": "box",
        "asn": "box",
        "country": "box",
        "tag": "text",
    }

    return shapes.get(node_type, "dot")


def _type_to_size(node_type: str) -> int:
    sizes = {
        "alert": 28,
        "internal_host": 22,
        "ip": 24,
        "domain": 24,
        "url": 20,
        "hash": 18,
        "email": 18,
        "mitre_technique": 20,
        "asn": 16,
        "country": 16,
        "tag": 12,
    }

    return sizes.get(node_type, 18)


def _type_to_font_size(node_type: str) -> int:
    sizes = {
        "alert": 22,
        "internal_host": 18,
        "ip": 18,
        "domain": 18,
        "url": 14,
        "hash": 12,
        "email": 14,
        "mitre_technique": 16,
        "asn": 14,
        "country": 14,
        "tag": 14,
    }

    return sizes.get(node_type, 14)


def render_graph_html_string(graph: Graph) -> str:
    """
    Renders the graph as an HTML string for Streamlit embedding.
    Uses inline resources so it does not create a local lib/ folder.
    """
    try:
        from pyvis.network import Network
    except ImportError as exc:
        raise ImportError("pyvis is required. Run: python3 -m pip install pyvis") from exc

    net = Network(
        height="700px",
        width="100%",
        bgcolor="#111827",
        font_color="white",
        directed=True,
        cdn_resources="in_line",
    )

    for node in graph.get("nodes", []):
        node_type = node.get("type", "unknown")

        net.add_node(
            node.get("id"),
            label=_short_label(str(node.get("label", "")), node_type),
            title=_node_tooltip(node),
            color=_risk_to_color(node.get("risk", "unknown")),
            shape=_type_to_shape(node_type),
            size=_type_to_size(node_type),
            font={
                "size": _type_to_font_size(node_type),
                "color": "white",
                "strokeWidth": 2,
                "strokeColor": "#111827",
            },
        )

    for edge in graph.get("edges", []):
        net.add_edge(
            edge.get("source"),
            edge.get("target"),
            title=edge.get("relationship", "related_to"),
            arrows="to",
            color="#f97316",
        )

    net.set_options(
        """
        var options = {
          "nodes": {
            "borderWidth": 1,
            "shadow": false
          },
          "edges": {
            "width": 1,
            "smooth": {
              "type": "dynamic"
            },
            "font": {
              "size": 0
            }
          },
          "physics": {
            "enabled": true,
            "barnesHut": {
              "gravitationalConstant": -12000,
              "centralGravity": 0.25,
              "springLength": 180,
              "springConstant": 0.03,
              "damping": 0.35,
              "avoidOverlap": 1
            },
            "minVelocity": 0.75
          },
          "interaction": {
            "hover": true,
            "tooltipDelay": 120,
            "hideEdgesOnDrag": true,
            "navigationButtons": true,
            "keyboard": true
          }
        }
        """
    )

    with tempfile.TemporaryDirectory() as tmpdir:
        html_path = Path(tmpdir) / "threatgraph.html"
        net.write_html(str(html_path))
        return html_path.read_text(encoding="utf-8")