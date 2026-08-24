"""
ThreatGraph AI module.

Builds a relationship graph from:
- original alert
- extracted IOCs
- enrichment results
- triage/MITRE results

The output is simple JSON:
{
    "nodes": [...],
    "edges": [...]
}
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional
import hashlib


Graph = Dict[str, List[Dict[str, Any]]]


def _safe_id(value: str) -> str:
    """
    Creates a safe fallback ID for graph nodes.
    """
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:12]


def _add_node(
    nodes: Dict[str, Dict[str, Any]],
    node_id: str,
    label: str,
    node_type: str,
    risk: str = "unknown",
    metadata: Optional[Dict[str, Any]] = None,
) -> None:
    """
    Adds or updates a graph node.
    """
    if not node_id:
        node_id = _safe_id(label)

    if node_id not in nodes:
        nodes[node_id] = {
            "id": node_id,
            "label": label,
            "type": node_type,
            "risk": risk,
            "metadata": metadata or {},
        }
    else:
        existing = nodes[node_id]
        existing["metadata"].update(metadata or {})

        # Upgrade risk if needed
        risk_priority = {
            "unknown": 0,
            "low": 1,
            "medium": 2,
            "suspicious": 3,
            "high": 4,
            "critical": 5,
            "malicious": 5,
        }

        if risk_priority.get(risk, 0) > risk_priority.get(existing.get("risk", "unknown"), 0):
            existing["risk"] = risk


def _add_edge(
    edges: List[Dict[str, Any]],
    source: str,
    target: str,
    relationship: str,
    metadata: Optional[Dict[str, Any]] = None,
) -> None:
    """
    Adds a relationship between two graph nodes.
    Avoids duplicate edges.
    """
    edge = {
        "source": source,
        "target": target,
        "relationship": relationship,
        "metadata": metadata or {},
    }

    if edge not in edges:
        edges.append(edge)


def _guess_ioc_type(ioc: str) -> str:
    """
    Guesses IOC type from value.
    """
    value = ioc.lower()

    if value.startswith("http://") or value.startswith("https://"):
        return "url"

    if len(value) in {32, 40, 64} and all(c in "0123456789abcdef" for c in value):
        return "hash"

    if "@" in value:
        return "email"

    if value.count(".") == 3 and all(part.isdigit() for part in value.split(".")):
        return "ip"

    if "." in value:
        return "domain"

    return "ioc"


def _risk_from_enrichment(enrichment: Dict[str, Any]) -> str:
    """
    Calculates simple risk label from enrichment results.
    Works with flexible VirusTotal-like dictionaries.
    """
    if not enrichment:
        return "unknown"

    stats = enrichment.get("last_analysis_stats", {})
    malicious = int(stats.get("malicious", 0) or 0)
    suspicious = int(stats.get("suspicious", 0) or 0)

    reputation = int(enrichment.get("reputation", 0) or 0)

    if malicious >= 5 or reputation <= -20:
        return "malicious"

    if malicious >= 1 or suspicious >= 3 or reputation < 0:
        return "suspicious"

    if suspicious >= 1:
        return "medium"

    return "low"


def build_threat_graph(
    alert: Dict[str, Any],
    extracted_iocs: Optional[List[Any]] = None,
    enrichment_results: Optional[Dict[str, Dict[str, Any]]] = None,
    triage_result: Optional[Dict[str, Any]] = None,
) -> Graph:
    """
    Builds the ThreatGraph JSON.

    Parameters:
        alert:
            Original alert dictionary.

        extracted_iocs:
            Can be:
            - ["1.2.3.4", "evil.com"]
            - [{"value": "1.2.3.4", "type": "ip"}]

        enrichment_results:
            Dictionary keyed by IOC value:
            {
                "1.2.3.4": {
                    "reputation": -5,
                    "last_analysis_stats": {"malicious": 3, "suspicious": 1},
                    "asn": 12345,
                    "country": "US"
                }
            }

        triage_result:
            Optional triage/MITRE result dictionary.

    Returns:
        {
            "nodes": [...],
            "edges": [...]
        }
    """
    nodes: Dict[str, Dict[str, Any]] = {}
    edges: List[Dict[str, Any]] = []

    extracted_iocs = extracted_iocs or []
    enrichment_results = enrichment_results or {}
    triage_result = triage_result or {}

    alert_id = str(alert.get("id") or alert.get("alert_id") or "alert-root")
    alert_title = str(alert.get("title") or alert.get("name") or "Security Alert")
    alert_severity = str(alert.get("severity") or triage_result.get("severity") or "unknown").lower()

    _add_node(
        nodes,
        node_id=alert_id,
        label=alert_title,
        node_type="alert",
        risk=alert_severity,
        metadata={
            "source": alert.get("source"),
            "description": alert.get("description"),
            "timestamp": alert.get("timestamp"),
        },
    )

    internal_host = alert.get("host") or alert.get("hostname") or alert.get("internal_host")
    if internal_host:
        host_id = f"host:{internal_host}"
        _add_node(
            nodes,
            node_id=host_id,
            label=str(internal_host),
            node_type="internal_host",
            risk="medium",
        )
        _add_edge(edges, alert_id, host_id, "observed_on")

    for item in extracted_iocs:
        if isinstance(item, dict):
            ioc_value = str(item.get("value") or item.get("ioc") or "")
            ioc_type = str(item.get("type") or _guess_ioc_type(ioc_value))
        else:
            ioc_value = str(item)
            ioc_type = _guess_ioc_type(ioc_value)

        if not ioc_value:
            continue

        enrichment = enrichment_results.get(ioc_value, {})
        ioc_risk = _risk_from_enrichment(enrichment)
        ioc_id = f"{ioc_type}:{ioc_value}"

        _add_node(
            nodes,
            node_id=ioc_id,
            label=ioc_value,
            node_type=ioc_type,
            risk=ioc_risk,
            metadata={
                "enrichment": enrichment,
            },
        )

        _add_edge(edges, alert_id, ioc_id, "contains_ioc")

        if internal_host:
            _add_edge(edges, f"host:{internal_host}", ioc_id, "communicated_with")

        # Add enrichment context nodes
        asn = enrichment.get("asn") or enrichment.get("as_owner")
        if asn:
            asn_id = f"asn:{asn}"
            _add_node(nodes, asn_id, str(asn), "asn", "unknown")
            _add_edge(edges, ioc_id, asn_id, "belongs_to_asn")

        country = enrichment.get("country")
        if country:
            country_id = f"country:{country}"
            _add_node(nodes, country_id, str(country), "country", "unknown")
            _add_edge(edges, ioc_id, country_id, "located_in")

        tags = enrichment.get("tags", [])
        if isinstance(tags, list):
            for tag in tags[:5]:
                tag_id = f"tag:{tag}"
                _add_node(nodes, tag_id, str(tag), "tag", "unknown")
                _add_edge(edges, ioc_id, tag_id, "has_tag")

        # Related indicators, if you add them later from VirusTotal relationships
        related = enrichment.get("related", [])
        if isinstance(related, list):
            for related_ioc in related[:10]:
                related_value = str(related_ioc)
                related_type = _guess_ioc_type(related_value)
                related_id = f"{related_type}:{related_value}"

                _add_node(
                    nodes,
                    node_id=related_id,
                    label=related_value,
                    node_type=related_type,
                    risk="unknown",
                )

                _add_edge(edges, ioc_id, related_id, "related_to")

    # Add MITRE technique nodes if present
    mitre_techniques = (
        triage_result.get("mitre_techniques")
        or triage_result.get("mitre")
        or alert.get("mitre_techniques")
        or []
    )

    if isinstance(mitre_techniques, list):
        for technique in mitre_techniques:
            if isinstance(technique, dict):
                tech_id_raw = str(technique.get("id") or technique.get("technique_id") or "")
                tech_name = str(technique.get("name") or tech_id_raw)
            else:
                tech_id_raw = str(technique)
                tech_name = tech_id_raw

            if not tech_id_raw:
                continue

            tech_id = f"mitre:{tech_id_raw}"

            _add_node(
                nodes,
                node_id=tech_id,
                label=f"{tech_id_raw} {tech_name}",
                node_type="mitre_technique",
                risk="medium",
            )

            _add_edge(edges, alert_id, tech_id, "mapped_to")

    return {
        "nodes": list(nodes.values()),
        "edges": edges,
    }


def get_graph_stats(graph: Graph) -> Dict[str, Any]:
    """
    Returns quick stats for dashboard display.
    """
    nodes = graph.get("nodes", [])
    edges = graph.get("edges", [])

    type_counts: Dict[str, int] = {}
    risk_counts: Dict[str, int] = {}

    for node in nodes:
        node_type = node.get("type", "unknown")
        risk = node.get("risk", "unknown")

        type_counts[node_type] = type_counts.get(node_type, 0) + 1
        risk_counts[risk] = risk_counts.get(risk, 0) + 1

    return {
        "node_count": len(nodes),
        "edge_count": len(edges),
        "type_counts": type_counts,
        "risk_counts": risk_counts,
    }