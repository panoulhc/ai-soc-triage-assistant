"""
Graph scoring module.

Calculates a risk score for the full ThreatGraph.
"""

from __future__ import annotations

from typing import Any, Dict, List


Graph = Dict[str, List[Dict[str, Any]]]


RISK_WEIGHTS = {
    "unknown": 0,
    "low": 5,
    "medium": 20,
    "suspicious": 35,
    "high": 60,
    "critical": 85,
    "malicious": 90,
}


def calculate_graph_risk_score(graph: Graph) -> Dict[str, Any]:
    """
    Calculates total graph risk score from 0-100.
    """
    nodes = graph.get("nodes", [])
    edges = graph.get("edges", [])

    if not nodes:
        return {
            "score": 0,
            "level": "unknown",
            "reasons": ["No graph nodes found."],
        }

    score = 0
    reasons = []

    malicious_nodes = 0
    suspicious_nodes = 0
    mitre_nodes = 0
    ioc_nodes = 0

    for node in nodes:
        node_type = node.get("type", "unknown")
        risk = node.get("risk", "unknown")

        score += RISK_WEIGHTS.get(risk, 0)

        if risk in {"malicious", "critical"}:
            malicious_nodes += 1

        if risk in {"suspicious", "high"}:
            suspicious_nodes += 1

        if node_type == "mitre_technique":
            mitre_nodes += 1

        if node_type in {"ip", "domain", "url", "hash", "email", "ioc"}:
            ioc_nodes += 1

    # Relationship complexity adds risk
    if len(edges) >= 5:
        score += 10
        reasons.append("Multiple relationships were observed between alert entities.")

    if len(edges) >= 10:
        score += 15
        reasons.append("The graph shows a complex investigation pattern.")

    if malicious_nodes:
        score += malicious_nodes * 20
        reasons.append(f"{malicious_nodes} malicious node(s) were identified.")

    if suspicious_nodes:
        score += suspicious_nodes * 10
        reasons.append(f"{suspicious_nodes} suspicious/high-risk node(s) were identified.")

    if mitre_nodes:
        score += mitre_nodes * 5
        reasons.append(f"{mitre_nodes} MITRE ATT&CK technique mapping(s) were found.")

    if ioc_nodes >= 3:
        score += 10
        reasons.append("Multiple indicators of compromise were extracted from the alert.")

    normalized_score = min(100, int(score / max(1, len(nodes))))

    if malicious_nodes:
        normalized_score = max(normalized_score, 75)

    if suspicious_nodes and normalized_score < 60:
        normalized_score = max(normalized_score, 60)

    level = _score_to_level(normalized_score)

    if not reasons:
        reasons.append("No strong malicious relationships were identified.")

    return {
        "score": normalized_score,
        "level": level,
        "reasons": reasons,
        "stats": {
            "nodes": len(nodes),
            "edges": len(edges),
            "malicious_nodes": malicious_nodes,
            "suspicious_nodes": suspicious_nodes,
            "mitre_nodes": mitre_nodes,
            "ioc_nodes": ioc_nodes,
        },
    }


def _score_to_level(score: int) -> str:
    if score >= 85:
        return "critical"

    if score >= 70:
        return "high"

    if score >= 45:
        return "medium"

    if score >= 20:
        return "low"

    return "informational"