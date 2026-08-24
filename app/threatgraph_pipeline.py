"""
ThreatGraph AI pipeline.

Connects the graph builder, risk scorer, and graph summarizer into one workflow.
"""

from __future__ import annotations

from typing import Any, Dict, List

from app.threat_graph import build_threat_graph, get_graph_stats
from app.graph_scorer import calculate_graph_risk_score
from app.graph_summarizer import summarize_graph


def run_threatgraph_analysis(
    alert: Dict[str, Any],
    extracted_iocs: List[Any],
    enrichment_results: Dict[str, Dict[str, Any]],
    triage_result: Dict[str, Any],
    use_claude: bool = False,
) -> Dict[str, Any]:
    """
    Runs ThreatGraph AI analysis.

    Returns:
        {
            "graph": {...},
            "graph_stats": {...},
            "graph_risk": {...},
            "graph_summary": "..."
        }
    """

    graph = build_threat_graph(
        alert=alert,
        extracted_iocs=extracted_iocs,
        enrichment_results=enrichment_results,
        triage_result=triage_result,
    )

    graph_stats = get_graph_stats(graph)
    graph_risk = calculate_graph_risk_score(graph)

    graph_summary = summarize_graph(
        graph=graph,
        risk_result=graph_risk,
        use_claude=use_claude,
    )

    return {
        "graph": graph,
        "graph_stats": graph_stats,
        "graph_risk": graph_risk,
        "graph_summary": graph_summary,
    }