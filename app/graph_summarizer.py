"""
Graph summarizer module.

Creates an analyst-style summary for the ThreatGraph.
Uses Claude if ANTHROPIC_API_KEY exists, otherwise returns a local fallback summary.
"""

from __future__ import annotations

import os
from typing import Any, Dict, List, Optional


Graph = Dict[str, List[Dict[str, Any]]]


def summarize_graph(
    graph: Graph,
    risk_result: Optional[Dict[str, Any]] = None,
    use_claude: bool = True,
) -> str:
    """
    Generates a summary of the graph.
    """
    risk_result = risk_result or {}

    if use_claude and os.getenv("ANTHROPIC_API_KEY"):
        try:
            return _summarize_with_claude(graph, risk_result)
        except Exception as exc:
            return _fallback_summary(graph, risk_result, error=str(exc))

    return _fallback_summary(graph, risk_result)


def _summarize_with_claude(graph: Graph, risk_result: Dict[str, Any]) -> str:
    """
    Claude-powered graph summary.
    """
    from anthropic import Anthropic

    client = Anthropic(api_key=os.getenv("ANTHROPIC_API_KEY"))

    prompt = f"""
You are a SOC analyst. Analyze this threat intelligence graph.

Return a concise incident investigation summary with:
1. What happened
2. Important IOCs
3. Relationship graph interpretation
4. Risk level
5. Recommended next steps

Threat graph:
{graph}

Risk result:
{risk_result}
"""

    response = client.messages.create(
        model=os.getenv("ANTHROPIC_MODEL", "claude-3-5-sonnet-latest"),
        max_tokens=700,
        temperature=0.2,
        messages=[
            {
                "role": "user",
                "content": prompt,
            }
        ],
    )

    return response.content[0].text


def _fallback_summary(
    graph: Graph,
    risk_result: Dict[str, Any],
    error: Optional[str] = None,
) -> str:
    """
    Local summary if Claude is unavailable.
    """
    nodes = graph.get("nodes", [])
    edges = graph.get("edges", [])

    iocs = [
        node for node in nodes
        if node.get("type") in {"ip", "domain", "url", "hash", "email", "ioc"}
    ]

    malicious = [
        node for node in nodes
        if node.get("risk") in {"malicious", "critical"}
    ]

    suspicious = [
        node for node in nodes
        if node.get("risk") in {"suspicious", "high"}
    ]

    mitre = [
        node for node in nodes
        if node.get("type") == "mitre_technique"
    ]

    level = risk_result.get("level", "unknown")
    score = risk_result.get("score", "unknown")

    summary = []
    summary.append("ThreatGraph AI Investigation Summary")
    summary.append("")
    summary.append(f"The graph contains {len(nodes)} node(s) and {len(edges)} relationship(s).")
    summary.append(f"Overall graph risk level: {level} ({score}/100).")
    summary.append("")

    if iocs:
        summary.append("Extracted IOCs:")
        for node in iocs[:8]:
            summary.append(f"- {node.get('label')} ({node.get('type')}, risk: {node.get('risk')})")
        summary.append("")

    if malicious:
        summary.append("High-priority finding:")
        summary.append(f"- {len(malicious)} malicious/critical node(s) were found.")
        summary.append("")

    if suspicious:
        summary.append("Suspicious activity:")
        summary.append(f"- {len(suspicious)} suspicious/high-risk node(s) were found.")
        summary.append("")

    if mitre:
        summary.append("MITRE ATT&CK mapping:")
        for node in mitre[:5]:
            summary.append(f"- {node.get('label')}")
        summary.append("")

    summary.append("Recommended next steps:")
    summary.append("- Review the original alert and affected host.")
    summary.append("- Block or monitor suspicious external indicators.")
    summary.append("- Check DNS, proxy, firewall, and endpoint logs for related activity.")
    summary.append("- Preserve evidence before remediation.")
    summary.append("- Escalate if the same IOCs appear across multiple hosts.")

    if error:
        summary.append("")
        summary.append(f"Claude fallback note: {error}")

    return "\n".join(summary)