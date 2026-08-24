from app.threat_graph import build_threat_graph, get_graph_stats


def test_build_threat_graph_creates_nodes_and_edges():
    alert = {
        "id": "alert-test",
        "title": "Suspicious Connection",
        "severity": "high",
        "host": "workstation-1",
    }

    extracted_iocs = [
        {"value": "203.0.113.45", "type": "ip"},
        {"value": "evil.example", "type": "domain"},
    ]

    enrichment_results = {
        "203.0.113.45": {
            "reputation": -10,
            "country": "US",
            "asn": 64500,
            "last_analysis_stats": {
                "malicious": 2,
                "suspicious": 1,
            },
            "tags": ["phishing", "malware"],
        },
        "evil.example": {
            "reputation": -5,
            "last_analysis_stats": {
                "malicious": 1,
                "suspicious": 1,
            },
        },
    }

    triage_result = {
        "severity": "high",
        "mitre_techniques": [
            {"id": "T1110", "name": "Brute Force"}
        ],
    }

    graph = build_threat_graph(
        alert=alert,
        extracted_iocs=extracted_iocs,
        enrichment_results=enrichment_results,
        triage_result=triage_result,
    )

    assert "nodes" in graph
    assert "edges" in graph
    assert len(graph["nodes"]) >= 5
    assert len(graph["edges"]) >= 4


def test_graph_stats():
    graph = {
        "nodes": [
            {"id": "1", "type": "alert", "risk": "high"},
            {"id": "2", "type": "ip", "risk": "suspicious"},
        ],
        "edges": [
            {"source": "1", "target": "2", "relationship": "contains_ioc"}
        ],
    }

    stats = get_graph_stats(graph)

    assert stats["node_count"] == 2
    assert stats["edge_count"] == 1
    assert stats["type_counts"]["alert"] == 1
    assert stats["type_counts"]["ip"] == 1