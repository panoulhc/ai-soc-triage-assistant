from app.graph_scorer import calculate_graph_risk_score


def test_graph_scorer_returns_score():
    graph = {
        "nodes": [
            {"id": "alert-1", "type": "alert", "risk": "high"},
            {"id": "ip:203.0.113.45", "type": "ip", "risk": "malicious"},
            {"id": "mitre:T1110", "type": "mitre_technique", "risk": "medium"},
        ],
        "edges": [
            {
                "source": "alert-1",
                "target": "ip:203.0.113.45",
                "relationship": "contains_ioc",
            },
            {
                "source": "alert-1",
                "target": "mitre:T1110",
                "relationship": "mapped_to",
            },
        ],
    }

    result = calculate_graph_risk_score(graph)

    assert "score" in result
    assert "level" in result
    assert result["score"] >= 70
    assert result["level"] in {"high", "critical"}


def test_empty_graph_score():
    graph = {
        "nodes": [],
        "edges": [],
    }

    result = calculate_graph_risk_score(graph)

    assert result["score"] == 0
    assert result["level"] == "unknown"