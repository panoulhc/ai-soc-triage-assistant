from __future__ import annotations

import json
from typing import Any

from app.claude_triage import triage_with_claude
from app.enrichers import enrich_iocs
from app.ioc_extractor import extract_iocs
from app.report_gen import generate_markdown_report
from app.schemas import AnalysisResult
from app.triage_rules import (
    detect_prompt_injection_markers,
    rule_based_triage,
)


def parse_alert_json(raw: str) -> dict[str, Any]:
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValueError(f"Invalid JSON alert: {exc}") from exc

    if not isinstance(parsed, dict):
        raise ValueError("Alert JSON must be an object/dictionary.")

    return parsed


def analyze_alert(alert: dict[str, Any], use_claude: bool = False) -> AnalysisResult:
    raw_text = json.dumps(alert, indent=2, sort_keys=True)

    prompt_injection_markers = detect_prompt_injection_markers(raw_text)

    iocs = extract_iocs(alert)
    enrichments = enrich_iocs(iocs)

    rule_output = rule_based_triage(
        alert=alert,
        iocs=iocs,
        enrichments=enrichments,
        prompt_injection_markers=prompt_injection_markers,
    )

    if use_claude:
        triage = triage_with_claude(
            alert=alert,
            iocs=iocs,
            enrichments=enrichments,
            rule_based_output=rule_output,
            prompt_injection_markers=prompt_injection_markers,
        )
    else:
        triage = rule_output

    report = generate_markdown_report(
        alert=alert,
        iocs=iocs,
        enrichments=enrichments,
        triage=triage,
        prompt_injection_markers=prompt_injection_markers,
    )

    return AnalysisResult(
        alert=alert,
        iocs=iocs,
        enrichments=enrichments,
        triage=triage,
        prompt_injection_markers=prompt_injection_markers,
        report_markdown=report,
    )