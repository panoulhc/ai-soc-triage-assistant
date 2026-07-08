from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

from app.schemas import EnrichmentResult, IOCSet, TriageOutput


def _table_row(values: list[str]) -> str:
    escaped = [str(value).replace("\n", " ").replace("|", "\\|") for value in values]
    return "| " + " | ".join(escaped) + " |"


def generate_markdown_report(
    alert: dict[str, Any],
    iocs: IOCSet,
    enrichments: list[EnrichmentResult],
    triage: TriageOutput,
    prompt_injection_markers: list[str],
) -> str:
    generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    lines: list[str] = []

    lines.append("# SOC Alert Triage Report")
    lines.append("")
    lines.append(f"**Generated:** {generated_at}")
    lines.append("")
    lines.append("## 1. Triage Verdict")
    lines.append("")
    lines.append(f"- **Severity:** {triage.severity.upper()}")
    lines.append(f"- **Confidence:** {triage.confidence.upper()}")
    lines.append(f"- **Likely Activity:** {triage.likely_activity}")
    lines.append("")
    lines.append("## 2. Analyst Summary")
    lines.append("")
    lines.append(triage.analyst_summary)
    lines.append("")

    lines.append("## 3. Evidence")
    lines.append("")
    if triage.evidence:
        for item in triage.evidence:
            lines.append(f"- {item}")
    else:
        lines.append("- No strong evidence generated.")
    lines.append("")

    lines.append("## 4. MITRE ATT&CK Mapping")
    lines.append("")
    if triage.mitre_attack_mapping:
        lines.append(_table_row(["Technique ID", "Technique Name", "Tactic"]))
        lines.append(_table_row(["---", "---", "---"]))
        for item in triage.mitre_attack_mapping:
            lines.append(
                _table_row(
                    [
                        item.technique_id,
                        item.technique_name,
                        item.tactic,
                    ]
                )
            )
    else:
        lines.append("No confident MITRE mapping.")
    lines.append("")

    lines.append("## 5. Extracted IOCs")
    lines.append("")
    lines.append(f"- **Public IPs:** {', '.join(iocs.public_ip_addresses) or 'None'}")
    lines.append(f"- **Private IPs:** {', '.join(iocs.private_ip_addresses) or 'None'}")
    lines.append(f"- **Domains:** {', '.join(iocs.domains) or 'None'}")
    lines.append(f"- **URLs:** {', '.join(iocs.urls) or 'None'}")
    lines.append(f"- **Hashes:** {', '.join(iocs.hashes) or 'None'}")
    lines.append(f"- **Emails:** {', '.join(iocs.emails) or 'None'}")
    lines.append("")

    lines.append("## 6. IOC Enrichment")
    lines.append("")
    if enrichments:
        lines.append(_table_row(["IOC", "Type", "Source", "Status", "Score", "Summary"]))
        lines.append(_table_row(["---", "---", "---", "---", "---", "---"]))
        for item in enrichments:
            lines.append(
                _table_row(
                    [
                        item.ioc,
                        item.ioc_type,
                        item.source,
                        item.status,
                        str(item.score if item.score is not None else "N/A"),
                        item.summary,
                    ]
                )
            )
    else:
        lines.append("No enrichment results.")
    lines.append("")

    lines.append("## 7. Recommended Next Steps")
    lines.append("")
    for index, action in enumerate(triage.recommended_actions, start=1):
        lines.append(f"{index}. {action}")
    lines.append("")

    lines.append("## 8. Prompt-Injection Safety Check")
    lines.append("")
    if prompt_injection_markers:
        lines.append("Potential prompt-injection markers were found inside the alert content:")
        lines.append("")
        for marker in prompt_injection_markers:
            lines.append(f"- `{marker}`")
    else:
        lines.append("No obvious prompt-injection markers were detected in the alert content.")
    lines.append("")

    lines.append("## 9. Raw Alert")
    lines.append("")
    lines.append("```json")
    lines.append(json.dumps(alert, indent=2))
    lines.append("```")
    lines.append("")

    return "\n".join(lines)