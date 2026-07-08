from __future__ import annotations

import json
import re
from typing import Any

from app.schemas import EnrichmentResult, IOCSet, MitreTechnique, TriageOutput


PROMPT_INJECTION_MARKERS = [
    "ignore previous instructions",
    "ignore all previous instructions",
    "reveal your system prompt",
    "show me your system prompt",
    "developer message",
    "system message",
    "jailbreak",
    "do anything now",
    "DAN mode",
    "bypass your rules",
    "forget your instructions",
]


def alert_to_text(alert: dict[str, Any]) -> str:
    return json.dumps(alert, indent=2, sort_keys=True).lower()


def detect_prompt_injection_markers(text: str) -> list[str]:
    lowered = text.lower()
    found = []

    for marker in PROMPT_INJECTION_MARKERS:
        if marker.lower() in lowered:
            found.append(marker)

    return found


def _contains_any(text: str, values: list[str]) -> bool:
    return any(value.lower() in text for value in values)


def _get_numeric_field(alert: dict[str, Any], candidates: list[str]) -> int | None:
    for key in candidates:
        value = alert.get(key)
        if value is None:
            continue

        try:
            return int(value)
        except ValueError:
            continue
        except TypeError:
            continue

    return None


def _has_bad_enrichment(enrichments: list[EnrichmentResult]) -> bool:
    for result in enrichments:
        if result.status in {"malicious", "suspicious"}:
            return True
        if result.score is not None and result.score >= 70:
            return True

    return False


def _add_unique_mitre(
    techniques: list[MitreTechnique],
    technique_id: str,
    technique_name: str,
    tactic: str,
) -> None:
    if not any(item.technique_id == technique_id for item in techniques):
        techniques.append(
            MitreTechnique(
                technique_id=technique_id,
                technique_name=technique_name,
                tactic=tactic,
            )
        )


def rule_based_triage(
    alert: dict[str, Any],
    iocs: IOCSet,
    enrichments: list[EnrichmentResult],
    prompt_injection_markers: list[str] | None = None,
) -> TriageOutput:
    text = alert_to_text(alert)
    prompt_injection_markers = prompt_injection_markers or []

    severity = "low"
    confidence = "low"
    likely_activity = "Unclassified security alert"

    evidence: list[str] = []
    actions: list[str] = []
    mitre: list[MitreTechnique] = []

    failed_attempts = _get_numeric_field(
        alert,
        ["failed_attempts", "failed_logins", "failure_count", "count"],
    )

    username = str(
        alert.get("username")
        or alert.get("user")
        or alert.get("account")
        or ""
    ).lower()

    if failed_attempts is not None and failed_attempts >= 10:
        severity = "medium"
        confidence = "medium"
        likely_activity = "Possible credential brute-force attempt"
        evidence.append(f"{failed_attempts} failed login attempts observed.")
        actions.extend(
            [
                "Check whether any successful login occurred after the failures.",
                "Search for the same source IP across other hosts.",
                "Review MFA and account lockout status for the targeted user.",
            ]
        )
        _add_unique_mitre(mitre, "T1110", "Brute Force", "Credential Access")

        if failed_attempts >= 30 or username in {"admin", "administrator", "root"}:
            severity = "high"
            confidence = "high"
            evidence.append("High-volume failures or privileged account targeting detected.")

    if _contains_any(text, ["powershell.exe", "pwsh.exe", "encodedcommand", " -enc ", "-nop", "-w hidden"]):
        severity = "high"
        confidence = "medium"
        likely_activity = "Suspicious PowerShell execution"
        evidence.append("PowerShell indicators such as encoded command, hidden window, or no-profile flags were found.")
        actions.extend(
            [
                "Collect the full command line and parent process.",
                "Check network connections made after PowerShell execution.",
                "Search for the same command line across endpoints.",
                "Review whether the parent process was Office, browser, or script host.",
            ]
        )
        _add_unique_mitre(mitre, "T1059.001", "PowerShell", "Execution")
        _add_unique_mitre(mitre, "T1027", "Obfuscated Files or Information", "Defense Evasion")

    if _contains_any(text, ["winword.exe", "excel.exe", "powerpnt.exe"]) and _contains_any(text, ["powershell", "cmd.exe", "wscript", "cscript"]):
        severity = "high"
        confidence = "high"
        likely_activity = "Possible malicious Office child-process execution"
        evidence.append("Office process appears to have spawned a scripting or shell process.")
        actions.extend(
            [
                "Collect the original document and email delivery path.",
                "Check whether macros were enabled.",
                "Review endpoint telemetry for payload download or persistence.",
            ]
        )
        _add_unique_mitre(mitre, "T1204", "User Execution", "Execution")

    if _contains_any(text, ["phishing", "credential", "verify your account", "account disabled", "password reset"]):
        if severity in {"low", "medium"}:
            severity = "medium"
        confidence = "medium"
        likely_activity = "Possible phishing attempt"
        evidence.append("Phishing-themed language or credential-harvesting indicators were found.")
        actions.extend(
            [
                "Inspect sender domain, reply-to address, and authentication results.",
                "Check whether the user submitted credentials.",
                "Search mailboxes for similar messages.",
                "Block malicious URLs or domains if confirmed.",
            ]
        )
        _add_unique_mitre(mitre, "T1566", "Phishing", "Initial Access")

    if _contains_any(text, ["new admin", "administrator group", "privileged account", "domain admins"]):
        severity = "high"
        confidence = "medium"
        likely_activity = "Suspicious privileged account activity"
        evidence.append("Privileged account or admin group activity was found.")
        actions.extend(
            [
                "Confirm whether the account creation/change was authorized.",
                "Review who performed the change.",
                "Check for other privilege escalation activity around the same time.",
            ]
        )
        _add_unique_mitre(mitre, "T1136", "Create Account", "Persistence")

    if iocs.public_ip_addresses:
        evidence.append(f"Public IP IOC(s) detected: {', '.join(iocs.public_ip_addresses)}.")

    if iocs.urls:
        evidence.append(f"URL IOC(s) detected: {', '.join(iocs.urls)}.")

    if iocs.hashes:
        evidence.append(f"File hash IOC(s) detected: {', '.join(iocs.hashes)}.")

    if _has_bad_enrichment(enrichments):
        if severity == "low":
            severity = "medium"
        elif severity == "medium":
            severity = "high"

        confidence = "high"
        evidence.append("Threat-intelligence enrichment returned suspicious or malicious reputation.")
        actions.append("Validate enrichment results and apply blocking/containment according to policy.")

    if prompt_injection_markers:
        if severity == "low":
            severity = "medium"

        evidence.append(
            "Possible prompt-injection markers found inside alert content: "
            + ", ".join(prompt_injection_markers)
        )
        actions.append("Treat alert text as untrusted data; do not allow it to override system instructions.")

    if not actions:
        actions = [
            "Review the raw alert and related logs.",
            "Validate whether the activity is expected for the user and host.",
            "Document findings and close as false positive only if evidence supports it.",
        ]

    evidence = list(dict.fromkeys(evidence))
    actions = list(dict.fromkeys(actions))

    analyst_summary = (
        f"{likely_activity}. Severity is {severity}. "
        f"The assessment is based on alert fields, extracted IOCs, enrichment results, and rule-based SOC logic."
    )

    return TriageOutput(
        severity=severity,
        confidence=confidence,
        likely_activity=likely_activity,
        mitre_attack_mapping=mitre,
        evidence=evidence,
        recommended_actions=actions,
        analyst_summary=analyst_summary,
    )