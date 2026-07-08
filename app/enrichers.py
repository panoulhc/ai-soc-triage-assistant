from __future__ import annotations

import base64
from typing import Any

import requests

from app.config import settings
from app.schemas import EnrichmentResult, IOCSet


def _safe_get_json(url: str, headers: dict[str, str], params: dict[str, Any] | None = None) -> dict:
    response = requests.get(
        url,
        headers=headers,
        params=params,
        timeout=settings.request_timeout_seconds,
    )
    response.raise_for_status()
    return response.json()


def _mock_enrichment(ioc: str, ioc_type: str) -> EnrichmentResult:
    suspicious_keywords = [
        "malicious",
        "phishing",
        "suspicious",
        "evil",
        "login-reset",
        "fake-login",
    ]

    score = 10
    status = "clean"
    summary = "No live API key configured. Mock enrichment returned low risk."

    lowered = ioc.lower()
    if any(keyword in lowered for keyword in suspicious_keywords):
        score = 75
        status = "suspicious"
        summary = "Mock enrichment flagged this IOC as suspicious based on naming."

    return EnrichmentResult(
        ioc=ioc,
        ioc_type=ioc_type,
        source="mock",
        status=status,
        score=score,
        summary=summary,
        raw={},
    )


def enrich_ip_abuseipdb(ip: str) -> EnrichmentResult | None:
    if not settings.abuseipdb_api_key:
        return None

    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {
        "Key": settings.abuseipdb_api_key,
        "Accept": "application/json",
    }
    params = {
        "ipAddress": ip,
        "maxAgeInDays": "90",
    }

    try:
        data = _safe_get_json(url, headers=headers, params=params)
        body = data.get("data", {})
        score = int(body.get("abuseConfidenceScore", 0))
        total_reports = body.get("totalReports", 0)
        country = body.get("countryCode", "unknown")

        if score >= 80:
            status = "malicious"
        elif score >= 40:
            status = "suspicious"
        else:
            status = "clean"

        return EnrichmentResult(
            ioc=ip,
            ioc_type="ip",
            source="AbuseIPDB",
            status=status,
            score=score,
            summary=f"Abuse score {score}/100, reports: {total_reports}, country: {country}.",
            raw=body,
        )
    except Exception as exc:
        return EnrichmentResult(
            ioc=ip,
            ioc_type="ip",
            source="AbuseIPDB",
            status="error",
            score=None,
            summary=f"AbuseIPDB lookup failed: {exc}",
            raw={},
        )


def _virustotal_headers() -> dict[str, str]:
    return {
        "x-apikey": settings.virustotal_api_key or "",
        "accept": "application/json",
    }


def _vt_stats_to_result(ioc: str, ioc_type: str, stats: dict) -> EnrichmentResult:
    malicious = int(stats.get("malicious", 0))
    suspicious = int(stats.get("suspicious", 0))
    harmless = int(stats.get("harmless", 0))

    score = min(100, malicious * 20 + suspicious * 10)

    if malicious >= 3:
        status = "malicious"
    elif malicious > 0 or suspicious > 0:
        status = "suspicious"
    else:
        status = "clean"

    return EnrichmentResult(
        ioc=ioc,
        ioc_type=ioc_type,
        source="VirusTotal",
        status=status,
        score=score,
        summary=(
            f"VT stats - malicious: {malicious}, suspicious: {suspicious}, "
            f"harmless: {harmless}."
        ),
        raw={"last_analysis_stats": stats},
    )


def enrich_virustotal(ioc: str, ioc_type: str) -> EnrichmentResult | None:
    if not settings.virustotal_api_key:
        return None

    base = "https://www.virustotal.com/api/v3"

    if ioc_type == "ip":
        endpoint = f"{base}/ip_addresses/{ioc}"
    elif ioc_type == "domain":
        endpoint = f"{base}/domains/{ioc}"
    elif ioc_type == "hash":
        endpoint = f"{base}/files/{ioc}"
    elif ioc_type == "url":
        encoded = base64.urlsafe_b64encode(ioc.encode()).decode().strip("=")
        endpoint = f"{base}/urls/{encoded}"
    else:
        return None

    try:
        data = _safe_get_json(endpoint, headers=_virustotal_headers())
        attrs = data.get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        return _vt_stats_to_result(ioc=ioc, ioc_type=ioc_type, stats=stats)
    except Exception as exc:
        return EnrichmentResult(
            ioc=ioc,
            ioc_type=ioc_type,
            source="VirusTotal",
            status="error",
            score=None,
            summary=f"VirusTotal lookup failed: {exc}",
            raw={},
        )


def enrich_iocs(iocs: IOCSet) -> list[EnrichmentResult]:
    results: list[EnrichmentResult] = []

    for ip in iocs.private_ip_addresses:
        results.append(
            EnrichmentResult(
                ioc=ip,
                ioc_type="ip",
                source="local",
                status="internal",
                score=0,
                summary="Private/internal IP address. Skipping public reputation lookup.",
                raw={},
            )
        )

    for ip in iocs.public_ip_addresses:
        abuse_result = enrich_ip_abuseipdb(ip)
        vt_result = enrich_virustotal(ip, "ip")

        results.append(abuse_result or _mock_enrichment(ip, "ip"))
        if vt_result:
            results.append(vt_result)

    for domain in iocs.domains:
        vt_result = enrich_virustotal(domain, "domain")
        results.append(vt_result or _mock_enrichment(domain, "domain"))

    for url in iocs.urls:
        vt_result = enrich_virustotal(url, "url")
        results.append(vt_result or _mock_enrichment(url, "url"))

    for file_hash in iocs.hashes:
        vt_result = enrich_virustotal(file_hash, "hash")
        results.append(vt_result or _mock_enrichment(file_hash, "hash"))

    return results