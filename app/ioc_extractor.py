from __future__ import annotations

import ipaddress
import json
import re
from urllib.parse import urlparse

from app.schemas import IOCSet


IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

URL_RE = re.compile(
    r"https?://[^\s\"'<>]+",
    re.IGNORECASE,
)

EMAIL_RE = re.compile(
    r"\b[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+\b",
    re.IGNORECASE,
)

HASH_RE = re.compile(
    r"\b[a-fA-F0-9]{32}\b|\b[a-fA-F0-9]{40}\b|\b[a-fA-F0-9]{64}\b"
)

DOMAIN_RE = re.compile(
    r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b",
    re.IGNORECASE,
)

IGNORED_FAKE_TLDS = {
    "exe",
    "dll",
    "ps1",
    "bat",
    "cmd",
    "vbs",
    "js",
    "json",
    "local",
}


def _dedupe(items: list[str]) -> list[str]:
    seen = set()
    output = []

    for item in items:
        normalized = item.strip().strip(".,;:)]}>'\"").lower()
        if normalized and normalized not in seen:
            seen.add(normalized)
            output.append(normalized)

    return output


def _to_text(data: dict | str) -> str:
    if isinstance(data, str):
        return data

    return json.dumps(data, indent=2, sort_keys=True)


def is_valid_ip(ip: str) -> bool:
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def is_public_ip(ip: str) -> bool:
    try:
        parsed = ipaddress.ip_address(ip)
        return not (
            parsed.is_private
            or parsed.is_loopback
            or parsed.is_reserved
            or parsed.is_link_local
            or parsed.is_multicast
            or parsed.is_unspecified
        )
    except ValueError:
        return False


def _extract_domains_from_urls(urls: list[str]) -> list[str]:
    domains = []

    for url in urls:
        try:
            parsed = urlparse(url)
            if parsed.hostname:
                domains.append(parsed.hostname)
        except Exception:
            continue

    return domains


def _filter_domains(domains: list[str]) -> list[str]:
    clean = []

    for domain in domains:
        domain = domain.lower().strip().strip(".,;:)]}>'\"")
        if not domain or "." not in domain:
            continue

        tld = domain.rsplit(".", 1)[-1]
        if tld in IGNORED_FAKE_TLDS:
            continue

        if is_valid_ip(domain):
            continue

        clean.append(domain)

    return _dedupe(clean)


def extract_iocs(alert: dict | str) -> IOCSet:
    text = _to_text(alert)

    raw_ips = _dedupe(IPV4_RE.findall(text))
    valid_ips = [ip for ip in raw_ips if is_valid_ip(ip)]

    public_ips = [ip for ip in valid_ips if is_public_ip(ip)]
    private_ips = [ip for ip in valid_ips if not is_public_ip(ip)]

    urls = _dedupe(URL_RE.findall(text))
    emails = _dedupe(EMAIL_RE.findall(text))
    hashes = _dedupe(HASH_RE.findall(text))

    domains_from_urls = _extract_domains_from_urls(urls)
    domains_from_text = DOMAIN_RE.findall(text)

    domains = _filter_domains(domains_from_urls + domains_from_text)

    return IOCSet(
        ip_addresses=valid_ips,
        public_ip_addresses=public_ips,
        private_ip_addresses=private_ips,
        domains=domains,
        urls=urls,
        hashes=hashes,
        emails=emails,
    )