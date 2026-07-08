from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field


Severity = Literal["low", "medium", "high", "critical"]
Confidence = Literal["low", "medium", "high"]


class IOCSet(BaseModel):
    ip_addresses: list[str] = Field(default_factory=list)
    public_ip_addresses: list[str] = Field(default_factory=list)
    private_ip_addresses: list[str] = Field(default_factory=list)
    domains: list[str] = Field(default_factory=list)
    urls: list[str] = Field(default_factory=list)
    hashes: list[str] = Field(default_factory=list)
    emails: list[str] = Field(default_factory=list)


class EnrichmentResult(BaseModel):
    ioc: str
    ioc_type: str
    source: str
    status: str
    score: int | None = None
    summary: str
    raw: dict = Field(default_factory=dict)


class MitreTechnique(BaseModel):
    technique_id: str
    technique_name: str
    tactic: str


class TriageOutput(BaseModel):
    severity: Severity
    confidence: Confidence
    likely_activity: str
    mitre_attack_mapping: list[MitreTechnique] = Field(default_factory=list)
    evidence: list[str] = Field(default_factory=list)
    recommended_actions: list[str] = Field(default_factory=list)
    analyst_summary: str


class AnalysisResult(BaseModel):
    alert: dict
    iocs: IOCSet
    enrichments: list[EnrichmentResult]
    triage: TriageOutput
    prompt_injection_markers: list[str]
    report_markdown: str