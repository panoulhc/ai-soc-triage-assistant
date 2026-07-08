"""
AI SOC Alert Triage Assistant

A defensive cybersecurity project that:
- accepts security alert JSON
- extracts IOCs
- enriches IOCs using threat-intelligence APIs
- performs rule-based triage
- optionally improves the report with Claude
- generates a SOC-style Markdown report
"""