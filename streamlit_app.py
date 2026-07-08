import json
from pathlib import Path

import streamlit as st

from app.config import settings
from app.pipeline import analyze_alert, parse_alert_json


st.set_page_config(
    page_title="AI SOC Triage Assistant",
    page_icon="🛡️",
    layout="wide",
)


SAMPLE_DIR = Path("sample_alerts")


def load_sample_alerts() -> dict[str, str]:
    samples: dict[str, str] = {}

    if not SAMPLE_DIR.exists():
        return samples

    for path in SAMPLE_DIR.glob("*.json"):
        samples[path.name] = path.read_text(encoding="utf-8")

    return samples


st.title("🛡️ AI SOC Alert Triage Assistant")
st.caption("Defensive SOC triage with IOC extraction, threat-intel enrichment, rule logic, and optional Claude analysis.")

with st.sidebar:
    st.header("Settings")

    use_claude = st.checkbox(
        "Use Claude API",
        value=False,
        help="Requires ANTHROPIC_API_KEY in your .env file.",
    )

    st.write("**Claude model:**")
    st.code(settings.anthropic_model)

    if use_claude and not settings.anthropic_api_key:
        st.warning("ANTHROPIC_API_KEY is not set. The app will fall back to rule-based triage.")

    st.divider()

    st.write("**Threat Intel APIs**")
    st.write(f"AbuseIPDB key loaded: {'yes' if settings.abuseipdb_api_key else 'no'}")
    st.write(f"VirusTotal key loaded: {'yes' if settings.virustotal_api_key else 'no'}")


samples = load_sample_alerts()

default_alert = """{
  "alert_name": "Multiple Failed Login Attempts",
  "username": "admin",
  "source_ip": "203.0.113.16",
  "destination_host": "WIN-SRV-01",
  "failed_attempts": 45,
  "time_window": "10 minutes",
  "timestamp": "2026-02-13T18:35:00Z"
}
"""

left, right = st.columns([1, 1])

with left:
    st.subheader("Alert Input")

    selected_sample = None
    if samples:
        selected_sample = st.selectbox(
            "Load sample alert",
            options=["Custom"] + list(samples.keys()),
        )

    if selected_sample and selected_sample != "Custom":
        initial_value = samples[selected_sample]
    else:
        initial_value = default_alert

    raw_alert = st.text_area(
        "Paste alert JSON",
        value=initial_value,
        height=420,
    )

    analyze_button = st.button("Analyze Alert", type="primary")

with right:
    st.subheader("How this works")
    st.markdown(
        """
        This app performs:

        1. JSON alert parsing  
        2. IOC extraction  
        3. Threat-intel enrichment  
        4. Rule-based SOC triage  
        5. Optional Claude triage refinement  
        6. Markdown report generation  

        Alert text is treated as **untrusted data**, so prompt-injection markers are detected and included in the report.
        """
    )


if analyze_button:
    try:
        alert = parse_alert_json(raw_alert)
        result = analyze_alert(alert, use_claude=use_claude)

        st.success("Analysis complete.")

        tab1, tab2, tab3, tab4, tab5 = st.tabs(
            [
                "Triage",
                "IOCs",
                "Enrichment",
                "Report",
                "Raw JSON",
            ]
        )

        with tab1:
            st.subheader("Triage Verdict")

            col1, col2, col3 = st.columns(3)
            col1.metric("Severity", result.triage.severity.upper())
            col2.metric("Confidence", result.triage.confidence.upper())
            col3.metric("MITRE Techniques", len(result.triage.mitre_attack_mapping))

            st.write("### Likely Activity")
            st.write(result.triage.likely_activity)

            st.write("### Analyst Summary")
            st.write(result.triage.analyst_summary)

            st.write("### Evidence")
            for item in result.triage.evidence:
                st.write(f"- {item}")

            st.write("### Recommended Actions")
            for index, item in enumerate(result.triage.recommended_actions, start=1):
                st.write(f"{index}. {item}")

            if result.triage.mitre_attack_mapping:
                st.write("### MITRE ATT&CK Mapping")
                st.dataframe(
                    [item.model_dump() for item in result.triage.mitre_attack_mapping],
                    use_container_width=True,
                )

        with tab2:
            st.subheader("Extracted IOCs")
            st.json(result.iocs.model_dump())

        with tab3:
            st.subheader("Threat-Intel Enrichment")
            if result.enrichments:
                st.dataframe(
                    [item.model_dump(exclude={"raw"}) for item in result.enrichments],
                    use_container_width=True,
                )
            else:
                st.info("No enrichment results.")

        with tab4:
            st.subheader("Markdown Report")
            st.download_button(
                label="Download Markdown Report",
                data=result.report_markdown,
                file_name="soc_triage_report.md",
                mime="text/markdown",
            )
            st.markdown(result.report_markdown)

        with tab5:
            st.subheader("Full Analysis JSON")
            st.json(result.model_dump())

    except Exception as exc:
        st.error(str(exc))