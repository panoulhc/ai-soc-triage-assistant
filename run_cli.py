import argparse
import json
from pathlib import Path

from app.pipeline import analyze_alert


def main() -> None:
    parser = argparse.ArgumentParser(
        description="AI SOC Alert Triage Assistant CLI"
    )
    parser.add_argument(
        "alert_file",
        help="Path to a JSON alert file.",
    )
    parser.add_argument(
        "--claude",
        action="store_true",
        help="Use Claude API for enhanced triage.",
    )
    parser.add_argument(
        "--save-report",
        action="store_true",
        help="Save Markdown report into ./reports.",
    )

    args = parser.parse_args()

    alert_path = Path(args.alert_file)

    if not alert_path.exists():
        raise FileNotFoundError(f"Alert file not found: {alert_path}")

    alert = json.loads(alert_path.read_text(encoding="utf-8"))
    result = analyze_alert(alert, use_claude=args.claude)

    print("\n=== TRIAGE RESULT ===")
    print(json.dumps(result.triage.model_dump(), indent=2))

    print("\n=== EXTRACTED IOCs ===")
    print(json.dumps(result.iocs.model_dump(), indent=2))

    if args.save_report:
        reports_dir = Path("reports")
        reports_dir.mkdir(exist_ok=True)

        output_path = reports_dir / f"{alert_path.stem}_report.md"
        output_path.write_text(result.report_markdown, encoding="utf-8")

        print(f"\nReport saved to: {output_path}")


if __name__ == "__main__":
    main()