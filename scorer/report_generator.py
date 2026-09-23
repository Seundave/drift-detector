import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


SEVERITIES = (
    "CRITICAL",
    "HIGH",
    "MEDIUM",
    "LOW",
)


def build_severity_summary(
    scored_drifts: list[dict[str, Any]],
) -> dict[str, int]:
    """
    Count how many drifts exist at each severity level.
    """

    summary = {
        severity.lower(): 0
        for severity in SEVERITIES
    }

    for drift in scored_drifts:
        severity = str(
            drift.get("severity", "")
        ).upper()

        if severity in SEVERITIES:
            summary[severity.lower()] += 1

    return summary



def generate_report(
    scored_drifts: list[dict[str, Any]],
    output_path: str = "drift-report.json",
) -> dict[str, Any]:
    """
    Generate a structured JSON report from scored drift.
    """

    severity_summary = build_severity_summary(
        scored_drifts
    )

    report = {
        "scan_time": datetime.now(
            timezone.utc
        ).isoformat(),

        "drift_detected": bool(
            scored_drifts
        ),

        "difference_count": len(
            scored_drifts
        ),

        "severity_summary": severity_summary,

        "drifts": scored_drifts,
    }

    path = Path(output_path)

    path.write_text(
        json.dumps(
            report,
            indent=2,
            default=str,
        ),
        encoding="utf-8",
    )

    return report


def build_slack_payload(
    scored_drifts: list[dict[str, Any]],
) -> dict[str, Any]:
    """
    Build a Slack Block Kit payload for scored drift.
    """

    if not scored_drifts:
        return {
            "text": "No actionable infrastructure drift detected.",
            "blocks": [
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": (
                            "✅ *No actionable "
                            "infrastructure drift detected.*"
                        ),
                    },
                }
            ],
        }

    severity_summary = build_severity_summary(
        scored_drifts
    )

    blocks: list[dict[str, Any]] = [
        {
            "type": "header",
            "text": {
                "type": "plain_text",
                "text": "Infrastructure Drift Detected",
            },
        },
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": (
                    f"*Total drift:* "
                    f"{len(scored_drifts)}\n"
                    f"*Critical:* "
                    f"{severity_summary['critical']}\n"
                    f"*High:* "
                    f"{severity_summary['high']}\n"
                    f"*Medium:* "
                    f"{severity_summary['medium']}\n"
                    f"*Low:* "
                    f"{severity_summary['low']}"
                ),
            },
        },
        {
            "type": "divider",
        },
    ]

    for drift in scored_drifts:
        severity = drift["severity"]

        blocks.append(
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": (
                        f"*{severity}* — "
                        f"`{drift['resource']}`\n"
                        f"*Field:* "
                        f"`{drift['field']}`\n"
                        f"*Environment:* "
                        f"`{drift['environment']}`\n"
                        f"*Expected:* "
                        f"`{drift['expected']}`\n"
                        f"*Live:* "
                        f"`{drift['live']}`\n"
                        f"*Score:* "
                        f"`{drift['score']}`"
                    ),
                },
            }
        )

        blocks.append(
            {
                "type": "divider",
            }
        )

    return {
        "text": "Infrastructure drift detected.",
        "blocks": blocks,
    }