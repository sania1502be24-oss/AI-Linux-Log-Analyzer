from datetime import datetime
from pathlib import Path

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
)


def generate_pdf_report(
    total_logs,
    threat_score,
    high_threats,
    medium_threats,
    total_attacks=0,
    risk_level="UNKNOWN",
    brute_force=None,
    invalid_users=None,
    root_attempts=None,
    sudo_abuse=None,
    privilege_escalation=None,
):
    """
    Generate a professional PDF security incident report.
    """

    brute_force = brute_force or {}
    invalid_users = invalid_users or []
    root_attempts = root_attempts or []
    sudo_abuse = sudo_abuse or []
    privilege_escalation = privilege_escalation or []

    # ---------------------------------------------------------
    # OUTPUT DIRECTORY
    # ---------------------------------------------------------

    reports_dir = Path("reports")
    reports_dir.mkdir(parents=True, exist_ok=True)

    output_path = reports_dir / "security_report.pdf"

    # ---------------------------------------------------------
    # PDF DOCUMENT
    # ---------------------------------------------------------

    pdf = SimpleDocTemplate(
        str(output_path),
        pagesize=A4,
        rightMargin=18 * mm,
        leftMargin=18 * mm,
        topMargin=18 * mm,
        bottomMargin=18 * mm,
    )

    styles = getSampleStyleSheet()

    title_style = ParagraphStyle(
        "ReportTitle",
        parent=styles["Title"],
        fontSize=20,
        leading=24,
        alignment=TA_CENTER,
        spaceAfter=8,
    )

    subtitle_style = ParagraphStyle(
        "Subtitle",
        parent=styles["Normal"],
        fontSize=10,
        leading=14,
        alignment=TA_CENTER,
        spaceAfter=18,
    )

    section_style = ParagraphStyle(
        "Section",
        parent=styles["Heading2"],
        fontSize=13,
        leading=16,
        spaceBefore=10,
        spaceAfter=8,
    )

    normal_style = ParagraphStyle(
        "ReportNormal",
        parent=styles["Normal"],
        fontSize=9.5,
        leading=13,
        spaceAfter=5,
    )

    small_style = ParagraphStyle(
        "Small",
        parent=styles["Normal"],
        fontSize=8.5,
        leading=11,
    )

    # ---------------------------------------------------------
    # DOCUMENT CONTENT
    # ---------------------------------------------------------

    content = []

    content.append(
        Paragraph(
            "AI LINUX LOG ANALYZER",
            title_style,
        )
    )

    content.append(
        Paragraph(
            "SECURITY INCIDENT REPORT",
            subtitle_style,
        )
    )

    content.append(
        Paragraph(
            f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            small_style,
        )
    )

    content.append(Spacer(1, 12))

    # ---------------------------------------------------------
    # EXECUTIVE SUMMARY
    # ---------------------------------------------------------

    content.append(
        Paragraph(
            "Executive Summary",
            section_style,
        )
    )

    summary_data = [
        ["Metric", "Value"],
        ["Total Logs Analyzed", str(total_logs)],
        ["Total Detected Attacks", str(total_attacks)],
        ["Threat Score", f"{threat_score}/100"],
        ["Overall Risk Level", risk_level],
        ["Unique Attacker IPs", str(len(brute_force))],
    ]

    summary_table = Table(
        summary_data,
        colWidths=[85 * mm, 75 * mm],
    )

    summary_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1f2937")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTNAME", (0, 1), (0, -1), "Helvetica-Bold"),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("PADDING", (0, 0), (-1, -1), 7),
            ]
        )
    )

    content.append(summary_table)

    # ---------------------------------------------------------
    # ATTACK STATISTICS
    # ---------------------------------------------------------

    content.append(
        Paragraph(
            "Attack Statistics",
            section_style,
        )
    )

    attack_data = [
        ["Attack Type", "Count"],
        ["Brute Force Sources", str(len(brute_force))],
        ["Invalid User Attempts", str(len(invalid_users))],
        ["Root Login Attempts", str(len(root_attempts))],
        ["Sudo Abuse Attempts", str(len(sudo_abuse))],
        [
            "Privilege Escalation Attempts",
            str(len(privilege_escalation)),
        ],
    ]

    attack_table = Table(
        attack_data,
        colWidths=[110 * mm, 50 * mm],
    )

    attack_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#374151")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                ("PADDING", (0, 0), (-1, -1), 7),
            ]
        )
    )

    content.append(attack_table)

    # ---------------------------------------------------------
    # ATTACKER IP INTELLIGENCE
    # ---------------------------------------------------------

    content.append(
        Paragraph(
            "Attacker IP Intelligence",
            section_style,
        )
    )

    if brute_force:
        ip_data = [
            ["IP Address", "Failed Login Attempts"]
        ]

        for ip, count in brute_force.items():
            ip_data.append([str(ip), str(count)])

        ip_table = Table(
            ip_data,
            colWidths=[90 * mm, 70 * mm],
        )

        ip_table.setStyle(
            TableStyle(
                [
                    (
                        "BACKGROUND",
                        (0, 0),
                        (-1, 0),
                        colors.HexColor("#374151"),
                    ),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                    ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                    ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                    ("PADDING", (0, 0), (-1, -1), 7),
                ]
            )
        )

        content.append(ip_table)

    else:
        content.append(
            Paragraph(
                "No attacker IPs identified.",
                normal_style,
            )
        )

    # ---------------------------------------------------------
    # SECURITY FINDINGS
    # ---------------------------------------------------------

    content.append(
        Paragraph(
            "Security Findings",
            section_style,
        )
    )

    findings = []

    if brute_force:
        for ip, count in brute_force.items():
            findings.append(
                f"[HIGH] {ip} generated {count} failed login attempts."
            )

    for attack in invalid_users:
        findings.append(f"[MEDIUM] {attack}")

    for attack in root_attempts:
        findings.append(f"[HIGH] {attack}")

    for attack in sudo_abuse:
        findings.append(f"[HIGH] {attack}")

    for attack in privilege_escalation:
        findings.append(f"[CRITICAL] {attack}")

    if findings:
        for finding in findings:
            content.append(
                Paragraph(
                    finding,
                    normal_style,
                )
            )
    else:
        content.append(
            Paragraph(
                "No significant security findings detected.",
                normal_style,
            )
        )

    # ---------------------------------------------------------
    # RECOMMENDATIONS
    # ---------------------------------------------------------

    content.append(
        Paragraph(
            "Recommended Security Actions",
            section_style,
        )
    )

    recommendations = []

    if brute_force:
        recommendations.append(
            "Investigate repeated authentication failures."
        )
        recommendations.append(
            "Review and consider restricting suspicious source IPs."
        )
    else:
        recommendations.append(
            "Continue monitoring authentication activity."
        )

    if root_attempts:
        recommendations.append(
            "Review root account access and authentication logs."
        )

    if sudo_abuse:
        recommendations.append(
            "Audit privileged command execution."
        )

    if privilege_escalation:
        recommendations.append(
            "Investigate privilege escalation indicators immediately."
        )

    recommendations.append(
        "Continue monitoring Linux authentication logs."
    )

    for index, recommendation in enumerate(
        recommendations,
        start=1,
    ):
        content.append(
            Paragraph(
                f"{index}. {recommendation}",
                normal_style,
            )
        )

    # ---------------------------------------------------------
    # FOOTER
    # ---------------------------------------------------------

    content.append(Spacer(1, 20))

    content.append(
        Paragraph(
            "Generated by AI Linux Log Analyzer",
            subtitle_style,
        )
    )

    pdf.build(content)

    return str(output_path)