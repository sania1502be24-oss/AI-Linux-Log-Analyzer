from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer
)

from reportlab.lib.styles import getSampleStyleSheet


def generate_pdf_report(
    total_logs,
    threat_score,
    high_threats,
    medium_threats
):
    pdf = SimpleDocTemplate(
        "reports/security_report.pdf"
    )

    styles = getSampleStyleSheet()

    content = []

    content.append(
        Paragraph(
            "AI Linux Log Analyzer Security Report",
            styles["Title"]
        )
    )

    content.append(Spacer(1, 12))

    content.append(
        Paragraph(
            f"Total Logs Parsed: {total_logs}",
            styles["Normal"]
        )
    )

    content.append(
        Paragraph(
            f"Threat Score: {threat_score}/100",
            styles["Normal"]
        )
    )

    content.append(
        Paragraph(
            f"High Severity Threats: {high_threats}",
            styles["Normal"]
        )
    )

    content.append(
        Paragraph(
            f"Medium Severity Threats: {medium_threats}",
            styles["Normal"]
        )
    )

    content.append(Spacer(1, 20))

    content.append(
        Paragraph(
            "Security Recommendations",
            styles["Heading2"]
        )
    )

    content.append(
        Paragraph(
            "- Investigate suspicious logins immediately.",
            styles["Normal"]
        )
    )

    content.append(
        Paragraph(
            "- Review privilege escalation attempts.",
            styles["Normal"]
        )
    )

    content.append(
        Paragraph(
            "- Block malicious IP addresses.",
            styles["Normal"]
        )
    )

    pdf.build(content)