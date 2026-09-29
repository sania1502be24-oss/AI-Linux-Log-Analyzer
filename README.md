# AI Linux Log Analyzer

### Security Log Analysis, Threat Scoring & Incident Investigation

An interactive cybersecurity project built with Python and Streamlit to analyze Linux authentication logs, identify suspicious activity, summarize potential security threats, and generate incident reports.

**Live Demo:** [Launch AI Linux Log Analyzer](https://ai-linux-log-analyzer-ewupnu3bljznscwksuyzn9.streamlit.app/)

**Source Code:** [GitHub Repository](https://github.com/sania1502be24-oss/AI-Linux-Log-Analyzer)

---

## Overview

AI Linux Log Analyzer is a security log analysis dashboard designed to help users examine Linux authentication logs and investigate potentially suspicious events.

The application parses log entries, identifies suspicious authentication activity using detection rules, calculates a threat score, presents investigation summaries, and supports exporting alerts and PDF security reports.

The project demonstrates practical skills in Python development, security log analysis, data visualization, incident investigation, and deployment.

## Key Features

* **Linux Log Parsing:** Processes supported authentication log entries into structured records.
* **Suspicious Activity Detection:** Identifies suspicious authentication patterns and other configured security events.
* **Threat Scoring:** Calculates a threat score to summarize the risk indicated by analyzed log activity.
* **Security Dashboard:** Displays security metrics, threat summaries, and visualizations.
* **Incident Investigation:** Presents incident summaries, evidence timelines, and investigation guidance.
* **Attacker IP Analysis:** Helps review IP addresses associated with suspicious log activity.
* **Threat Intelligence View:** Displays available threat intelligence information within the dashboard.
* **Alert Filtering:** Review recent alerts and filter results to investigate relevant events.
* **CSV Export:** Export alert data for further analysis.
* **PDF Security Reports:** Generate and download security incident reports.
* **Interactive Interface:** Explore analysis results through a Streamlit web dashboard.

## Screenshots

The following screenshots can be added to the repository to demonstrate the application's main features.

### 1. Security Dashboard

![AI Linux Log Analyzer Dashboard](screenshots/dashboard.png)

### 2. Incident Investigation

![Incident Investigation and Evidence Timeline](screenshots/incident-investigation.png)

### 3. Security Report

![Security Incident Report](screenshots/security-report.png)

> Add your actual application screenshots to the `screenshots/` directory using the filenames above.

## Technology Stack

| Technology                | Purpose                                 |
| ------------------------- | --------------------------------------- |
| Python                    | Core application and log analysis       |
| Streamlit                 | Interactive web dashboard               |
| Pandas                    | Structured data processing              |
| Plotly                    | Interactive data visualization          |
| ReportLab                 | PDF report generation                   |
| Git and GitHub            | Version control and source code hosting |
| Streamlit Community Cloud | Application deployment                  |

## Project Structure

```text
AI-Linux-Log-Analyzer/
├── dashboard.py
├── requirements.txt
├── README.md
├── data/
│   └── auth.log
├── reports/
│   ├── security_report.pdf
│   └── security_report.txt
└── src/
    ├── parser.py
    ├── detector.py
    ├── threat_score.py
    ├── bruteforce_detector.py
    ├── incident_investigator.py
    ├── pdf_report.py
    ├── reporter.py
    ├── email_alert.py
    └── threat_intelligence.py
```

*The tree highlights the main project files; the complete repository may contain additional files.*

## Getting Started

### Prerequisites

* Python 3.13 or another compatible Python version
* Git
* pip
* A web browser

### 1. Clone the repository

```bash
git clone https://github.com/sania1502be24-oss/AI-Linux-Log-Analyzer.git
cd AI-Linux-Log-Analyzer
```

### 2. Create a virtual environment

**Windows PowerShell:**

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

If PowerShell blocks environment activation, you can use the environment's Python executable directly.

### 3. Install dependencies

```powershell
python -m pip install -r requirements.txt
```

### 4. Launch the dashboard

```powershell
python -m streamlit run dashboard.py
```

Open the local URL displayed in your terminal, typically `http://localhost:8501`.

## How to Use

1. Open the dashboard.
2. Review the available log analysis results and security metrics.
3. Examine suspicious activity and threat summaries.
4. Use the incident investigation section to review relevant evidence and timelines.
5. Inspect alert records and associated IP information.
6. Export alert data to CSV when needed.
7. Generate and download a PDF security incident report.

The exact results depend on the log data available to the application.

## Deployment

The application is deployed using Streamlit Community Cloud.

**Live Application:** [AI Linux Log Analyzer](https://ai-linux-log-analyzer-ewupnu3bljznscwksuyzn9.streamlit.app/)

**Deployment Platform:** Streamlit Community Cloud

## Limitations

* Detection results depend on the supported log format, available data, and configured detection rules.
* A high threat score indicates suspicious patterns according to the application's scoring logic; it does not prove that a system has been compromised.
* IP analysis and threat intelligence results depend on the information available to the application.
* The project is an educational and portfolio-oriented security analysis tool, not a replacement for a production SIEM or a complete incident response platform.
* Detection accuracy, false positives, and false negatives require further testing against diverse real-world logs.
* The separate experimental Isolation Forest anomaly detector is not documented as an integrated, verified dashboard feature.
* Email alert delivery depends on valid configuration and a working email service.

## Future Improvements

* Integrate and validate machine-learning-based anomaly detection.
* Expand log-format support and test against additional Linux distributions.
* Add automated unit and integration tests.
* Improve detection evaluation with labeled datasets and false-positive analysis.
* Enhance threat intelligence enrichment and investigation workflows.
* Add authentication, access controls, and operational monitoring if the application is developed for production use.

## Learning Outcomes

This project provided practical experience with:

* Python application development
* Linux authentication log analysis
* Security event detection and threat scoring
* Incident investigation workflows
* Interactive dashboards and data visualization
* CSV and PDF report generation
* Git, GitHub, and cloud deployment

## Author

**Sania Mittal**

Cybersecurity-focused Computer Science student interested in threat detection, security analytics, incident investigation, and secure software development.

* **GitHub:** [sania1502be24-oss](https://github.com/sania1502be24-oss)
* **Project Repository:** [AI Linux Log Analyzer](https://github.com/sania1502be24-oss/AI-Linux-Log-Analyzer)
* **Live Demo:** [Open Application](https://ai-linux-log-analyzer-ewupnu3bljznscwksuyzn9.streamlit.app/)

---

*Built as a hands-on cybersecurity project for learning, experimentation, and portfolio demonstration.*
