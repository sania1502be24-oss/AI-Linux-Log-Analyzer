# AI Linux Log Analyzer

## Overview

AI Linux Log Analyzer is a cybersecurity project designed to analyze Linux authentication logs and identify potential security threats. The system parses log files, detects suspicious activities such as brute-force attacks, invalid user enumeration attempts, and root login attempts, classifies threats based on severity, and generates automated security reports.

This project simulates the functionality of a basic Security Information and Event Management (SIEM) system and helps security analysts monitor Linux systems for malicious activity.

---

## Features

* Parse Linux authentication logs (`auth.log`)
* Detect failed SSH login attempts
* Identify brute-force attacks
* Detect invalid user enumeration attacks
* Detect root login attempts
* Classify threats by severity level
* Generate automated security reports
* Structured log analysis workflow
* Extensible architecture for future AI-based threat detection

---

## Project Structure

```text
AI-Linux-Log-Analyzer/
│
├── data/
│   └── auth.log
│
├── reports/
│   └── security_report.txt
│
├── src/
│   ├── parser.py
│   ├── detector.py
│   ├── reporter.py
│   └── main.py
│
├── requirements.txt
├── .gitignore
└── README.md
```

---

## Technologies Used

* Python 3
* Regular Expressions (Regex)
* Collections Module
* File Handling
* Cybersecurity Log Analysis

---

## Threat Detection Capabilities

### Brute Force Detection

Detects repeated failed login attempts from the same IP address.

### Invalid User Detection

Identifies login attempts targeting non-existent user accounts.

### Root Login Attempt Detection

Monitors attempts to gain access using the root account.

### Severity Classification

| Severity | Description                              |
| -------- | ---------------------------------------- |
| High     | Brute-force attacks, Root login attempts |
| Medium   | Invalid user enumeration attacks         |

---

## Installation

Clone the repository:

```bash
git clone https://github.com/sania1502be24-oss/AI-Linux-Log-Analyzer.git
cd AI-Linux-Log-Analyzer
```

Create a virtual environment:

```bash
python -m venv .venv
```

Activate the virtual environment:

### Windows

```powershell
.venv\Scripts\Activate.ps1
```

Install dependencies:

```bash
pip install -r requirements.txt
```

---

## Usage

Run the analyzer:

```bash
python src/main.py
```

---

## Sample Output

```text
Total Logs Parsed: 13

=== BRUTE FORCE ATTEMPTS ===
[HIGH] 192.168.1.100 -> 6 failed attempts

=== INVALID USER ATTACKS ===
[MEDIUM] Invalid user admin from 192.168.1.150
[MEDIUM] Invalid user test from 192.168.1.151

=== ROOT LOGIN ATTEMPTS ===
[HIGH] Failed password for root from 192.168.1.100 port 22 ssh2

Report generated successfully!
Location: reports/security_report.txt
```

---

## Security Report Generation

The analyzer automatically generates a detailed report containing:

* Threat summary
* Brute-force attack details
* Invalid user attack details
* Root login attempt details
* Severity classifications
* Analysis timestamp

Generated report location:

```text
reports/security_report.txt
```

---

## Future Enhancements

* AI-based anomaly detection
* Threat scoring engine
* Streamlit dashboard
* Interactive charts and visualizations
* Historical log storage
* SQLite/PostgreSQL integration
* Real-time log monitoring
* Email alert system
* PDF report export
* Deployment using Docker

---

## Learning Outcomes

This project demonstrates practical knowledge of:

* Linux log analysis
* Security monitoring
* Threat detection techniques
* Python programming
* File parsing and automation
* SOC analyst workflows
* SIEM concepts

---

## Author

**Sania Mittal**

B.E. Computer Science Engineering
Chitkara University
Cybersecurity Enthusiast

---

## Project Status

🚧 Currently under active development

Completed:

* Day 1: Project Setup & Log Parser
* Day 2: Structured Log Parsing
* Day 3: Failed Login Detection
* Day 4: Attack Classification & Severity Levels
* Day 5: Automated Security Report Generation

Upcoming:

* Threat Scoring Engine
* AI-Based Detection
* Dashboard Development
* Advanced Reporting
