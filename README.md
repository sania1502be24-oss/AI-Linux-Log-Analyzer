# AI Linux Log Analyzer

AI Linux Log Analyzer is a cybersecurity-focused project that analyzes Linux authentication logs (`auth.log`) to identify suspicious activities, calculate threat scores, and generate automated security reports.

The project is designed to simulate real-world Security Operations Center (SOC) workflows by detecting common attack patterns such as brute-force attacks, invalid user enumeration, root logins, sudo abuse, and privilege escalation attempts.

---

## Features

### Log Parsing
- Parses Linux authentication logs (`auth.log`)
- Extracts timestamps, services, and log messages
- Handles multiple log entries efficiently

### Threat Detection
- Failed Login Detection
- Brute Force Attack Detection
- Invalid User Detection
- Root Login Detection
- Sudo Abuse Detection
- Privilege Escalation Detection

### Threat Scoring
- Calculates an overall threat score (0–100)
- Weighs threats based on severity
- Helps prioritize security incidents

### Automated Security Reports
- Generates detailed security reports
- Categorizes threats by severity
- Summarizes attack activity
- Stores reports in a dedicated reports directory

---

## Detected Attack Types

| Attack Type | Severity |
|------------|------------|
| Failed Login Attempts | Medium |
| Brute Force Attacks | High |
| Invalid User Enumeration | Medium |
| Root Login Attempts | High |
| Sudo Abuse | High |
| Privilege Escalation | Critical |

---

## Example Detected Activities

```text
Failed password for root from 192.168.1.100
Invalid user admin from 192.168.1.150
Accepted password for root from 192.168.1.250
user sania executed sudo su
user admin executed sudo -i
usermod -aG sudo test
chmod 777 /etc/passwd
```

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
│   ├── main.py
│   ├── parser.py
│   ├── detector.py
│   ├── reporter.py
│   └── threat_score.py
│
├── requirements.txt
├── README.md
└── .gitignore
```

---

## Installation

### Clone Repository

```bash
git clone https://github.com/sania1502be24-oss/AI-Linux-Log-Analyzer.git
cd AI-Linux-Log-Analyzer
```

### Create Virtual Environment

```bash
python -m venv .venv
```

### Activate Virtual Environment

#### Windows

```bash
.venv\Scripts\activate
```

#### Linux / macOS

```bash
source .venv/bin/activate
```

### Install Dependencies

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
Total Logs Parsed: 20

Overall Threat Score: 100/100

=== BRUTE FORCE ATTEMPTS ===
[HIGH] 192.168.1.100 -> 6 failed attempts

=== INVALID USER ATTACKS ===
[MEDIUM] Invalid user admin from 192.168.1.150
[MEDIUM] Invalid user test from 192.168.1.151

=== ROOT LOGIN ATTEMPTS ===
[HIGH] Accepted password for root from 192.168.1.250 port 22 ssh2

=== SUDO ABUSE ATTEMPTS ===
[HIGH] user sania executed sudo su
[HIGH] user admin executed sudo -i
[HIGH] user test executed sudo bash

=== PRIVILEGE ESCALATION ATTEMPTS ===
[CRITICAL] sania executed su root
[CRITICAL] usermod -aG sudo test
[CRITICAL] chmod 777 /etc/passwd
```

---

## Threat Scoring Logic

| Threat Type | Score |
|------------|--------|
| Failed Login (Brute Force) | 10 per attempt |
| Invalid User | 5 each |
| Root Login | 25 each |
| Sudo Abuse | 15 each |
| Privilege Escalation | 20 each |

Maximum Threat Score = **100**

---

## Security Report Example

The tool automatically generates:

```text
reports/security_report.txt
```

Example sections:

```text
THREAT SUMMARY
BRUTE FORCE ATTACKS
INVALID USER ATTACKS
ROOT LOGIN ATTEMPTS
SUDO ABUSE ATTEMPTS
PRIVILEGE ESCALATION ATTEMPTS
```

---

## Development Progress

### Completed

- ✅ Day 1: Project Setup
- ✅ Day 2: Log Parsing Engine
- ✅ Day 3: Failed Login Detection
- ✅ Day 4: Brute Force Detection
- ✅ Day 5: Automated Security Reports
- ✅ Day 6: Root Login Detection & Threat Scoring
- ✅ Day 7: Sudo Abuse Detection
- ✅ Day 8: Privilege Escalation Detection

---

## Upcoming Features

### Detection Enhancements
- Suspicious IP Intelligence
- Attack Frequency Analysis
- Attacker Ranking

### AI Features
- AI Incident Summary
- AI-Based Risk Recommendations
- Threat Prioritization

### Dashboard
- Interactive Web Dashboard
- Threat Visualizations
- Charts and Analytics
- Real-Time Monitoring

### Deployment
- FastAPI Backend
- Docker Support
- Cloud Deployment

---

## Skills Demonstrated

- Python
- Cybersecurity
- Log Analysis
- Threat Detection
- Incident Response
- SOC Workflows
- Security Automation
- Report Generation
- Risk Assessment

---

## Author

**Sania Mittal**  
B.E. Computer Science Engineering (Cybersecurity)  
Chitkara University

GitHub: https://github.com/sania1502be24-oss

---

## License

This project is developed for educational and cybersecurity learning purposes.
