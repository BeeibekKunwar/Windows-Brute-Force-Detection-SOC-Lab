# Windows Failed-Login Detection | SOC Level 1 Lab

**Python-Based Windows Authentication Monitoring, Threshold Detection, and SOC Investigation**

A hands-on defensive cybersecurity project demonstrating how a junior **Security Operations Centre (SOC) Analyst** can analyse Windows Security Event Logs, identify suspicious authentication patterns, validate detection rules, and document investigation findings.

The project uses **Python and Windows Event ID 4625** to identify repeated failed login attempts that may indicate password guessing or brute-force activity.

> **Project Scope:** This project was conducted in a controlled educational laboratory. An alert indicates that a detection rule was satisfied, not that an attack or account compromise was confirmed. The tool analyses exported EVTX files offline and is not a live SIEM.

---

## 1. Project Objectives

- Extract Windows failed-logon events (Event ID 4625) from `.evtx` files.
- Parse timestamps, target usernames, and source IP addresses using Python.
- Correlate authentication failures by username and source IP address.
- Detect five failed login attempts within a rolling five-minute window.
- Validate alert and no-alert scenarios through controlled testing.
- Collect and analyse security evidence.
- Practise SOC Level 1 alert triage, investigation, and documentation.

## 2. Lab Environment

| Component | Technology |
|---|---|
| Analysis Workstation | Ubuntu Linux |
| Test Endpoint | Windows Virtual Machine |
| Virtualisation | Oracle VirtualBox |
| Programming Language | Python 3 |
| Log Source | Windows Security Event Logs |
| Log Format | `.evtx` |
| Windows Event ID | 4625 — Failed Logon |
| Python Library | `python-evtx` |
| Detection Method | Threshold-Based Rolling Time Window |
| Detection Threshold | 5 Failed Attempts |
| Time Window | 5 Minutes |

## 3. Detection Methodology

The Python script processes Windows Security Event Logs and identifies repeated failed authentication attempts.

### 3.1 Detection Workflow

```text
       Windows Security Event Logs
                    |
                    v
             EVTX File Parsing
                    |
                    v
          Filter Windows Event 4625
                    |
                    v
     Extract Timestamp, Username and IP
                    |
                    v
        Sort Events Chronologically
                    |
                    v
         Group by Username + IP
                    |
                    v
       Apply Rolling 5-Minute Window
                    |
                    v
          5 Failed Login Attempts?
                 /       \
               YES        NO
                |          |
                v          v
        Generate Alert   No Alert
```

### 3.2 Detection Rule

| Parameter | Configuration |
|---|---|
| Event ID | 4625 |
| Event Description | Failed Windows Logon |
| Threshold | 5 Failed Attempts |
| Detection Window | 5 Minutes |
| Correlation Fields | Username and Source IP |
| Detection Output | Terminal-Based Alert |

**Detection Condition:**

An alert is generated when five failed authentication events for the same username and source IP address are identified within a rolling five-minute window.

The current implementation generates an alert when the rolling count equals the configured threshold.

## 4. Test Scenarios and Results

Multiple controlled authentication tests were conducted to evaluate the detection mechanism.

### 4.1 Test Results Summary

| Test ID | Test Scenario | Events | Detection Rule | Observed Result |
|---|---|---:|---|---|
| T01 | Single Failed Login | 1 | 5 failures / 5 min | No Alert |
| T02 | Threshold Sensitivity Test | 1 | 1 failure / 1 min | Alert Generated |
| T03 | Below-Threshold Test | 4 | 5 failures / 5 min | No Alert |
| T04 | Six-Event Scenario | 6 | 5 failures / 5 min | No Alert |
| T05 | Positive Detection Test | 8 | 5 failures / 5 min | Alert Generated |

### 4.2 Test Findings

**T01 — Single Failed Login**

The script identified one failed authentication event. The configured threshold was not reached, and no alert was generated.

**T02 — Threshold Sensitivity Test**

The threshold was temporarily changed to one failure within one minute. The script generated an alert, demonstrating that the detection parameters can be adjusted.

**T03 — Below-Threshold Test**

Four failed authentication events were processed. No alert was generated because the threshold required five qualifying failures.

**T04 — Six-Event Scenario**

Six failed authentication events were identified, but no alert was generated. Further verification of the individual timestamps, usernames, and source IP addresses is required to confirm why the detection condition was not satisfied.

**T05 — Positive Detection Test**

Eight failed authentication events were processed, and the script generated one alert when five qualifying failures were detected within the configured time window.

## 5. Successful Detection Evidence

### 5.1 Terminal Output — T05

```text
Failed logon events found: 8
Detection threshold: 5 failures within 5 minutes

!!! BRUTE-FORCE DETECTION ALERT !!!

Username: IEUser
Source IP: 127.0.0.1
Failed attempts: 5
Window: 5 minutes
Latest event: 2026-10-22T15:57:17.337746+00:00

----------------------------------------

Total detection alerts: 1
```

### 5.2 Alert Summary

| Field | Observed Value |
|---|---|
| Detection Type | Repeated Failed Authentication |
| Event ID | 4625 |
| Target Username | IEUser |
| Source IP | 127.0.0.1 |
| Failed Attempts at Threshold | 5 |
| Detection Window | 5 Minutes |
| Alert Count | 1 |
| Alert-Triggering Timestamp | 2026-10-22 15:57:17 UTC |
| Classification | Potential Brute-Force Activity |
| Environment | Controlled Laboratory |

**Analyst Observation:** The reported source IP address `127.0.0.1` represents the local loopback interface and does not establish that an external attacker was involved.

## 6. Installation and Usage

### 6.1 Clone the Repository

```bash
git clone https://github.com/BeeibekKunwar/Windows-Brute-Force-Detection-SOC-Lab.git

cd Windows-Brute-Force-Detection-SOC-Lab
```

### 6.2 Create a Virtual Environment

```bash
python3 -m venv .venv
source .venv/bin/activate
```

### 6.3 Install Dependencies

```bash
pip install python-evtx
```

### 6.4 Configure the Detection Script

Open `detect_bruteforce.py` and configure the input file and detection parameters:

```python
LOG_FILE = "path/to/your_exported_security_log.evtx"

THRESHOLD = 5
WINDOW_MINUTES = 5
```

### 6.5 Execute the Detection Script

```bash
python3 detect_bruteforce.py
```

The script analyses the specified EVTX file and displays any activity meeting the configured detection threshold.

**Note:** The current script requires the input filename to be configured manually.

## 7. SOC Level 1 Investigation Workflow

When a detection alert is generated, a SOC analyst should follow a structured investigation process.

| Stage | Investigation Activity | Purpose |
|---|---|---|
| 1. Alert Validation | Verify Event ID, threshold, and timestamps | Confirm the alert is valid |
| 2. Account Identification | Identify affected username and account privileges | Understand the affected account |
| 3. Source Investigation | Review source IP, hostname, and logon type | Identify the origin of activity |
| 4. Timeline Analysis | Examine failed attempts and their sequence | Understand authentication patterns |
| 5. Event Correlation | Review related Event ID 4624 and other logs | Identify possible successful logins |
| 6. Threat Assessment | Evaluate benign and suspicious explanations | Determine potential risk |
| 7. Escalation Decision | Assess whether senior analyst review is needed | Support incident response |
| 8. Documentation | Record evidence, findings, and disposition | Maintain an investigation record |

### 7.1 The 5Ws and 1H of the Positive Detection

| Question | Investigation Finding |
|---|---|
| Who? | Target account: IEUser |
| What? | Repeated failed authentication attempts |
| When? | Alert-triggering event: 22 October 2026, 15:57:17 UTC |
| Where? | Windows VM; reported source IP 127.0.0.1 |
| Why? | Five qualifying failures met the detection threshold; underlying cause unconfirmed |
| How? | Python-based analysis of Windows Security Event ID 4625 |

## 8. Evidence and Investigation Report

The repository contains supporting evidence and a detailed SOC investigation report.

### Evidence Files

[View Evidence Folder](evidence/)

The evidence includes terminal screenshots demonstrating the detection tests and their results.

### SOC Investigation Report

[View Investigation Reports](reports/)

The report includes:

- Executive summary
- Detection methodology
- 5Ws and 1H analysis
- Test scenarios and results
- Evidence interpretation
- SOC investigation workflow
- Technical limitations
- Recommendations
- Python source code appendix

## 9. Project Limitations

| Limitation | Explanation |
|---|---|
| Offline Log Analysis | The tool processes exported EVTX files rather than monitoring events continuously |
| Fixed Threshold | Authentication attempts below the threshold may remain undetected |
| Limited Correlation | Grouping by username and IP may miss distributed attacks |
| Missing Event Context | Logon type, failure codes, and account privileges are not included in detection decisions |
| No SIEM Integration | Alerts are displayed in the terminal |
| Basic Alert Handling | No JSON/CSV output, automated escalation, or incident case management |
| Evidence Completeness | Missing or incomplete event exports can affect results |
| Test Validation Gap | The six-event scenario requires event-level verification |

## 10. Future Improvements

1. Implement real-time Windows Security Event monitoring.
2. Add automated regression tests for detection thresholds.
3. Support command-line arguments for EVTX input files.
4. Export structured alerts in JSON and CSV formats.
5. Include Windows LogonType and authentication failure codes.
6. Correlate failed logons (4625) with successful logons (4624).
7. Improve alert deduplication and exception handling.
8. Integrate detection with a SIEM such as Splunk or Elastic.
9. Implement structured SOC investigation and incident reporting.

## 11. Responsible Use and Data Privacy

This project was developed for defensive cybersecurity learning and authorised laboratory testing.

Windows Security Event Logs may contain usernames, hostnames, network addresses, and other sensitive information.

Original EVTX files, screenshots, and reports should be reviewed and sanitised before public publication.

**Important:** Deleting sensitive files in a later Git commit does not necessarily remove them from the repository's history.

## 12. Reference

Microsoft (n.d.) *4625(F): An account failed to log on.* Microsoft Learn. Available at: https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4625

## 13. Author

**Bibek Kunwar**

MSc Cybersecurity  
University of the West of Scotland — London Campus


## 14. License

This project is licensed under the **MIT License**. See the [LICENSE](LICENSE) file for details.