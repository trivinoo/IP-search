# 🛡️ Splunk Live Lab: Command & SPL Reference Guide

This reference guide serves as your quick-access command center for managing and running your Python live IP integration laboratory and executing target SPL (Search Processing Language) queries.

---

## 💻 Laboratory Execution Commands

Open your PowerShell terminal and run these commands from your laboratory directory:

| Action / Goal | Command to Run |
| :--- | :--- |
| **Verify Python Environment** | `python --version` |
| **Run IP Discovery & Geolocate (Once)** | `python live_splunk_lab.py --run-once` |
| **Stream Live Logs (Every 5 seconds)** | `python live_splunk_lab.py --stream 5` |
| **Stream Live Logs (Every 10 seconds)** | `python live_splunk_lab.py --stream 10` |
| **Target Lookup & Score Specific IP** | `python live_splunk_lab.py --lookup 185.220.101.5` |
| **Custom IP / User IP Manual Lookup** | `python live_splunk_lab.py --lookup <ANY_PUBLIC_IP>` |

---

## 🔍 Target Splunk SIEM Queries (SPL)

Run these queries in your local Splunk Enterprise search bar (set the time picker to **All Time** or use **Real-time** search when streaming logs):

### 1. View All Dynamic Integration Logs
Shows every event that has been ingested from your dynamic integration monitor.
```spl
source="*live_splunk_logs.log"
```

### 2. Identify Unique Geolocation Sources
Aggregates all traffic sources by Country, City, and ISP network to track where connections are originating.
```spl
source="*live_splunk_logs.log" 
| stats count, dc(src_ip) as "Unique IPs" by geo.country, geo.city, geo.isp
| sort - count
```

### 3. High Severity Threat Intelligence Triggers
Filters the dataset to show only events triggered by high-risk IPs (threat score > 75).
```spl
source="*live_splunk_logs.log" threat_intel.threat_score>=75
| table timestamp, src_ip, geo.country, threat_intel.classification, threat_intel.threat_score, event_type
| sort - threat_intel.threat_score
```

### 4. Interactive Authentication Audits
Summarizes login attempts, highlighting usernames targeted, successes vs. failures, and the source IP.
```spl
source="*live_splunk_logs.log" event_type=auth_audit
| stats count by auth.user, auth.auth_status, src_ip, geo.country
| sort - count
```

### 5. Suspicious Software Scanning & Brute Forces
Spotting automated tools hitting your server endpoints.
```spl
source="*live_splunk_logs.log" event_type=web_access (web.status_code=401 OR web.status_code=403)
| table timestamp, src_ip, geo.isp, web.uri, web.status_code, web.user_agent
```

---

## 📡 Splunk Data Monitoring Settings

Configure Splunk to watch your directory and ingest logs automatically:
1. **Target File Path**: `C:\Users\trivi\.gemini\antigravity\scratch\newgeminisplunk\live_splunk_logs.log`
2. **Monitoring Mode**: Continuously Monitor (Tails the file).
3. **Source Type**: `_json` (Splunk's native JSON parser).
4. **Index**: `main` (or a dedicated index of your choice).
