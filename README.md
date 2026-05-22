# Splunk Live Lab

A Python script that grabs your real public IP, geolocates it, checks it against a threat database, and writes the results as structured JSON logs that Splunk can pick up and parse instantly.

I built this because most Splunk tutorials just hand you static CSV files. That's boring. This actually talks to the internet, pulls real data about real IPs, and feeds it into Splunk so you can practice writing SPL queries against something that feels alive.

## What it does

1. Hits `api.ipify.org` to find your actual public IP address
2. Sends that IP (and a few known-malicious ones) to `ip-api.com` for geolocation — country, city, ISP, coordinates
3. Scores each IP against a threat intelligence database (simulated, but the data structure matches what you'd see in a real SOC)
4. Writes everything as single-line JSON to a log file that Splunk monitors

The logs include three event types that rotate randomly:
- **Web access** — HTTP requests with methods, URIs, status codes, and user agents (malicious IPs get tools like `Sqlmap` and `Hydra`)
- **Auth audits** — Login attempts with usernames, pass/fail status, and target services
- **Threat alerts** — IDS-style alerts with severity ratings and rule IDs

## Requirements

- Python 3.8+ (uses only standard library — nothing to install)
- Splunk Enterprise or Splunk Free running locally
- Internet connection for the IP lookups

## Getting started

```bash
git clone https://github.com/YOUR_USERNAME/splunk-live-lab.git
cd splunk-live-lab
```

That's it. No `pip install`, no virtual env.

## Usage

There are three modes:

### Quick run — grab your IP, make 5 logs, done

```bash
python live_splunk_lab.py --run-once
```

This fetches your public IP, geolocates it, generates 5 security events (your IP + some threat IPs), and writes them to `live_splunk_logs.log`. Good for a first test.

Output looks like this:
```
======================================================================
         SPLUNK DYNAMIC SECURITY INTEGRATION & ENRICHMENT LAB
======================================================================
[*] Contacting external authority to retrieve your public IP...
[+] Successfully identified your Public IP: 187.10.140.35

--------------------------------------------------
[*] Live Public IP Threat Intelligence Enrichment:
   IP Address:     187.10.140.35
   Location:       Sao Paulo, Brazil (Sao Paulo)
   ISP Network:    Vivo (AS27699 TELEFONICA BRASIL S.A)
   Threat Score:   10/100
   Classification: Clean / Unlisted
--------------------------------------------------

[+] Total of 5 enriched JSON events written to 'live_splunk_logs.log'.
```

### Stream mode — keep feeding Splunk continuously

```bash
python live_splunk_lab.py --stream 5
```

Generates a new log event every 5 seconds (or whatever interval you set). Rotates through your IP, known threat IPs, and internal addresses. Leave it running in a terminal while you practice SPL queries with Splunk's real-time search.

`Ctrl+C` to stop.

### Lookup mode — investigate a specific IP

```bash
python live_splunk_lab.py --lookup 185.220.101.5
```

Geolocates the target IP, scores it, prints the results, and writes one log entry. Handy if you spot a suspicious IP in Splunk and want to check it.

```
[*] Manual Geolocation & Threat Intelligence Lookup Result:
   IP Target:      185.220.101.5
   Location:       Brandenburg, Germany (Brandenburg)
   ISP Network:    Stiftung Erneuerbare Freiheit (AS60729)
   Threat Score:   98/100
   Classification: Tor Exit Node
   Threat Actor:   Unknown (Tor Network Scanner)
   Malicious:      True
```

## What the logs look like

Each line in `live_splunk_logs.log` is a self-contained JSON object. Here are a few examples:

**A Tor exit node trying SQL injection against the admin panel:**
```json
{"timestamp": "2026-05-22T17:06:52.018Z", "src_ip": "185.220.101.5", "dest_ip": "10.0.0.52", "geo": {"country": "Germany", "city": "Brandenburg", "isp": "Stiftung Erneuerbare Freiheit"}, "threat_intel": {"threat_score": 98, "classification": "Tor Exit Node", "malicious": true}, "event_type": "web_access", "web": {"method": "POST", "uri": "/admin/config/database_settings", "status_code": 401, "user_agent": "Sqlmap/v1.7.11 (SQL Injection Testing Tool)"}}
```

**A Mirai botnet triggering an IDS alert:**
```json
{"timestamp": "2026-05-22T17:06:52.293Z", "src_ip": "45.227.254.12", "dest_ip": "10.0.0.224", "geo": {"country": "Lithuania", "city": "Vilnius", "isp": "Flyservers S.A."}, "threat_intel": {"threat_score": 88, "classification": "SSH Brute-Force Botnet", "malicious": true}, "event_type": "threat_alert", "alert": {"signature": "IDS_ALERT_SSH_BRUTE-FORCE_BOTNET", "severity": "HIGH", "action_taken": "Logged & Flagged"}}
```

**Normal user browsing from your network:**
```json
{"timestamp": "2026-05-22T17:06:51.741Z", "src_ip": "187.10.140.35", "dest_ip": "10.0.0.248", "geo": {"country": "Brazil", "city": "Sao Paulo", "isp": "Vivo"}, "threat_intel": {"threat_score": 10, "classification": "Clean / Unlisted", "malicious": false}, "event_type": "web_access", "web": {"method": "GET", "uri": "/login", "status_code": 200, "response_ms": 76}}
```

Splunk parses all of this automatically when you set the source type to `_json`. Fields like `geo.country`, `threat_intel.threat_score`, and `web.user_agent` just show up in the sidebar — no regex, no transforms.

## Hooking it up to Splunk

1. Open Splunk Web → **Settings** → **Add Data** → **Monitor**
2. Pick **Files & Directories**, paste the full path to `live_splunk_logs.log`
3. Set source type to `_json`, index to `main`, submit

That's the whole setup.

### SPL queries to try

Once the data is in, open **Search & Reporting** and set the time picker to **All Time**:

```spl
-- See everything
source="*live_splunk_logs.log"

-- High-risk IPs only
source="*live_splunk_logs.log" threat_intel.threat_score>=75
| table timestamp, src_ip, geo.country, threat_intel.classification, threat_intel.threat_score
| sort - threat_intel.threat_score

-- Where is all the traffic coming from?
source="*live_splunk_logs.log"
| stats count, dc(src_ip) as "Unique IPs" by geo.country, geo.city, geo.isp
| sort - count

-- Who's getting brute-forced?
source="*live_splunk_logs.log" event_type=auth_audit auth.auth_status=failed
| stats count by auth.user, src_ip, geo.country
| sort - count

-- What are the attack tools hitting?
source="*live_splunk_logs.log" event_type=web_access web.status_code>=400
| table timestamp, src_ip, geo.country, web.uri, web.status_code, web.user_agent
```

For real-time monitoring, set the time picker to **Real-time → 30 second window** and run your stream mode in another terminal.

## Threat database

These IPs are hardcoded to always trigger high scores, so you get interesting attack data every run:

| IP | Score | What it is |
|---|---|---|
| `185.220.101.5` | 98 | Tor exit node (real one, actually) |
| `45.227.254.12` | 88 | SSH brute-force botnet |
| `198.51.100.42` | 75 | Phishing landing page |
| `8.8.8.8` | ~24 | Google DNS — clean |
| `192.168.x.x` | 0 | Local/private — always clean |

Any other public IP gets a score derived from its digits. The formula is deterministic, so the same IP always gets the same score across runs.

## Files

| File | What it does |
|---|---|
| `live_splunk_lab.py` | The main script — does everything |
| `live_splunk_logs.log` | Where the logs go (created automatically on first run) |
| `Splunk_Learning_Path.md` | Study guide — cert prep, free training links, SPL cheat sheet |
| `reference_guide.md` | Quick reference for commands and ready-to-paste SPL queries |

## APIs

| Service | What for | Rate limit |
|---|---|---|
| [ipify.org](https://www.ipify.org) | Gets your public IP | No limit |
| [ip-api.com](https://ip-api.com/docs) | Geolocation + ISP data | 45 requests/minute |

Both are free and don't need API keys. If you're using `--stream`, keep the delay at 2 seconds or higher to stay within ip-api's rate limit.

## Learning path

If you're using this to prep for Splunk certs, check out `Splunk_Learning_Path.md` in this repo. It covers:

- **Splunk Core Certified User** — searching, fields, stats, charts
- **Splunk Core Certified Power User** — lookups, eventtypes, tags, extractions

Some good practice resources:
- [Splunk free training courses](https://www.splunk.com/en_us/training/free-courses/overview.html)
- [TryHackMe Splunk rooms](https://tryhackme.com) — guided browser-based labs
- [Boss of the SOC (BOTS)](https://github.com/splunk/botsv1) — Splunk's own CTF dataset, free to download

## License

MIT
