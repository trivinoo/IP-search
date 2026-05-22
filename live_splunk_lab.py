#!/usr/bin/env python3
"""
Splunk Live Integration Laboratory
----------------------------------
This script performs real-world integration by:
1. Discovering the host's actual public IP address (via ipify API).
2. Fetching live geolocation and network data (via ip-api).
3. Enriching the IP against simulated threat intelligence databases.
4. Structuring and generating beautiful, single-line JSON logs.
5. Writing logs dynamically to a dedicated monitoring file for Splunk.

Features:
- Live public IP auto-detection & geolocation enrichment.
- Standard mock IP rotation (including real firewall/scanning vectors).
- Live manual lookup for any custom IP address.
- Interactive mode, Single Run mode, and Continuous Streaming mode.
"""

import argparse
import datetime
import json
import os
import random
import sys
import time
import urllib.request
import urllib.error

# Dedicated log file path (Splunk will monitor this file)
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_FILE = os.path.join(SCRIPT_DIR, "live_splunk_logs.log")

# Static/Simulated Threat Intelligence Feeds
MOCK_THREAT_DATABASE = {
    "185.220.101.5": {
        "threat_score": 98,
        "classification": "Tor Exit Node",
        "threat_actor": "Unknown (Tor Network Scanner)",
        "malicious": True
    },
    "45.227.254.12": {
        "threat_score": 88,
        "classification": "SSH Brute-Force Botnet",
        "threat_actor": "Mirai Variant",
        "malicious": True
    },
    "198.51.100.42": {
        "threat_score": 75,
        "classification": "Phishing Landing Page",
        "threat_actor": "APT-Mock-Group",
        "malicious": True
    }
}

# Standard users and services for log generation
USERS = ["admin", "root", "guest", "db_backup", "clara", "sam", "taylor", "developer"]
SERVICES = ["auth_portal", "payment_gateway", "user_profile", "admin_dashboard", "database_cluster"]
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_1_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1",
    "Hydra/v9.5 (Password Brute-forcing Tool)",
    "Sqlmap/v1.7.11 (SQL Injection Testing Tool)",
    "curl/8.4.0"
]

def print_banner():
    """Prints a beautiful security command-line dashboard banner."""
    print("=" * 70)
    print("         SPLUNK DYNAMIC SECURITY INTEGRATION & ENRICHMENT LAB        ")
    print("=" * 70)
    print(f"[*] Target Directory:  {os.getcwd()}")
    print(f"[*] Splunk Log File:   {LOG_FILE}")
    print("=" * 70)

def fetch_public_ip():
    """Fetches the user's public external IP address from a secure API."""
    print("[*] Contacting external authority to retrieve your public IP...")
    url = "https://api.ipify.org?format=json"
    try:
        req = urllib.request.Request(url, headers={'User-Agent': 'SplunkLabIntegration/1.0'})
        with urllib.request.urlopen(req, timeout=5) as response:
            res_data = response.read().decode('utf-8')
            ip_json = json.loads(res_data)
            ip = ip_json.get("ip")
            print(f"[+] Successfully identified your Public IP: {ip}")
            return ip
    except Exception as e:
        print(f"[!] Warning: Could not fetch public IP ({e}). Defaulting to a safe dummy IP.")
        return "192.0.2.100"  # Test-Net dummy IP

def lookup_geolocation(ip):
    """
    Looks up live geolocation data for an IP address.
    Uses free ip-api.com (limited to 45 requests per minute, so we handle it politely).
    """
    # Private / Local subnet checks
    if ip.startswith("192.168.") or ip.startswith("10.") or ip.startswith("172.16.") or ip.startswith("127.") or ip == "0.0.0.0":
        return {
            "country": "Local Subnet (LAN)",
            "country_code": "LAN",
            "region": "Internal",
            "city": "Private Network",
            "lat": 0.0,
            "lon": 0.0,
            "isp": "Private Subnet",
            "as_number": "N/A"
        }

    url = f"http://ip-api.com/json/{ip}"
    try:
        req = urllib.request.Request(url, headers={'User-Agent': 'SplunkLabIntegration/1.0'})
        with urllib.request.urlopen(req, timeout=5) as response:
            res_data = response.read().decode('utf-8')
            geo = json.loads(res_data)
            if geo.get("status") == "success":
                return {
                    "country": geo.get("country", "Unknown"),
                    "country_code": geo.get("countryCode", "UNK"),
                    "region": geo.get("regionName", "Unknown"),
                    "city": geo.get("city", "Unknown"),
                    "lat": geo.get("lat", 0.0),
                    "lon": geo.get("lon", 0.0),
                    "isp": geo.get("isp", "Unknown"),
                    "as_number": geo.get("as", "Unknown")
                }
    except Exception as e:
        pass
    
    return {
        "country": "Unknown Country",
        "country_code": "UNK",
        "region": "Unknown Region",
        "city": "Unknown City",
        "lat": 0.0,
        "lon": 0.0,
        "isp": "Offline or Rate-Limited",
        "as_number": "Unknown"
    }

def get_threat_intel(ip):
    """Checks the static database or dynamically scores the IP threat level."""
    # Check if IP is in our threat database
    if ip in MOCK_THREAT_DATABASE:
        return MOCK_THREAT_DATABASE[ip]
    
    # Otherwise, score dynamically based on range
    if ip.startswith("192.168.") or ip.startswith("10.") or ip.startswith("127."):
        return {"threat_score": 0, "classification": "Clean / Local Asset", "threat_actor": "None", "malicious": False}
    
    # Generate stable mock threat score based on hash of IP so it stays consistent
    ip_hash_sum = sum(int(char) for char in ip.replace(".", "") if char.isdigit())
    score = (ip_hash_sum * 7) % 100
    
    # If the score is higher than 75, let's classify it as a potential risk
    if score >= 75:
        return {
            "threat_score": score,
            "classification": "Suspicious Activity Detected",
            "threat_actor": "Automated Scanner Botnet",
            "malicious": True
        }
    else:
        return {
            "threat_score": score,
            "classification": "Clean / Unlisted",
            "threat_actor": "None",
            "malicious": False
        }

def generate_log_event(ip, geo, threat, force_attack=False):
    """
    Generates a realistic security event structured in JSON.
    Splunk reads JSON natively, creating beautiful fields automatically.
    """
    timestamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
    event_type = random.choice(["web_access", "auth_audit", "threat_alert"])
    
    # If the IP is highly threat scored, make it perform a malicious event
    is_malicious = threat["threat_score"] > 70 or force_attack
    
    event = {
        "timestamp": timestamp,
        "src_ip": ip,
        "dest_ip": f"10.0.0.{random.randint(10, 250)}",
        "geo": geo,
        "threat_intel": threat
    }
    
    if event_type == "web_access":
        event["event_type"] = "web_access"
        # Determine status codes and agents based on maliciousness
        if is_malicious:
            event["web"] = {
                "method": "POST",
                "uri": "/admin/config/database_settings",
                "status_code": random.choice([403, 401, 500]),
                "response_ms": random.randint(5, 45),
                "user_agent": random.choice([u for u in USER_AGENTS if "Sqlmap" in u or "Hydra" in u])
            }
        else:
            event["web"] = {
                "method": random.choice(["GET", "GET", "POST", "PUT"]),
                "uri": random.choice(["/index.html", "/api/v1/products", "/login", "/dashboard", "/payments/checkout"]),
                "status_code": random.choice([200, 200, 200, 302, 404]),
                "response_ms": random.randint(20, 350),
                "user_agent": random.choice([u for u in USER_AGENTS if "Mozilla" in u])
            }
            
    elif event_type == "auth_audit":
        event["event_type"] = "auth_audit"
        username = "admin" if is_malicious else random.choice(USERS)
        status = "failed" if is_malicious or random.random() < 0.1 else "success"
        
        event["auth"] = {
            "service": random.choice(SERVICES),
            "user": username,
            "auth_status": status,
            "port": random.choice([22, 443, 3389])
        }
        
    else:  # threat_alert
        event["event_type"] = "threat_alert"
        severity = "HIGH" if threat["threat_score"] > 80 else ("MEDIUM" if threat["threat_score"] > 50 else "LOW")
        event["alert"] = {
            "signature": f"IDS_ALERT_{threat['classification'].upper().replace(' ', '_')}",
            "severity": severity,
            "action_taken": "Logged & Flagged" if severity == "HIGH" else "Logged",
            "rule_id": f"SID-{random.randint(2000000, 2999999)}"
        }
        
    return event

def write_log_to_file(event):
    """Appends a single JSON log line to the monitored log file."""
    with open(LOG_FILE, "a") as f:
        f.write(json.dumps(event) + "\n")

def run_once(current_ip):
    """Executes a single lab iteration: retrieves current IP details and creates 5 diverse logs."""
    print(f"\n[*] --- RUNNING LAB: SINGLE INGESTION ENRICHMENT ---")
    
    # 1. Fetch current public IP details
    geo = lookup_geolocation(current_ip)
    threat = get_threat_intel(current_ip)
    
    print("\n" + "-" * 50)
    print("[*] Live Public IP Threat Intelligence Enrichment:")
    print(f"   IP Address:     {current_ip}")
    print(f"   Location:       {geo['city']}, {geo['country']} ({geo['region']})")
    print(f"   ISP Network:    {geo['isp']} ({geo['as_number']})")
    print(f"   Threat Score:   {threat['threat_score']}/100")
    print(f"   Classification: {threat['classification']}")
    print("-" * 50 + "\n")
    
    # Generate and append a log featuring this current live IP
    live_event = generate_log_event(current_ip, geo, threat)
    write_log_to_file(live_event)
    print(f"[+] Created and logged a live dynamic security event featuring your actual IP!")
    
    # Spin and create a few additional mock logs using revolving threat IPs for Splunk parsing richness
    print("[*] Simulating surrounding corporate network traffic & known threat attacks...")
    additional_ips = ["185.220.101.5", "45.227.254.12", "8.8.8.8", "192.168.1.15"]
    for ip in additional_ips:
        ip_geo = lookup_geolocation(ip)
        ip_threat = get_threat_intel(ip)
        event = generate_log_event(ip, ip_geo, ip_threat)
        write_log_to_file(event)
        
    print(f"[+] Total of 5 enriched JSON events written to '{LOG_FILE}'.")
    print(f"[+] Setup complete. Ready for Splunk Web ingestion monitoring!")

def stream_logs(current_ip, delay):
    """Streams live log data indefinitely with real-time logs generating every few seconds."""
    print(f"\n[*] --- RUNNING LAB: CONTINUOUS SIEM STREAMING MODE ---")
    print(f"[*] Logs are streaming into '{LOG_FILE}' every {delay} seconds.")
    print("[*] Press Ctrl+C to terminate the streaming laboratory.")
    print("=" * 70)
    
    # Cache geo and threat for the current IP to avoid rate limits
    my_geo = lookup_geolocation(current_ip)
    my_threat = get_threat_intel(current_ip)
    
    rotating_ips = [current_ip, "185.220.101.5", "45.227.254.12", "8.8.8.8", "192.168.1.15", "198.51.100.42"]
    
    try:
        counter = 0
        while True:
            # Pick a random IP and fetch details (use cache for own IP, resolve or generate for others)
            ip = random.choice(rotating_ips)
            if ip == current_ip:
                geo = my_geo
                threat = my_threat
            else:
                geo = lookup_geolocation(ip)
                threat = get_threat_intel(ip)
            
            event = generate_log_event(ip, geo, threat)
            write_log_to_file(event)
            
            counter += 1
            status_line = f"[+] Log Event #{counter} generated at {event['timestamp']} | IP: {ip} -> '{event['event_type']}' written."
            sys.stdout.write(f"\r{status_line:<110}")
            sys.stdout.flush()
            
            time.sleep(delay)
            
    except KeyboardInterrupt:
        print("\n\n[-] Continuous streaming lab paused.")
        print("[*] Log generator gracefully terminated. Splunk is updated.")

def main():
    parser = argparse.ArgumentParser(description="Splunk Live IP Integration and Threat Intelligence Log Generator Mini-Lab")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--run-once", action="store_true", help="Discovers current IP, geolocates it, generates 5 initial logs and exits.")
    group.add_argument("--stream", type=int, metavar="DELAY_SEC", help="Streams logs into the file continuously with a custom delay in seconds.")
    group.add_argument("--lookup", type=str, metavar="IP_ADDR", help="Performs a specific manual enrichment lookup for an IP, prints it, and generates its log.")
    
    args = parser.parse_args()
    
    print_banner()
    
    # Get current public IP as base
    current_ip = fetch_public_ip()
    
    if args.run_once:
        run_once(current_ip)
    elif args.stream:
        stream_logs(current_ip, args.stream)
    elif args.lookup:
        # Perform targeted IP lookup
        ip = args.lookup
        print(f"\n[*] Performing manual target lookup on: {ip}")
        geo = lookup_geolocation(ip)
        threat = get_threat_intel(ip)
        
        print("\n" + "-" * 50)
        print("[*] Manual Geolocation & Threat Intelligence Lookup Result:")
        print(f"   IP Target:      {ip}")
        print(f"   Location:       {geo['city']}, {geo['country']} ({geo['region']})")
        print(f"   ISP Network:    {geo['isp']} ({geo['as_number']})")
        print(f"   Threat Score:   {threat['threat_score']}/100")
        print(f"   Classification: {threat['classification']}")
        print(f"   Threat Actor:   {threat['threat_actor']}")
        print(f"   Malicious:      {threat['malicious']}")
        print("-" * 50 + "\n")
        
        # Write custom log entry for it
        event = generate_log_event(ip, geo, threat, force_attack=threat['malicious'])
        write_log_to_file(event)
        print(f"[+] Enriched event written to '{LOG_FILE}'. Check Splunk!")

if __name__ == "__main__":
    main()
