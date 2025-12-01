#!/usr/bin/python3

import requests
import datetime
import argparse
import signal
import os
import time
import random
import ipaddress

# Colors
class Color:
    RED = "\033[91m"
    YELLOW = "\033[93m"
    GREEN = "\033[92m"
    BLUE = "\033[94m"
    CYAN = "\033[96m"
    RESET = "\033[0m"

session = requests.Session()
cve_cache = {}

# Banner
BANNER = f"""{Color.GREEN}
______                          ______  __             _____
___  / ______ __________  __    ___  / / /___  __________  /_____________
__  /  _  __ `/__  /_  / / /    __  /_/ /_  / / /_  __ \  __/  _ \_  ___/
_  /___/ /_/ /__  /_  /_/ /     _  __  / / /_/ /_  / / / /_ /  __/  /
/_____\__,_/ _____/\__, /      /_/ /_/  \__,_/ /_/ /_/\__/ \___//_/
                   /____/                                           v1.0
                                    LazyHunter Recon Tool Dev @iamunixtz
{Color.RESET}
"""

# Helper print functions
def info(msg):
    print(f"{Color.YELLOW}[INFO]{Color.RESET} {msg}")

def error(msg):
    print(f"{Color.RED}[ERROR]{Color.RESET} {msg}")

# CTRL+C handler
def signal_handler(sig, frame):
    choice = input(f"\n{Color.YELLOW}Do you want to quit? (y/n): {Color.RESET}")
    if choice.lower() == "y":
        print(f"{Color.RED}Exiting...{Color.RESET}")
        exit(0)

signal.signal(signal.SIGINT, signal_handler)

# Severity colors
def get_severity_color(score):
    if score is None:
        score = 0
    if score >= 9.0:
        return f"{Color.RED}[CRITICAL]{Color.RESET}"
    elif score >= 7.0:
        return f"{Color.RED}[HIGH]{Color.RESET}"
    elif score >= 4.0:
        return f"{Color.YELLOW}[MEDIUM]{Color.RESET}"
    return f"{Color.GREEN}[LOW]{Color.RESET}"

# CVE Fetcher with cache
def fetch_cve_details(cve_id):
    if cve_id in cve_cache:
        return cve_cache[cve_id]

    url = f"https://cvedb.shodan.io/cve/{cve_id}"
    try:
        r = session.get(url, timeout=5)
        if r.status_code == 200:
            data = r.json()
            cve_cache[cve_id] = data
            return data
    except:
        pass

    return {}

# Log outputs
def log_results(ip, data, show_cves, show_ports, show_hosts, show_cve_ports):
    lines = []
    base = f"{Color.YELLOW}[INFO]{Color.RESET} {Color.BLUE}[{ip}]{Color.RESET}"

    if show_ports or not any([show_cves, show_hosts, show_cve_ports]):
        if "ports" in data:
            ports = ", ".join(f"{Color.GREEN}{p}{Color.RESET}" for p in data["ports"])
            lines.append(f"{base} [PORTS: {ports}]")

    if show_cves or not any([show_ports, show_hosts, show_cve_ports]):
        if "vulns" in data:
            for cve in data["vulns"]:
                c = fetch_cve_details(cve)
                sev = get_severity_color(c.get("cvss_v3"))
                desc = c.get("summary", "No description.")[:80]
                lines.append(f"{base} [{Color.GREEN}{cve}{Color.RESET}] {sev} [{Color.GREEN}{desc}{Color.RESET}]")

    if show_cve_ports:
        if "vulns" in data and "ports" in data:
            ports = ", ".join(f"{Color.GREEN}{p}{Color.RESET}" for p in data["ports"])
            for cve in data["vulns"]:
                c = fetch_cve_details(cve)
                sev = get_severity_color(c.get("cvss_v3"))
                desc = c.get("summary", "No description.")[:80]
                lines.append(f"{base} [{Color.GREEN}{cve}{Color.RESET}] {sev} [{Color.GREEN}{desc}{Color.RESET}] [PORTS: {ports}]")

    if show_hosts:
        if "hostnames" in data:
            hosts = ", ".join(f"{Color.GREEN}{h}{Color.RESET}" for h in data["hostnames"])
            lines.append(f"{base} [HOSTNAMES: {hosts}]")

    for line in lines:
        print(line)

# Single IP handler
def process_ip(ip, show_cves, show_ports, show_hosts, show_cve_ports):
    try:
        ipaddress.ip_address(ip)
    except:
        error(f"Invalid IP format: {ip}")
        return

    url = f"https://internetdb.shodan.io/{ip}"
    try:
        r = session.get(url, timeout=5)
        if r.status_code == 200:
            log_results(ip, r.json(), show_cves, show_ports, show_hosts, show_cve_ports)
        else:
            error(f"Shodan returned status {r.status_code}")
    except:
        error(f"Failed to fetch data for {ip}")

# Main
def main():
    os.system("clear")
    print(BANNER)

    parser = argparse.ArgumentParser(description="LazyRecon - Automated Bug Hunting Recon Tool")
    parser.add_argument("-f", "--file", help="File with IP list")
    parser.add_argument("--ip", help="Single IP")
    parser.add_argument("--cves", action="store_true")
    parser.add_argument("--ports", action="store_true")
    parser.add_argument("--host", action="store_true")
    parser.add_argument("--cve+ports", dest="cve_ports", action="store_true")
    args = parser.parse_args()

    if args.ip:
        info(f"Target: {args.ip}")
        process_ip(args.ip, args.cves, args.ports, args.host, args.cve_ports)

    elif args.file:
        with open(args.file) as f:
            ips = f.read().splitlines()
            info(f"Loaded file: {args.file}")
            info(f"Total IPs: {len(ips)}")

            for ip in ips:
                process_ip(ip, args.cves, args.ports, args.host, args.cve_ports)

    else:
        process_ip("127.0.0.1", True, True, True, True)

    info("Scan Completed")

if __name__ == "__main__":
    main()
