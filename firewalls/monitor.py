#!/usr/bin/env python3
"""CLI tool to continuously monitor and tally denied ingress and egress firewall connections."""

import argparse
import datetime
import os
import re
import socket
import sys
import time
from collections import Counter
from pathlib import Path

from colorama import Fore, Style, init

from firewalls.log_control import managed_firewall_log

init(autoreset=True)

DEFAULT_LOG = Path("/var/log/firewalld/denied.log")
DNS_CACHE: dict[str, str] = {}
SERVICE_CACHE: dict[tuple[str, str], str] = {}

KNOWN_PROTOCOLS: dict[str, str] = {
    "1": "ICMP",
    "2": "IGMP",
    "6": "TCP",
    "17": "UDP",
    "41": "IPv6",
    "47": "GRE",
    "50": "ESP",
    "51": "AH",
    "58": "ICMPv6",
    "88": "EIGRP",
    "89": "OSPF",
    "112": "VRRP",
    "132": "SCTP",
}


def normalize_proto(proto: str) -> str:
    """Normalize protocol representation from number or lowercase name to uppercase name.

    Args:
        proto: Raw protocol string from kernel log (e.g., '6', '17', 'tcp').

    Returns:
        str: Normalized protocol name (e.g., 'TCP', 'UDP', 'IGMP').
    """
    if not proto or proto == "N/A":
        return "N/A"
    return KNOWN_PROTOCOLS.get(proto, proto.upper())


def resolve_service(dpt: str, proto: str) -> str:
    """Resolve destination port and transport protocol to a known service name with caching.

    Args:
        dpt: Destination port string (e.g., '80', '443').
        proto: Protocol string (e.g., 'TCP', 'UDP').

    Returns:
        str: Service name (e.g., 'http', 'https', 'domain') or empty string if unresolvable.
    """
    if not dpt or dpt == "N/A":
        return ""
    key = (dpt, proto.lower())
    if key in SERVICE_CACHE:
        return SERVICE_CACHE[key]

    service = ""
    try:
        port_num = int(dpt)
        proto_name = proto.lower() if proto.lower() in ("tcp", "udp") else None
        if proto_name:
            service = socket.getservbyport(port_num, proto_name)
        else:
            service = socket.getservbyport(port_num)
    except (ValueError, OSError, OverflowError):
        service = ""

    SERVICE_CACHE[key] = service
    return service


def format_port_entry(dpt: str, proto: str) -> str:
    """Format port string with normalized protocol and optional service name.

    Args:
        dpt: Destination port string.
        proto: Transport protocol string.

    Returns:
        str: Formatted string such as '80 TCP (http)' or '443 UDP (https)'.
    """
    proto_str = normalize_proto(proto)
    if not dpt or dpt == "N/A":
        return proto_str

    service = resolve_service(dpt, proto_str)
    if service:
        return f"{dpt} {proto_str} ({service})"
    return f"{dpt} {proto_str}"


def resolve_ip(ip: str) -> str:
    """Resolve IP address to host reverse domain name (PTR record) with caching.

    Args:
        ip: IPv4 or IPv6 address string.

    Returns:
        str: Resolved hostname/domain or the original IP string on failure.
    """
    if not ip or ip in ("N/A", "127.0.0.1", "0.0.0.0"):
        return ip
    if ip in DNS_CACHE:
        return DNS_CACHE[ip]

    try:
        old_timeout = socket.getdefaulttimeout()
        socket.setdefaulttimeout(1.0)
        domain, _, _ = socket.gethostbyaddr(ip)
        socket.setdefaulttimeout(old_timeout)
        DNS_CACHE[ip] = domain
        return domain
    except Exception:
        DNS_CACHE[ip] = ip
        return ip


def format_host_entry(ip: str, resolve: bool) -> str:
    """Format host entry with IP address and optional reverse DNS domain name.

    Args:
        ip: IP address string.
        resolve: Whether to perform and display reverse DNS lookup.

    Returns:
        str: Formatted string (e.g., '1.1.1.1 (one.one.one.one)' or '1.1.1.1').
    """
    if not resolve:
        return ip
    domain = resolve_ip(ip)
    if domain != ip:
        return f"{ip} ({domain})"
    return ip


def parse_denied_line(line: str) -> tuple[str, tuple[str, str, str]]:
    """Parse firewall log line into direction and event tuple (protocol, address, port).

    Args:
        line: Raw log line string.

    Returns:
        tuple[str, tuple[str, str, str]]: A tuple containing the direction
        ('ingress' or 'egress') and the event key (proto, host_ip, dpt).
    """
    out_m = re.search(r"\bOUT=([^\s]+)", line)
    is_egress = bool(out_m and out_m.group(1) != "")

    proto_m = re.search(r"\bPROTO=([^\s]+)", line)
    dpt_m = re.search(r"\bDPT=([^\s]+)", line)

    proto = proto_m.group(1) if proto_m else "N/A"
    dpt = dpt_m.group(1) if dpt_m else "N/A"

    if is_egress:
        dst_m = re.search(r"\bDST=([^\s]+)", line)
        dst = dst_m.group(1) if dst_m else "N/A"
        return "egress", (proto, dst, dpt)
    else:
        src_m = re.search(r"\bSRC=([^\s]+)", line)
        src = src_m.group(1) if src_m else "N/A"
        return "ingress", (proto, src, dpt)


def render_dashboard(
    log_file: Path,
    interval: float,
    top_limit: int,
    count_historical: bool = False,
    resolve_dns: bool = True,
) -> None:
    """Render a continuous real-time dashboard of denied connection tallies.

    Args:
        log_file: Path to the firewall denied log file.
        interval: Refresh rate in seconds.
        top_limit: Maximum number of ranked entries to display per panel.
        count_historical: If True, counts all existing log lines; if False,
            starts counting only from the moment the monitor starts.
        resolve_dns: If True, performs reverse DNS resolution on IPs.
    """
    ingress_counts: Counter[tuple[str, str, str]] = Counter()
    egress_counts: Counter[tuple[str, str, str]] = Counter()
    start_time_str = datetime.datetime.now().strftime("%H:%M:%S")

    f = None
    if log_file.exists():
        try:
            f = log_file.open("r", encoding="utf-8", errors="ignore")
            if not count_historical:
                f.seek(0, os.SEEK_END)
        except Exception:
            f = None

    while True:
        now_str = datetime.datetime.now().strftime("%H:%M:%S")

        if f is None and log_file.exists():
            try:
                f = log_file.open("r", encoding="utf-8", errors="ignore")
                if not count_historical:
                    f.seek(0, os.SEEK_END)
            except Exception:
                f = None

        if f is not None:
            try:
                current_pos = f.tell()
                file_size = log_file.stat().st_size
                if current_pos > file_size:
                    f.seek(0, 0)

                for line in f:
                    if (
                        "_DROP" in line
                        or "_REJECT" in line
                        or "FINAL_DROP" in line
                        or "FINAL_REJECT" in line
                        or "_DENIED" in line
                    ):
                        event_type, key = parse_denied_line(line)
                        if event_type == "egress":
                            egress_counts[key] += 1
                        else:
                            ingress_counts[key] += 1
            except Exception:
                pass

        # Clear terminal screen (ANSI)
        sys.stdout.write("\033[H\033[2J")

        dns_status = "DNS PTR Active" if resolve_dns else "DNS PTR Disabled"
        print(f"{Fore.CYAN}===================================================================================================={Style.RESET_ALL}")
        print(f"{Fore.CYAN}  FIREWALL DENIAL MONITOR | Started: {start_time_str} | Refresh: {interval}s | {dns_status}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}  File: {log_file} | Last update: {Fore.YELLOW}{now_str}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}===================================================================================================={Style.RESET_ALL}")

        if not log_file.exists():
            print(f"\n{Fore.RED}[ERROR] Log file not found: {log_file}{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}Waiting for log file to be created...{Style.RESET_ALL}")
        else:
            total_ingress = sum(ingress_counts.values())
            total_egress = sum(egress_counts.values())

            # Panel 1: INGRESS
            print(f"\n{Fore.RED}📥 DENIED INCOMING (INGRESS){Style.RESET_ALL} - Captured events: {Fore.YELLOW}{total_ingress}{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}{'POS':<5} {'COUNT':<10} {'PORT':<24} {'SOURCE IP / HOSTNAME':<48}{Style.RESET_ALL}")
            print("-" * 90)
            if not ingress_counts:
                print(f"{Fore.WHITE}Waiting for denied incoming events...{Style.RESET_ALL}")
            else:
                for rank, ((proto, src, dpt), count) in enumerate(ingress_counts.most_common(top_limit), start=1):
                    host_str = format_host_entry(src, resolve_dns)
                    port_str = format_port_entry(dpt, proto)
                    print(
                        f"{Fore.WHITE}#{rank:<4}{Style.RESET_ALL} "
                        f"{Fore.GREEN}{count:<10}{Style.RESET_ALL} "
                        f"{Fore.CYAN}{port_str:<24}{Style.RESET_ALL} "
                        f"{Fore.WHITE}{host_str:<48}{Style.RESET_ALL}"
                    )

            # Panel 2: EGRESS
            print(f"\n{Fore.RED}📤 DENIED OUTGOING (EGRESS){Style.RESET_ALL} - Captured events: {Fore.YELLOW}{total_egress}{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}{'POS':<5} {'COUNT':<10} {'PORT':<24} {'DESTINATION IP / HOSTNAME':<48}{Style.RESET_ALL}")
            print("-" * 90)
            if not egress_counts:
                print(f"{Fore.WHITE}Waiting for denied outgoing events...{Style.RESET_ALL}")
            else:
                for rank, ((proto, dst, dpt), count) in enumerate(egress_counts.most_common(top_limit), start=1):
                    host_str = format_host_entry(dst, resolve_dns)
                    port_str = format_port_entry(dpt, proto)
                    print(
                        f"{Fore.WHITE}#{rank:<4}{Style.RESET_ALL} "
                        f"{Fore.GREEN}{count:<10}{Style.RESET_ALL} "
                        f"{Fore.CYAN}{port_str:<24}{Style.RESET_ALL} "
                        f"{Fore.WHITE}{host_str:<48}{Style.RESET_ALL}"
                    )

        sys.stdout.flush()
        time.sleep(interval)


def main() -> None:
    """Main CLI entrypoint for firewalls_monitor."""
    parser = argparse.ArgumentParser(
        prog="firewalls_monitor",
        description="Real-time live dashboard tallying denied incoming and outgoing connections (IP + port + reverse DNS).",
    )
    parser.add_argument(
        "-n",
        "-i",
        "--interval",
        type=float,
        default=3.0,
        help="Refresh interval in seconds (default 3.0).",
    )
    parser.add_argument(
        "-f",
        "--file",
        type=Path,
        default=DEFAULT_LOG,
        help="Path to log file (default /var/log/firewalld/denied.log).",
    )
    parser.add_argument(
        "-p",
        "-l",
        "-t",
        "--positions",
        "--limit",
        "--top",
        dest="top",
        type=int,
        default=20,
        help="Maximum ranking positions to display per panel (default 20).",
    )
    parser.add_argument(
        "-a",
        "--all",
        action="store_true",
        help="Count all historical events in the log file instead of starting from zero.",
    )
    parser.add_argument(
        "-r",
        "--resolve",
        action="store_true",
        default=True,
        help="Resolve IP addresses to domain names via reverse DNS PTR (enabled by default).",
    )
    parser.add_argument(
        "--no-resolve",
        action="store_false",
        dest="resolve",
        help="Disable reverse DNS resolution (show IP addresses only).",
    )
    args = parser.parse_args()

    try:
        with managed_firewall_log("all"):
            render_dashboard(
                args.file,
                args.interval,
                args.top,
                count_historical=args.all,
                resolve_dns=args.resolve,
            )
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}Monitor stopped.{Style.RESET_ALL}")
        sys.exit(0)


if __name__ == "__main__":
    main()
