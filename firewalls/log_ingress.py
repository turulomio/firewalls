#!/usr/bin/env python3
"""CLI tool to monitor and summarize denied ingress (incoming) firewall logs."""

import argparse
import re
import socket
import sys
import time
from collections import Counter
from pathlib import Path

from colorama import Fore, Style, init

from firewalls import _
from firewalls.log_control import managed_firewall_log

init(autoreset=True)

DEFAULT_LOG = Path("/var/log/firewalld/denied.log")
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
        str: Formatted string such as '80 TCP (http)' or '53 UDP (domain)'.
    """
    proto_str = normalize_proto(proto)
    if not dpt or dpt == "N/A":
        return proto_str

    service = resolve_service(dpt, proto_str)
    if service:
        return f"{dpt} {proto_str} ({service})"
    return f"{dpt} {proto_str}"


def parse_line(line: str) -> dict[str, str] | None:
    """Parse a single kernel firewall log line into ingress event fields.

    Ingress events have an empty OUT interface (e.g., 'OUT= ' or 'OUT=' at end of line).

    Args:
        line: Raw log line string.

    Returns:
        dict[str, str] | None: Dictionary with fields ('timestamp', 'proto',
        'src', 'dpt', 'spt', 'in') or None if not an ingress drop line.
    """
    out_match = re.search(r"\bOUT=(\s|$)", line)
    if not out_match:
        return None

    timestamp_match = re.match(r"^([A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2})", line)
    timestamp = timestamp_match.group(1) if timestamp_match else "N/A"

    proto_m = re.search(r"\bPROTO=([^\s]+)", line)
    src_m = re.search(r"\bSRC=([^\s]+)", line)
    dpt_m = re.search(r"\bDPT=([^\s]+)", line)
    spt_m = re.search(r"\bSPT=([^\s]+)", line)
    in_m = re.search(r"\bIN=([^\s]+)", line)

    return {
        "timestamp": timestamp,
        "proto": proto_m.group(1) if proto_m else "N/A",
        "src": src_m.group(1) if src_m else "N/A",
        "dpt": dpt_m.group(1) if dpt_m else "N/A",
        "spt": spt_m.group(1) if spt_m else "N/A",
        "in": in_m.group(1) if in_m else "N/A",
    }


def show_summary(log_file: Path) -> None:
    """Read log file and print a ranked summary table of denied ingress events.

    Args:
        log_file: Path to the denied packets log file.

    Raises:
        SystemExit: If log_file does not exist.
    """
    if not log_file.exists():
        print(f"{Fore.RED}[ERROR]{Style.RESET_ALL} {_('Log file does not exist: {file}').format(file=log_file)}")
        sys.exit(1)

    counter: Counter[tuple[str, str, str]] = Counter()
    with log_file.open("r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            data = parse_line(line)
            if data:
                key = (data["proto"], data["src"], data["dpt"])
                counter[key] += 1

    print(f"{Fore.CYAN}======================================================{Style.RESET_ALL}")
    print(f"{Fore.CYAN}  {_('Denied Ingress Connections Summary')}                  {Style.RESET_ALL}")
    print(f"{Fore.CYAN}======================================================{Style.RESET_ALL}")
    if not counter:
        print(f"{Fore.YELLOW}{_('No denied ingress events found.')}{Style.RESET_ALL}")
        return

    count_hdr = _("COUNT")
    port_hdr = _("PORT")
    src_hdr = _("SOURCE")
    print(f"{Fore.YELLOW}{count_hdr:<8} {port_hdr:<24} {src_hdr:<24}{Style.RESET_ALL}")
    print("-" * 58)
    for (proto, src, dpt), count in counter.most_common():
        port_str = format_port_entry(dpt, proto)
        print(f"{Fore.GREEN}{count:<8}{Style.RESET_ALL} {Fore.CYAN}{port_str:<24}{Style.RESET_ALL} {Fore.WHITE}{src:<24}{Style.RESET_ALL}")


def follow_logs(log_file: Path) -> None:
    """Continuously tail and print denied ingress connection events in real time.

    Args:
        log_file: Path to the denied packets log file.
    """
    if not log_file.exists():
        log_file.parent.mkdir(parents=True, exist_ok=True)
        log_file.touch(mode=0o640, exist_ok=True)

    print(f"{Fore.CYAN}======================================================{Style.RESET_ALL}")
    print(f"{Fore.CYAN}  {_('Denied INGRESS Traffic Monitor')}                      {Style.RESET_ALL}")
    print(f"{Fore.CYAN}  {_('Log File: {file}').format(file=log_file)}                                {Style.RESET_ALL}")
    print(f"{Fore.CYAN}======================================================{Style.RESET_ALL}")
    print(f"{Fore.GREEN}{_('Streaming real-time events (Press Ctrl+C to exit)...')}\n{Style.RESET_ALL}")

    blocked_tag = _("BLOCKED INGRESS")
    port_lbl = _("Port")
    src_lbl = _("Source")
    src_port_lbl = _("Source Port")
    iface_lbl = _("Interface")

    with log_file.open("r", encoding="utf-8", errors="ignore") as f:
        f.seek(0, 2)
        try:
            while True:
                line = f.readline()
                if not line:
                    time.sleep(0.5)
                    continue
                data = parse_line(line)
                if data:
                    port_str = format_port_entry(data["dpt"], data["proto"])
                    print(
                        f"{Fore.YELLOW}[{data['timestamp']}]{Style.RESET_ALL} "
                        f"{Fore.RED}[{blocked_tag}]{Style.RESET_ALL} "
                        f"{port_lbl}: {Fore.CYAN}{port_str:<22}{Style.RESET_ALL} "
                        f"{src_lbl}: {Fore.GREEN}{data['src']:<15}{Style.RESET_ALL} "
                        f"({src_port_lbl}: {data['spt']} -> {iface_lbl}: {data['in']})"
                    )
                    sys.stdout.flush()
        except KeyboardInterrupt:
            print(f"\n{Fore.YELLOW}{_('Monitor stopped.')}{Style.RESET_ALL}")


def main() -> None:
    """Main CLI entrypoint for firewalls_log_ingress."""
    parser = argparse.ArgumentParser(
        prog="firewalls_log_ingress",
        description=_("Monitor and summarize incoming (ingress) connections blocked by the firewall."),
    )
    parser.add_argument(
        "-s", "--summary", action="store_true", help=_("Display a ranked summary of blocked ingress connections.")
    )
    parser.add_argument(
        "-f", "--file", type=Path, default=DEFAULT_LOG, help=_("Path to log file (default /var/log/firewalld/denied.log).")
    )
    args = parser.parse_args()

    if args.summary:
        show_summary(args.file)
    else:
        with managed_firewall_log("all"):
            follow_logs(args.file)


if __name__ == "__main__":
    main()
