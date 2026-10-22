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
    """Normalize protocol name or number (e.g. '2' -> 'IGMP', '6' -> 'TCP')."""
    if not proto or proto == "N/A":
        return "N/A"
    return KNOWN_PROTOCOLS.get(proto, proto.upper())


def resolve_service(dpt: str, proto: str) -> str:
    """Resolve port and protocol to standard service name with caching."""
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
    """Format port entry with port number, PROTO (TCP/UDP), and optional service in parentheses."""
    proto_str = normalize_proto(proto)
    if not dpt or dpt == "N/A":
        return proto_str

    service = resolve_service(dpt, proto_str)
    if service:
        return f"{dpt} {proto_str} ({service})"
    return f"{dpt} {proto_str}"



def resolve_ip(ip: str) -> str:
    """Resolve IP address to domain name (PTR record) with caching."""
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
    """Format host entry with IP and optional domain name."""
    if not resolve:
        return ip
    domain = resolve_ip(ip)
    if domain != ip:
        return f"{ip} ({domain})"
    return ip


def parse_denied_line(line: str):
    """Parse log line into ingress or egress event with IP, port, and protocol."""
    # Egress if OUT= has a non-empty interface
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
):
    ingress_counts = Counter()
    egress_counts = Counter()
    start_time_str = datetime.datetime.now().strftime("%H:%M:%S")

    f = None
    if log_file.exists():
        try:
            f = log_file.open("r", encoding="utf-8", errors="ignore")
            if not count_historical:
                # Start from end of file (count from zero for new events)
                f.seek(0, os.SEEK_END)
        except Exception:
            f = None

    while True:
        now_str = datetime.datetime.now().strftime("%H:%M:%S")

        # Read any new lines appended since last check
        if f is None and log_file.exists():
            try:
                f = log_file.open("r", encoding="utf-8", errors="ignore")
                if not count_historical:
                    f.seek(0, os.SEEK_END)
            except Exception:
                f = None

        if f is not None:
            try:
                # Check for file truncation/rotation
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

        # Clear screen (ANSI escape)
        sys.stdout.write("\033[H\033[2J")

        dns_status = "DNS PTR Activo" if resolve_dns else "DNS PTR Desactivado"
        print(f"{Fore.CYAN}===================================================================================================={Style.RESET_ALL}")
        print(f"{Fore.CYAN}  MONITOR DE DENEGACIONES FIREWALL | Inicio: {start_time_str} | Refresco: {interval}s | {dns_status}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}  Archivo: {log_file} | Última actualización: {Fore.YELLOW}{now_str}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}===================================================================================================={Style.RESET_ALL}")

        if not log_file.exists():
            print(f"\n{Fore.RED}[ERROR] No se encuentra el archivo de log: {log_file}{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}Esperando a que se cree el archivo...{Style.RESET_ALL}")
        else:
            total_ingress = sum(ingress_counts.values())
            total_egress = sum(egress_counts.values())

            # Panel 1: INGRESS
            print(f"\n{Fore.RED}📥 ENTRADAS DENEGADAS (INGRESS){Style.RESET_ALL} - Eventos capturados: {Fore.YELLOW}{total_ingress}{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}{'POS':<5} {'CONTEO':<10} {'PUERTO':<24} {'IP / DOMINIO ORIGEN':<48}{Style.RESET_ALL}")
            print("-" * 90)
            if not ingress_counts:
                print(f"{Fore.WHITE}Esperando eventos de entrada denegados...{Style.RESET_ALL}")
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
            print(f"\n{Fore.RED}📤 SALIDAS DENEGADAS (EGRESS){Style.RESET_ALL} - Eventos capturados: {Fore.YELLOW}{total_egress}{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}{'POS':<5} {'CONTEO':<10} {'PUERTO':<24} {'IP / DOMINIO DESTINO':<48}{Style.RESET_ALL}")
            print("-" * 90)
            if not egress_counts:
                print(f"{Fore.WHITE}Esperando eventos de salida denegados...{Style.RESET_ALL}")
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


def main():
    parser = argparse.ArgumentParser(
        prog="firewalls_monitor",
        description="Monitor en tiempo real de conteo acumulado de denegaciones de entrada y salida (IP + puerto + dominio).",
    )
    parser.add_argument(
        "-n",
        "-i",
        "--interval",
        type=float,
        default=3.0,
        help="Intervalo de refresco en segundos (por defecto 3.0).",
    )
    parser.add_argument(
        "-f",
        "--file",
        type=Path,
        default=DEFAULT_LOG,
        help="Ruta al archivo de log (por defecto /var/log/firewalld/denied.log).",
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
        help="Número de posiciones / entradas a mostrar en el ranking por panel (por defecto 20).",
    )
    parser.add_argument(
        "-a",
        "--all",
        action="store_true",
        help="Incluir el historial completo desde el inicio del archivo de log en lugar de empezar desde cero.",
    )
    parser.add_argument(
        "-r",
        "--resolve",
        action="store_true",
        default=True,
        help="Resolver direcciones IP a su nombre de dominio mediante DNS inverso PTR (activado por defecto).",
    )
    parser.add_argument(
        "--no-resolve",
        action="store_false",
        dest="resolve",
        help="Desactivar la resolución de nombres de dominio (mostrar únicamente direcciones IP).",
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
        print(f"\n{Fore.YELLOW}Monitor finalizado.{Style.RESET_ALL}")
        sys.exit(0)


if __name__ == "__main__":
    main()
